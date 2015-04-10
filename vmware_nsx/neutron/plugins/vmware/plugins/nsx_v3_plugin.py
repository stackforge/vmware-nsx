# Copyright 2015 OpenStack Foundation
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import random

import netaddr
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
from oslo_utils import uuidutils

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.v2 import attributes
from neutron.extensions import l3
from neutron.extensions import portbindings as pbin

from neutron.common import constants as const
from neutron.common import exceptions as ntn_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import securitygroups_db

from vmware_nsx.neutron.plugins.vmware.common import config  # noqa
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import nsx_constants
from vmware_nsx.neutron.plugins.vmware.dbexts import db as nsx_db
from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib
from vmware_nsx.openstack.common._i18n import _LI, _LW

LOG = log.getLogger(__name__)


DEVICE_OWNER_NSX_TIER0_ROUTER = "network:nsx_tier0_router"
db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS.append(DEVICE_OWNER_NSX_TIER0_ROUTER)


class NsxV3Plugin(db_base_plugin_v2.NeutronDbPluginV2,
                  securitygroups_db.SecurityGroupDbMixin,
                  external_net_db.External_net_db_mixin,
                  l3_db.L3_NAT_dbonly_mixin,
                  portbindings_db.PortBindingMixin,
                  agentschedulers_db.DhcpAgentSchedulerDbMixin):
    # NOTE(salv-orlando): Security groups are not actually implemented by this
    # plugin at the moment

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["quotas",
                                   "binding",
                                   "security-group",
                                   "external-net",
                                   "router"]

    def __init__(self):
        super(NsxV3Plugin, self).__init__()
        LOG.info(_("Starting NsxV3Plugin"))

        self.base_binding_dict = {
            pbin.VIF_TYPE: pbin.VIF_TYPE_OVS,
            pbin.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                pbin.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        self._setup_rpc()

    def _setup_rpc(self):
        self.topic = topics.PLUGIN
        self.conn = n_rpc.create_connection(new=True)
        self.endpoints = [dhcp_rpc.DhcpRpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI())
        self.conn.consume_in_threads()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.supported_extension_aliases.extend(
            ['agent', 'dhcp_agent_scheduler'])

    def _nsx_create_network(self, network):
        return nsxlib.create_logical_switch(
            network['network']['name'],
            cfg.CONF.default_tz_uuid)

    def _nsx_setup_external_network(self, context, subnet):
        # Create a tier0 router
        lr = nsxlib.create_logical_router(
            'tier0_rtr_%s' % subnet.get('name', subnet['id']),
            cfg.CONF.nsx_v3.default_edge_cluster_uuid,
            tier_0=True)
        # Add a logical router port on the transit network
        # NOTE(salv-orlando): I do not know if this is really needed
        transit_net = netaddr.IPNetwork(
            cfg.CONF.nsx_v3.external_transit_network)
        transit_range = netaddr.IPRange(
            transit_net.first + 1, transit_net.last - 1)
        random.seed()
        ip = transit_range[random.randint(0, len(transit_range))]
        nsxlib.create_logical_router_port(
            lr['id'], None, nsx_constants.LROUTERPORT_LINK,
            transit_net.prefixlen, ip)
        # Create an uplink port on the tier0 router
        port_info = {'network_id': subnet['network_id'],
                     'admin_state_up': True,
                     'device_id': 'meh',
                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                     'name': 'uplink_%s' % subnet.get('name', subnet['id']),
                     'device_owner': DEVICE_OWNER_NSX_TIER0_ROUTER,
                     'fixed_ips': [{'subnet_id': subnet['id']}]}
        neutron_gw_port = self.create_port(
            context, {'port': port_info})
        port_id = neutron_gw_port['id']
        _ls_id, lp_id = nsx_db.get_nsx_switch_and_port_id(
            context.session, port_id)
        port_ip = neutron_gw_port['fixed_ips'][0]['ip_address']
        # FIXME(salv-orlando): cidr_length = 24 is just a hack!
        nsxlib.create_logical_router_port(
            lr['id'], lp_id,
            resource_type=nsx_constants.LROUTERPORT_UPLINK,
            cidr_length=24,
            ip_address=port_ip)
        nsx_db.add_neutron_nsx_subnet_mapping(context.session,
                                              subnet['id'], lr['id'])

    def _nsx_teardown_external_network(self, context, subnet_id,
                                       nsx_tier0_router_id):
        # FIXME(salv-orlando): This operation currently leaves a dangling port
        # on the external logical switch (but possibly we don't care about it
        # as we are going to get rid of said logical switch)
        if not nsx_tier0_router_id:
            LOG.info(_LI("Tier0 router for subnet %s not found"), subnet_id)
            return
        # Remove all logical ports for said router
        # This should be safe... hopefullyi!
        lr_ports = nsxlib.get_logical_router_ports(nsx_tier0_router_id)
        for lr_port in lr_ports:
            nsxlib.delete_logical_router_port(lr_port['id'])
        # And finally teardown the tier-0 router
        nsxlib.delete_logical_router(nsx_tier0_router_id)

    def create_network(self, context, network):
        result = self._nsx_create_network(network)
        net_data = network['network']
        network['network']['id'] = result['id']
        with context.session.begin():
            new_network = super(NsxV3Plugin, self).create_network(context,
                                                                  network)
            self._process_l3_create(context, new_network, net_data)
        # TODO(salv-orlando): Undo logical switch creation on failure
        return new_network

    def delete_network(self, context, network_id):
        # First call DB operation for delete network as it will perform
        # checks on active ports
        ret_val = super(NsxV3Plugin, self).delete_network(context, network_id)
        # TODO(salv-orlando): Handle backend failure, possibly without
        # requiring us to un-delete the DB object. For instance, ignore
        # failures occuring if logical switch is not found
        nsxlib.delete_logical_switch(network_id)
        return ret_val

    def update_network(self, context, id, network):
        # TODO(arosen) - call to backend
        return super(NsxV3Plugin, self).update_network(context, id,
                                                       network)

    def create_subnet(self, context, subnet):
        subnet = super(NsxV3Plugin, self).create_subnet(context, subnet)
        # TODO(salv-orlando): Perform error handling for external network
        # configuration
        if self._network_is_external(context, subnet['network_id']):
            # Configure external network for routing
            self._nsx_setup_external_network(context, subnet)

        return subnet

    def delete_subnet(self, context, subnet_id):
        # TODO(salv-orlando): Perform error handling for external network
        # configuration
        # It's a bit boring having to perform 2 db operations for knowing if
        # if a subnet is on an external network. We might as well just always
        # try and find a tier0 router associated with it and do nothing if
        # the router is not found
        subnet = self._get_subnet(context, subnet_id)
        is_subnet_external = self._network_is_external(context,
                                                       subnet['network_id'])
        if is_subnet_external:
            nsx_tier0_router_id = nsx_db.get_nsx_tier0_router_id(
                context.session, subnet_id)
        ret_val = super(NsxV3Plugin, self).delete_subnet(context, subnet_id)
        if is_subnet_external:
            self._nsx_teardown_external_network(context, subnet_id,
                                                nsx_tier0_router_id)
        return ret_val

    def create_port(self, context, port):
        # NOTE(salv-orlando): This method currently first performs the backend
        # operation. However it is important to note that this workflow might
        # change in the future as the backend might need parameter generated
        # from the neutron side such as port MAC address
        port_id = uuidutils.generate_uuid()
        result = nsxlib.create_logical_port(
            lswitch_id=port['port']['network_id'],
            vif_uuid=port_id)
        port['port']['id'] = port_id
        # TODO(salv-orlando): Undo logical switch creation on failure
        with context.session.begin():
            neutron_db = super(NsxV3Plugin, self).create_port(context, port)
            port['port'].update(neutron_db)
            # TODO(salv-orlando): The logical switch identifier in the mapping
            # object is not necessary anymore.
            nsx_db.add_neutron_nsx_port_mapping(
                context.session, neutron_db['id'],
                port['port']['network_id'], result['id'])
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         neutron_db)

            neutron_db[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL
        return neutron_db

    def delete_port(self, context, port_id, l3_port_check=True):
        _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
            context.session, port_id)
        ret_val = super(NsxV3Plugin, self).delete_port(context, port_id)

        nsxlib.delete_logical_port(nsx_port_id)

        return ret_val

    def update_port(self, context, id, port):
        # TODO(arosen) - call to backend
        return super(NsxV3Plugin, self).update_port(context, id,
                                                    port)

    def create_router(self, context, router):
        result = nsxlib.create_logical_router(
            display_name=router['router'].get('name', 'a_router_with_no_name'),
            tier_0=False,
            edge_cluster_uuid=cfg.CONF.nsx_v3.default_edge_cluster_uuid)

        with context.session.begin():
            router = super(NsxV3Plugin, self).create_router(
                context, router)
            nsx_db.add_neutron_nsx_router_mapping(
                context.session, router['id'], result['id'])

        return router

    def delete_router(self, context, router_id):
        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        ret_val = super(NsxV3Plugin, self).delete_router(context,
                                                         router_id)
        # Remove logical router from the NSX backend
        # It is safe to do now as db-level checks for resource deletion were
        # passed (and indeed the resource was removed from the Neutron DB
        try:
            nsxlib.delete_logical_router(nsx_router_id)
        except nsx_exc.LogicalRouterNotFound:
            # If the logical router was not found on the backend do not worry
            # about it. The conditions has already been logged, so there is no
            # need to do further logging
            pass
        except nsx_exc.NsxPluginException:
            # if there is a failure in deleting the router do not fail the
            # operation, especially since the router object has already been
            # removed from the neutron DB. Take corrective steps to ensure the
            # resulting zombie object does not forward any traffic and is
            # eventually removed.
            LOG.warning(_LW("Backend router deletion for neutron router %s "
                            "failed. The object was however removed from the "
                            "Neutron datanase"), router_id)

        return ret_val

    def update_router(self, context, router_id, router):
        router_data = router['router']
        gw_info = router_data.get('external_gateway_info')
        if gw_info:
            # The following DB read will be performed again when updating
            # gateway info. This is not great, but still better than
            # creating NSX router here and updating it later
            network_id = gw_info.get('network_id')
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external "
                             "network") % network_id)
                    raise ntn_exc.BadRequest(resource='router', msg=msg)
                if ext_net.subnets:
                    ext_subnet = ext_net.subnets[0]
            # Find tier-0 router for ext_subnet
            nsx_tier0_router_id = nsx_db.get_nsx_tier0_router_id(
                context.session, ext_subnet['id'])
            if nsx_tier0_router_id:
                pass
            else:
                # We should probably raise here.
                LOG.warning(_LW("Unable to find tier0 router for subnet %s."
                                "Gateway settings will not work."),
                            ext_subnet['id'])
            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     router_id)
            # FIXME(salv-orlando): These IP addresses should not be random of
            # course. We need an IPAM engine, hopefully Neutron will offer one
            # soon.
            # Create a link port between tier-1 router for router_id and
            # tier-0 router
            transit_net = netaddr.IPNetwork(
                cfg.CONF.nsx_v3.external_transit_network)
            transit_range = netaddr.IPRange(
                transit_net.first + 1, transit_net.last - 1)
            random.seed()
            ip = transit_range[random.randint(0, len(transit_range))]
            nsxlib.create_logical_router_port(
                nsx_router_id,
                None,
                nsx_constants.LROUTERPORT_LINK,
                transit_net.prefixlen, ip)

        return super(NsxV3Plugin, self).update_router(context, router_id,
                                                      router)

    def add_router_interface(self, context, router_id, interface_info):
        # NOTE(arosen): I think there is a bug here since I believe we
        # can also get a port or ip here....
        subnet = self.get_subnet(context, interface_info['subnet_id'])
        port = {'port': {'network_id': subnet['network_id'], 'name': '',
                         'admin_state_up': True, 'device_id': '',
                         'device_owner': l3_db.DEVICE_OWNER_ROUTER_INTF,
                         'mac_address': attributes.ATTR_NOT_SPECIFIED,
                         'fixed_ips': [{'subnet_id': subnet['id'],
                                        'ip_address': subnet['gateway_ip']}]}}
        port = self.create_port(context, port)
        result = nsxlib.create_logical_router_port(
            router_id=router_id,
            resource_type=nsx_constants.LROUTERPORT_UPLINK,
            cidr_length=24, ip_addresses=subnet['gateway_ip'],
            port_id=port['id'])
        interface_info['port_id'] = port['id']
        del interface_info['subnet_id']
        result = super(NsxV3Plugin, self).add_router_interface(
            context, router_id, interface_info)
        return result

    def remove_router_interface(self, context, router_id, interface_info):
        if 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._get_subnet(context, subnet_id)
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
                network_id=subnet['network_id'])
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                    port_id = p['id']
                    break
            else:
                raise l3.RouterInterfaceNotFoundForSubnet(router_id=router_id,
                                                          subnet_id=subnet_id)
            nsxlib.delete_logical_router_port(port_id)
        return super(NsxV3Plugin, self).remove_router_interface(
            context, router_id, interface_info)
