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

import six

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
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import securitygroups_db
from neutron.i18n import _LW

from vmware_nsx.neutron.plugins.vmware.common import config  # noqa
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import utils
from vmware_nsx.neutron.plugins.vmware.dbexts import db as nsx_db
from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib

LOG = log.getLogger(__name__)


class NsxV3Plugin(db_base_plugin_v2.NeutronDbPluginV2,
                  securitygroups_db.SecurityGroupDbMixin,
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

    def create_network(self, context, network):
        tags = utils.build_v3_tags_payload(network['network'])
        result = nsxlib.create_logical_switch(
            network['network']['name'],
            cfg.CONF.default_tz_uuid, tags)
        network['network']['id'] = result['id']
        tenant_id = self._get_tenant_id_for_create(context, network['network'])

        self._ensure_default_security_group(context, tenant_id)
        network = super(NsxV3Plugin, self).create_network(context, network)
        # TODO(salv-orlando): Undo logical switch creation on failure
        return network

    def delete_network(self, context, network_id):
        # First call DB operation for delete network as it will perform
        # checks on active ports
        ret_val = super(NsxV3Plugin, self).delete_network(context, network_id)
        # TODO(salv-orlando): Handle backend failure, possibly without
        # requiring us to un-delete the DB object. For instance, ignore
        # failures occuring if logical switch is not found
        nsxlib.delete_logical_switch(network_id)
        return ret_val

    def update_network(self, context, network_id, network):
        # TODO(arosen) - call to backend
        return super(NsxV3Plugin, self).update_network(context, network_id,
                                                       network)

    def _build_address_bindings(self, port):
        address_bindings = []
        for fixed_ip in port['fixed_ips']:
            # NOTE(arosen): nsx-v3 doesn't seem to handle ipv6 addresses
            # currently so for now we remove them here and do not pass
            # them to the backend which would raise an error.
            if(netaddr.IPNetwork(fixed_ip['ip_address']).version == 6):
                continue
            address_bindings.append(
                {'mac_address': port['mac_address'],
                 'ip_address': fixed_ip['ip_address']})
        return address_bindings

    def _get_data_from_binding_profile(self, context, port):
        if (pbin.PROFILE not in port or
                not attributes.is_attr_set(port[pbin.PROFILE])):
            return None, None

        parent_name = (
            port[pbin.PROFILE].get('parent_name'))
        tag = port[pbin.PROFILE].get('tag')
        if not any((parent_name, tag)):
            # An empty profile is fine.
            return
        if not all((parent_name, tag)):
            # If one is set, they both must be set.
            msg = _('Invalid binding:profile. parent_name and tag are '
                    'both required.')
            raise n_exc.InvalidInput(error_message=msg)
        if not isinstance(parent_name, six.string_types):
            msg = _('Invalid binding:profile. parent_name "%s" must be '
                    'a string.') % parent_name
            raise n_exc.InvalidInput(error_message=msg)
        try:
            tag = int(tag)
            if(tag < 0 or tag > 4095):
                raise ValueError
        except ValueError:
            msg = _('Invalid binding:profile. tag "%s" must be '
                    'an int between 1 and 4096, inclusive.') % tag
            raise n_exc.InvalidInput(error_message=msg)
        # Make sure we can successfully look up the port indicated by
        # parent_name.  Just let it raise the right exception if there is a
        # problem.
        self.get_port(context, parent_name)
        return parent_name, tag

    def create_port(self, context, port):
        port_id = uuidutils.generate_uuid()
        tags = utils.build_v3_tags_payload(port['port'])
        port['port']['id'] = port_id

        self._ensure_default_security_group_on_port(context, port)
        # TODO(salv-orlando): Undo logical switch creation on failure
        with context.session.begin(subtransactions=True):
            parent_name, tag = self._get_data_from_binding_profile(
                context, port['port'])
            neutron_db = super(NsxV3Plugin, self).create_port(context, port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         neutron_db)

            port["port"].update(neutron_db)
            address_bindings = self._build_address_bindings(port['port'])
            # FIXME(arosen): we might need to pull this out of the transaction
            # here later.
            result = nsxlib.create_logical_port(
                lswitch_id=port['port']['network_id'],
                vif_uuid=port_id, name=port['port']['name'], tags=tags,
                admin_state=port['port']['admin_state_up'],
                address_bindings=address_bindings,
                parent_name=parent_name, parent_tag=tag)

            # TODO(salv-orlando): The logical switch identifier in the mapping
            # object is not necessary anymore.
            nsx_db.add_neutron_nsx_port_mapping(
                context.session, neutron_db['id'],
                neutron_db['network_id'], result['id'])
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         neutron_db)
            neutron_db[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL
            if pbin.PROFILE in port['port']:
                neutron_db[pbin.PROFILE] = port['port'][pbin.PROFILE]
            sgids = self._get_security_groups_on_port(context, port)
            self._process_port_create_security_group(
                context, neutron_db, sgids)

        return neutron_db

    def delete_port(self, context, port_id, l3_port_check=True):
        _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
            context.session, port_id)
        nsxlib.delete_logical_port(nsx_port_id)
        ret_val = super(NsxV3Plugin, self).delete_port(context, port_id)

        return ret_val

    def update_port(self, context, id, port):
        # TODO(arosen) - call to backend
        original_port = super(NsxV3Plugin, self).get_port(context, id)
        with context.session.begin(subtransactions=True):
            updated_port = super(NsxV3Plugin, self).update_port(context,
                                                                id, port)
            self.update_security_group_on_port(
                context, id, port, original_port, updated_port)

        return updated_port

    def create_router(self, context, router):
        tags = utils.build_v3_tags_payload(router['router'])
        result = nsxlib.create_logical_router(
            display_name=router['router'].get('name', 'a_router_with_no_name'),
            tier_0=True,
            edge_cluster_uuid=cfg.CONF.nsx_v3.default_edge_cluster_uuid,
            tags=tags)

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
        # TODO(arosen) - call to backend
        return super(NsxV3Plugin, self).update_router(context, id,
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
        _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
            context.session, port['id'])

        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        result = nsxlib.create_logical_router_port(
            logical_router_id=nsx_router_id,
            logical_switch_port_id=nsx_port_id,
            resource_type="LogicalRouterDownLinkPort",
            cidr_length=24, ip_address=subnet['gateway_ip'])
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
            _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            nsxlib.delete_logical_router_port(nsx_port_id)
        return super(NsxV3Plugin, self).remove_router_interface(
            context, router_id, interface_info)

    def create_security_group_rule_bulk(self, context, security_group_rules):
        return super(NsxV3Plugin, self).create_security_group_rule_bulk_native(
            context, security_group_rules)

    def extend_port_dict_binding(self, port_res, port_db):
        super(NsxV3Plugin, self).extend_port_dict_binding(port_res, port_db)
        port_res[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL
