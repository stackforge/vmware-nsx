# Copyright 2015 VMware, Inc.
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

import netaddr
import random

from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import uuidutils

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.v2 import attributes
from neutron.extensions import external_net as ext_net_extn
from neutron.extensions import l3
from neutron.extensions import portbindings as pbin
from neutron.extensions import providernet as pnet

from neutron.common import constants as const
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import securitygroups_db
from neutron.i18n import _LE, _LI, _LW

from vmware_nsx.neutron.plugins.vmware.common import config  # noqa
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import utils
from vmware_nsx.neutron.plugins.vmware.dbexts import db as nsx_db
from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib

LOG = log.getLogger(__name__)


class NsxV3Plugin(db_base_plugin_v2.NeutronDbPluginV2,
                  securitygroups_db.SecurityGroupDbMixin,
                  external_net_db.External_net_db_mixin,
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  portbindings_db.PortBindingMixin,
                  agentschedulers_db.DhcpAgentSchedulerDbMixin):
    # NOTE(salv-orlando): Security groups are not actually implemented by this
    # plugin at the moment

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["quotas",
                                   "binding",
                                   "ext-gw-mode",
                                   "security-group",
                                   "provider",
                                   "external-net",
                                   "extraroute",
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
        self.tier0_groups_dict = {}
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

    def _validate_tier0(self, tier0_uuid):
        if tier0_uuid in self.tier0_groups_dict.keys():
            return True
        try:
            lrouter = nsxlib.get_logical_router(tier0_uuid)
            edge_cluster_uuid = lrouter['edge_cluster_uuid']
            edge_cluster = nsxlib.get_edge_cluster(edge_cluster_uuid)
            member_index_list = [member['member_index']
                                 for member in edge_cluster['members']]
            if not member_index_list:
                raise nsx_exc.NsxPluginException(
                    err_msg=_("Unexpected error in backend while reading "
                              "edge_cluster %s") % edge_cluster_uuid)
        except nsx_exc.NsxPluginException as e:
            LOG.debug("Failed to validate tier0 since %s", e)
            return False
        else:
            self.tier0_groups_dict[tier0_uuid] = {
                'edge_cluster_uuid': edge_cluster_uuid,
                'member_index_list': member_index_list}
            return True

    def _get_edge_cluster_and_members(self, tier0_uuid):
        if self._validate_tier0(tier0_uuid):
            tier0_info = self.tier0_groups_dict[tier0_uuid]
            return (tier0_info['edge_cluster_uuid'],
                    tier0_info['member_index_list'])
        else:
            err_msg = _("tier0 %s can not be validated") % tier0_uuid
            raise nsx_exc.NsxPluginException(err_msg=err_msg)

    def _validate_provider_create(self, net_data):
        err_msg = None
        if not attributes.is_attr_set(net_data.get(pnet.PHYSICAL_NETWORK)):
            tier0_uuid = cfg.CONF.nsx_v3.default_tier0_router_uuid
            if not tier0_uuid:
                err_msg = _("Default tier0 router uuid is not specified for "
                            "the net")
        else:
            tier0_uuid = net_data[pnet.PHYSICAL_NETWORK]
        if not self._validate_tier0(tier0_uuid):
            err_msg = _("tier0 %s can not be validated") % tier0_uuid
        if err_msg:
            raise n_exc.InvalidInput(error_message=err_msg)

    def _extend_network_dict_provider(self, context, network, bindings=None):
        if not bindings:
            bindings = nsx_db.get_network_bindings(context.session,
                                                   network['id'])
        if bindings:
            # network came in through provider networks api
            network[pnet.NETWORK_TYPE] = bindings[0].binding_type
            network[pnet.PHYSICAL_NETWORK] = bindings[0].phy_uuid
            network[pnet.SEGMENTATION_ID] = bindings[0].vlan_id

    def create_network(self, context, network):
        net_data = network['network']
        self._validate_provider_create(net_data)
        external = net_data.get(ext_net_extn.EXTERNAL)
        backend_network = (not attributes.is_attr_set(external) or
                           attributes.is_attr_set(external) and not external)
        if backend_network:
            tags = utils.build_v3_tags_payload(network['network'])
            result = nsxlib.create_logical_switch(
                network['network']['name'],
                cfg.CONF.default_tz_uuid, tags)
            network['network']['id'] = result['id']
            tenant_id = self._get_tenant_id_for_create(
                context, network['network'])
            self._ensure_default_security_group(context, tenant_id)
        new_net = super(NsxV3Plugin, self).create_network(context, network)
        self._process_l3_create(context, new_net, net_data)
        if attributes.is_attr_set(net_data.get(pnet.PHYSICAL_NETWORK)):
            net_bindings = []
            physical_network = net_data.get(pnet.PHYSICAL_NETWORK)
            net_bindings.append(nsx_db.add_network_binding(
                context.session, new_net['id'],
                "l3_ext",
                physical_network,
                None))
            self._extend_network_dict_provider(context, new_net,
                                               bindings=net_bindings)
        # TODO(salv-orlando): Undo logical switch creation on failure
        return new_net

    def get_network(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            # goto to the plugin DB and fetch the network
            network = self._get_network(context, id)
            # Don't do field selection here otherwise we won't be able
            # to add provider networks fields
            net_result = self._make_network_dict(network,
                                                 context=context)
            self._extend_network_dict_provider(context, net_result)
        return self._fields(net_result, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            networks = (
                super(NsxV3Plugin, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            for net in networks:
                self._extend_network_dict_provider(context, net)
        return [self._fields(network, fields) for network in networks]

    def delete_network(self, context, network_id):
        external = self._network_is_external(context, network_id)
        # First call DB operation for delete network as it will perform
        # checks on active ports
        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, network_id)
            nsx_db.delete_network_bindings(context.session, network_id)
            super(NsxV3Plugin, self).delete_network(context, network_id)
        if not external:
            # TODO(salv-orlando): Handle backend failure, possibly without
            # requiring us to un-delete the DB object. For instance, ignore
            # failures occuring if logical switch is not found
            nsxlib.delete_logical_switch(network_id)
        else:
            # TODO(berlin): delete subnets public announce on the network
            pass

    def update_network(self, context, network_id, network):
        # TODO(arosen) - call to backend
        net = super(NsxV3Plugin, self).update_network(context, network_id,
                                                      network)
        self._process_l3_update(context, net, network['network'])
        return net

    def create_subnet(self, context, subnet):
        # TODO(berlin): announce external subnet
        # TODO(berlin): no-gateway is forever fixed for ext subnet
        return super(NsxV3Plugin, self).create_subnet(context, subnet)

    def delete_subnet(self, context, subnet_id):
        # TODO(berlin): delete external subnet public announce
        return super(NsxV3Plugin, self).delete_subnet(context, subnet_id)

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

    def create_port(self, context, port):
        port_id = uuidutils.generate_uuid()
        tags = utils.build_v3_tags_payload(port['port'])
        port['port']['id'] = port_id

        self._ensure_default_security_group_on_port(context, port)
        # TODO(salv-orlando): Undo logical switch creation on failure
        with context.session.begin(subtransactions=True):
            neutron_db = super(NsxV3Plugin, self).create_port(context, port)
            port["port"].update(neutron_db)

            external = self._network_is_external(
                context, port['port']['network_id'])
            if not external:
                address_bindings = self._build_address_bindings(port['port'])
                # FIXME(arosen): we might need to pull this out of the
                # transaction here later.
                result = nsxlib.create_logical_port(
                    lswitch_id=port['port']['network_id'],
                    vif_uuid=port_id, name=port['port']['name'], tags=tags,
                    admin_state=port['port']['admin_state_up'],
                    address_bindings=address_bindings)

                # TODO(salv-orlando): The logical switch identifier in the
                # mapping object is not necessary anymore.
                nsx_db.add_neutron_nsx_port_mapping(
                    context.session, neutron_db['id'],
                    neutron_db['network_id'], result['id'])
                self._process_portbindings_create_and_update(context,
                                                             port['port'],
                                                             neutron_db)

                neutron_db[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL

                sgids = self._get_security_groups_on_port(context, port)
                self._process_port_create_security_group(
                    context, neutron_db, sgids)
        return neutron_db

    def delete_port(self, context, port_id, l3_port_check=True):
        if l3_port_check:
            self.prevent_l3_port_deletion(context, port_id)
        port = self.get_port(context, port_id)
        if not self._network_is_external(context, port['network_id']):
            _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            nsxlib.delete_logical_port(nsx_port_id)
            nsx_db.delete_neutron_nsx_port_mapping(
                context.session, port_id)
        self.disassociate_floatingips(context, port_id)
        ret_val = super(NsxV3Plugin, self).delete_port(context, port_id)

        return ret_val

    def update_port(self, context, id, port):
        original_port = super(NsxV3Plugin, self).get_port(context, id)
        _, nsx_lport_id = nsx_db.get_nsx_switch_and_port_id(
            context.session, id)
        with context.session.begin(subtransactions=True):
            updated_port = super(NsxV3Plugin, self).update_port(context,
                                                                id, port)
            sec_grp_updated = self.update_security_group_on_port(
                                  context, id, port, original_port,
                                  updated_port)
        try:
            nsxlib.update_logical_port(
                nsx_lport_id, name=port['port'].get('name'),
                admin_state=port['port'].get('admin_state_up'))
        except nsx_exc.ManagerError:
            # In case if there is a failure on NSX-v3 backend, rollback the
            # previous update operation on neutron side.
            LOG.exception(_LE("Unable to update NSX backend, rolling back "
                              "changes on neutron"))
            with excutils.save_and_reraise_exception():
                with context.session.begin(subtransactions=True):
                    super(NsxV3Plugin, self).update_port(
                        context, id, original_port)
                    if sec_grp_updated:
                        self.update_security_group_on_port(
                            context, id, {'port': original_port}, updated_port,
                            original_port)

        return updated_port

    def _extract_external_gw(self, context, router, is_extract=True):
        r = router['router']
        gw_info = attributes.ATTR_NOT_SPECIFIED
        # First extract the gateway info in case of updating
        # gateway before edge is deployed.
        if 'external_gateway_info' in r:
            gw_info = r['external_gateway_info']
            if is_extract:
                del r['external_gateway_info']
            network_id = (gw_info.get('network_id') if gw_info
                          else None)
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external network") %
                           network_id)
                    raise n_exc.BadRequest(resource='router', msg=msg)
        return gw_info

    def _get_external_attachment_info(self, context, router):
        gw_port = router.gw_port
        ipaddress = None
        netmask = None
        nexthop = None

        if gw_port:
            # gw_port may have multiple IPs, only configure the first one
            if gw_port.get('fixed_ips'):
                ipaddress = gw_port['fixed_ips'][0]['ip_address']

            network_id = gw_port.get('network_id')
            if network_id:
                ext_net = self._get_network(context, network_id)
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external "
                             "network") % network_id)
                    raise n_exc.BadRequest(resource='router', msg=msg)
                if ext_net.subnets:
                    ext_subnet = ext_net.subnets[0]
                    netmask = str(netaddr.IPNetwork(ext_subnet.cidr).netmask)
                    nexthop = ext_subnet.gateway_ip

        return (ipaddress, netmask, nexthop)

    def _get_tier0_uuid_by_net(self, context, network_id):
        if not network_id:
            return
        network = self.get_network(context.elevated(), network_id)
        if not network.get(pnet.PHYSICAL_NETWORK):
            return cfg.CONF.nsx_v3.default_tier0_router_uuid
        else:
            return network.get(pnet.PHYSICAL_NETWORK)

    def _update_router_gw_info(self, context, router_id, info):
        router = self._get_router(context, router_id)
        org_ext_net_id = router.gw_port_id and router.gw_port.network_id
        org_tier0_uuid = self._get_tier0_uuid_by_net(context, org_ext_net_id)
        org_enable_snat = router.enable_snat
        new_ext_net_id = info and info.get('network_id')
        orgaddr, orgmask, _orgnexthop = (
            self._get_external_attachment_info(
                context, router))

        # TODO(berlin): For nonat user case, we actually don't need a gw port
        # which consumes one external ip. But after looking at the DB logic
        # and we need to make a big change so don't touch it at present.
        super(NsxV3Plugin, self)._update_router_gw_info(
            context, router_id, info, router=router)

        new_ext_net_id = router.gw_port_id and router.gw_port.network_id
        new_tier0_uuid = self._get_tier0_uuid_by_net(context, new_ext_net_id)
        new_enable_snat = router.enable_snat
        newaddr, newmask, _newnexthop = (
            self._get_external_attachment_info(
                context, router))
        nsx_router_id = nsx_db.get_nsx_router_id(context.session, router_id)

        # Remove router link port between tier1 and tier0 if tier0 router link
        # is remove or changed
        remove_router_link_port = (org_tier0_uuid and
                                   (not new_tier0_uuid or
                                    org_tier0_uuid != new_tier0_uuid))

        # Remove SNAT rules for gw ip if gw ip is deleted/changed or
        # enable_snat is updated from True to False
        remove_snat_rules = (org_enable_snat and orgaddr and
                             (newaddr != orgaddr or
                              not new_enable_snat))

        # Revocate bgp announce for nonat subnets if tier0 router link is
        # changed or enable_snat is updated from False to True
        revocate_bgp_announce = (not org_enable_snat and org_tier0_uuid and
                                 (new_tier0_uuid != org_tier0_uuid or
                                  new_enable_snat))

        # Add router link port between tier1 and tier0 if tier0 router link is
        # added or changed to a new one
        add_router_link_port = (new_tier0_uuid and
                                (not org_tier0_uuid or
                                 org_tier0_uuid != new_tier0_uuid))

        # Add SNAT rules for gw ip if gw ip is add/changed or
        # enable_snat is updated from False to True
        add_snat_rules = (new_enable_snat and newaddr and
                          (newaddr != orgaddr or
                           not org_enable_snat))

        # Bgp announce for nonat subnets if tier0 router link is changed or
        # enable_snat is updated from True to False
        bgp_announce = (new_enable_snat and new_tier0_uuid and
                        (new_tier0_uuid != org_tier0_uuid or
                         not org_enable_snat))

        advertise_route_nat_flag = True if new_enable_snat else False
        advertise_route_connected_flag = True if not new_enable_snat else False

        if revocate_bgp_announce:
            # revocate bgp announce on org tier0 router
            pass
        if remove_snat_rules:
            self._delete_gw_snat_rule(nsx_router_id, orgaddr)
        if remove_router_link_port:
            self._remove_router_link_port(nsx_router_id, org_tier0_uuid)
        if add_router_link_port:
            # First update edge cluster info for router
            edge_cluster_uuid, members = self._get_edge_cluster_and_members(
                new_tier0_uuid)
            self._update_router_edge_cluster(nsx_router_id, edge_cluster_uuid)
            self._add_router_link_port(nsx_router_id, new_tier0_uuid, members)
        if add_snat_rules:
            self._add_gw_snat_rule(nsx_router_id, newaddr)
        if bgp_announce:
            # bgp announce on new tier0 router
            pass

        if new_enable_snat != org_enable_snat:
            self._update_advertisement(nsx_router_id,
                                       advertise_route_nat_flag,
                                       advertise_route_connected_flag)

    def _add_router_link_port(self, tier1_uuid, tier0_uuid, edge_members):
        # Create Tier0 logical router link port
        tier0_link_port = nsxlib.create_logical_router_port(
            tier0_uuid, display_name="TIER0-RouterLinkPort",
            resource_type=nsxlib.LROUTERPORT_LINK,
            logical_port_id=None,
            address_groups=None)
        linked_logical_port_id = tier0_link_port['id']

        edge_cluster_member_index = random.choice(edge_members)
        # Create Tier1 logical router link port
        nsxlib.create_logical_router_port(
            tier1_uuid, display_name="TIER1-RouterLinkPort",
            resource_type=nsxlib.LROUTERPORT_LINK,
            logical_port_id=linked_logical_port_id,
            address_groups=None,
            edge_cluster_member_index=edge_cluster_member_index)

    def _remove_router_link_port(self, tier1_uuid, tier0_uuid):
        tier1_link_port = nsxlib.get_tier1_logical_router_link_port(tier1_uuid)
        tier1_link_port_id = tier1_link_port['id']
        tier0_link_port_id = tier1_link_port['linked_logical_router_port_id']
        nsxlib.delete_logical_router_port(tier1_link_port_id)
        nsxlib.delete_logical_router_port(tier0_link_port_id)

    def _update_advertisement(self, logical_router_id, advertise_route_nat,
                              advertise_route_connected):
        return nsxlib.update_logical_router_advertisement(
            logical_router_id,
            advertise_route_nat=advertise_route_nat,
            advertise_route_connected=advertise_route_connected)

    def _delete_gw_snat_rule(self, logical_router_id, gw_ip):
        return nsxlib.delete_nat_rule_by_values(logical_router_id,
                                                translated_network=gw_ip)

    def _add_gw_snat_rule(self, logical_router_id, gw_ip):
        return nsxlib.add_nat_rule(logical_router_id, action="SNAT",
                                   translated_network=gw_ip,
                                   rule_priority=1000)

    def _update_router_edge_cluster(self, nsx_router_id, edge_cluster_uuid):
        return nsxlib.update_logical_router(nsx_router_id,
                                            edge_cluster_id=edge_cluster_uuid)

    def create_router(self, context, router):
        # TODO(berlin): admin_state_up support
        gw_info = self._extract_external_gw(context, router, is_extract=True)
        tags = utils.build_v3_tags_payload(router['router'])
        result = nsxlib.create_logical_router(
            display_name=router['router'].get('name', 'a_router_with_no_name'),
            tags=tags)

        with context.session.begin():
            router = super(NsxV3Plugin, self).create_router(
                context, router)
            nsx_db.add_neutron_nsx_router_mapping(
                context.session, router['id'], result['id'])

        if gw_info != attributes.ATTR_NOT_SPECIFIED:
            try:
                self._update_router_gw_info(context, router['id'], gw_info)
            except nsx_exc.ManagerError:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Failed to set gateway info for router "
                                  "being created: %s - removing router"),
                              router['id'])
                    self.delete_router(context, router['id'])
                    LOG.info(_LI("Create router failed while setting external "
                                 "gateway. Router:%s has been removed from "
                                 "DB and backend"),
                             router['id'])

        return self.get_router(context, router['id'])

    def delete_router(self, context, router_id):
        ret_val = super(NsxV3Plugin, self).delete_router(context,
                                                         router_id)
        # Remove logical router from the NSX backend
        # It is safe to do now as db-level checks for resource deletion were
        # passed (and indeed the resource was removed from the Neutron DB
        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        try:
            nsxlib.delete_logical_router(nsx_router_id)
        except nsx_exc.ResourceNotFound:
            # If the logical router was not found on the backend do not worry
            # about it. The conditions has already been logged, so there is no
            # need to do further logging
            pass
        except nsx_exc.ManagerError:
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
        # TODO(berlin): admin_state_up support
        self._extract_external_gw(context, router, is_extract=False)
        r = router['router']
        try:
            if 'routes' in r:
                new_routes = r['routes']
                # TODO(berlin): Bad request if one router's nexthop is
                # in ext net
                self._validate_routes(context, router_id, new_routes)
                #old_routes = self._get_extra_routes_by_router_id(
                #    context, router_id)
                # TODO(berlin): update routes at the backend.
                #nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                #                                         router_id)
                #nsxlib.update_lrouter_routes(nsx_router_id, old_routes,
                #                             new_routes)
            return super(NsxV3Plugin, self).update_router(context, router_id,
                                                          router)
        except nsx_exc.ResourceNotFound:
            with context.session.begin(subtransactions=True):
                router_db = self._get_router(context, router_id)
                router_db['status'] = const.NET_STATUS_ERROR
            raise nsx_exc.NsxPluginException(
                err_msg=(_("logical router %s not found at the backend")
                         % router_id))
        except nsx_exc.ManagerError:
            raise nsx_exc.NsxPluginException(
                err_msg=(_("Unable to update router %s at the backend")
                         % router_id))

    def _get_router_interface_ports_by_network(
        self, context, router_id, network_id):
        port_filters = {'device_id': [router_id],
                        'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [network_id]}
        return self.get_ports(context, filters=port_filters)

    def _get_ports_and_address_groups(self, context, router_id, network_id):
        address_groups = []
        ports = self._get_router_interface_ports_by_network(
            context, router_id, network_id)
        for port in ports:
            address_group = {}
            gateway_ip = port['fixed_ips'][0]['ip_address']
            subnet = self.get_subnet(context,
                                     port['fixed_ips'][0]['subnet_id'])
            prefixlen = str(netaddr.IPNetwork(subnet['cidr']).prefixlen)
            address_group['ip_addresses'] = [gateway_ip]
            address_group['prefix_length'] = prefixlen
            address_groups.append(address_group)
        return (ports, address_groups)

    def add_router_interface(self, context, router_id, interface_info):
        # TODO(berlin): disallow multiple subnets attached to different routers
        info = super(NsxV3Plugin, self).add_router_interface(
            context, router_id, interface_info)
        subnet = self.get_subnet(context, info['subnet_ids'][0])
        port = self.get_port(context, info['port_id'])
        network_id = subnet['network_id']
        nsx_net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
            context.session, port['id'])

        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        _ports, address_groups = self._get_ports_and_address_groups(
            context, router_id, network_id)
        nsxlib.create_logical_router_port_by_ls_id(
            logical_router_id=nsx_router_id,
            ls_id=nsx_net_id,
            logical_switch_port_id=nsx_port_id,
            resource_type="LogicalRouterDownLinkPort",
            address_groups=address_groups)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        subnet = None
        subnet_id = None
        port_id = None
        self._validate_interface_info(interface_info, for_removal=True)
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            # find subnet_id - it is need for removing the SNAT rule
            port = self._get_port(context, port_id)
            if port.get('fixed_ips'):
                subnet_id = port['fixed_ips'][0]['subnet_id']
            if not (port['device_owner'] in const.ROUTER_INTERFACE_OWNERS
                    and port['device_id'] == router_id):
                raise l3.RouterInterfaceNotFound(router_id=router_id,
                                                 port_id=port_id)
        elif 'subnet_id' in interface_info:
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
        try:
            nsx_net_id, _nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            subnet = self.get_subnet(context, subnet_id)
            ports, address_groups = self._get_ports_and_address_groups(
                context, router_id, subnet['network_id'])
            nsx_router_id = nsx_db.get_nsx_router_id(
                context.session, router_id)
            if len(ports) >= 2:
                for port in ports:
                    if port['id'] != port_id:
                        new_using_port_id = port['id']
                        break
                _net_id, new_nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                    context.session, new_using_port_id)
                nsxlib.update_logical_router_port_by_ls_id(
                    nsx_router_id, nsx_net_id,
                    linked_logical_switch_port_id=new_nsx_port_id,
                    address_groups=address_groups)
            else:
                nsxlib.delete_logical_router_port_by_ls_id(nsx_net_id)
        except nsx_exc.ResourceNotFound:
            LOG.error(_LE("router port on router %(router_id)s for net "
                          "%(net_id)s not found at the backend"),
                      {'router_id': router_id,
                       'net_id': subnet['network_id']})
        return super(NsxV3Plugin, self).remove_router_interface(
            context, router_id, interface_info)

    def create_security_group_rule_bulk(self, context, security_group_rules):
        return super(NsxV3Plugin, self).create_security_group_rule_bulk_native(
            context, security_group_rules)
