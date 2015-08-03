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
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import securitygroups_db
from neutron.i18n import _LE, _LW
from neutron.plugins.common import constants as plugin_const
from neutron.plugins.common import utils as n_utils

from vmware_nsx.neutron.plugins.vmware.common import config  # noqa
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import utils
from vmware_nsx.neutron.plugins.vmware.dbexts import db as nsx_db
from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib

LOG = log.getLogger(__name__)


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
                                   "provider",
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

    def _validate_provider_create(self, context, network_data):
        physical_net = network_data.get(pnet.PHYSICAL_NETWORK)
        if not attributes.is_attr_set(physical_net):
            physical_net = None

        vlan_id = network_data.get(pnet.SEGMENTATION_ID)
        if not attributes.is_attr_set(vlan_id):
            vlan_id = None

        err_msg = None
        net_type = network_data.get(pnet.NETWORK_TYPE)
        if attributes.is_attr_set(net_type):
            if net_type == utils.NsxV3NetworkTypes.FLAT:
                if vlan_id is not None:
                    err_msg = (_("Segmentation ID cannot be specified with "
                                 "%s network type") %
                               utils.NsxV3NetworkTypes.FLAT)
                else:
                    # Set VLAN id to 0 for flat networks
                    vlan_id = '0'
                    if physical_net is None:
                        physical_net = cfg.CONF.nsx_v3.default_vlan_tz_uuid
            elif net_type == utils.NsxV3NetworkTypes.VLAN:
                # Use default VLAN transport zone if physical network not given
                if physical_net is None:
                    physical_net = cfg.CONF.nsx_v3.default_vlan_tz_uuid

                # Validate VLAN id
                if not vlan_id:
                    err_msg = (_('Segmentation ID must be specified with %s '
                                 'network type') %
                               utils.NsxV3NetworkTypes.VLAN)
                elif not n_utils.is_valid_vlan_tag(vlan_id):
                    err_msg = (_('Segmentation ID %(segmentation_id)s out of '
                                 'range (%(min_id)s through %(max_id)s)') %
                               {'segmentation_id': vlan_id,
                                'min_id': plugin_const.MIN_VLAN_TAG,
                                'max_id': plugin_const.MAX_VLAN_TAG})
                else:
                    # Verify VLAN id is not already allocated
                    bindings = (
                        nsx_db.get_network_bindings_by_vlanid_and_physical_net(
                            context.session, vlan_id, physical_net)
                    )
                    if bindings:
                        raise n_exc.VlanIdInUse(
                            vlan_id=vlan_id, physical_network=physical_net)
            elif net_type == utils.NsxV3NetworkTypes.VXLAN:
                if vlan_id:
                    err_msg = (_("Segmentation ID cannot be specified with "
                                 "%s network type") %
                               utils.NsxV3NetworkTypes.VXLAN)
            else:
                err_msg = (_('%(net_type_param)s %(net_type_value)s not '
                             'supported') %
                           {'net_type_param': pnet.NETWORK_TYPE,
                            'net_type_value': net_type})
        else:
            net_type = None

        if err_msg:
            raise n_exc.InvalidInput(error_message=err_msg)

        if physical_net is None:
            # Default to transport type overlay
            physical_net = cfg.CONF.nsx_v3.default_overlay_tz_uuid

        return net_type, physical_net, vlan_id

    def _validate_tier0(self, tier0_uuid):
        if tier0_uuid in self.tier0_groups_dict.keys():
            return True
        try:
            lrouter = nsxlib.get_logical_router(tier0_uuid)
            edge_cluster_uuid = lrouter.get('edge_cluster_id')
            if not edge_cluster_uuid:
                raise nsx_exc.NsxPluginException(
                    err_msg=_("Failed to get edge cluster uuid from LR %s "
                              "at the backend") % lrouter)
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
            self.tier0_groups_dict['tier0_uuid'] = {
                'edge_cluster_uuid': edge_cluster_uuid,
                'member_index_list': member_index_list}
            return True

    def _validate_provider_ext_net_create(self, net_data):
        err_msg = None
        is_provider_net = False
        if not attributes.is_attr_set(net_data.get(pnet.PHYSICAL_NETWORK)):
            tier0_uuid = cfg.CONF.nsx_v3.default_tier0_router_uuid
            if not tier0_uuid:
                err_msg = _("Default tier0 router uuid is not specified for "
                            "the net")
        else:
            tier0_uuid = net_data[pnet.PHYSICAL_NETWORK]
            is_provider_net = True
        if not self._validate_tier0(tier0_uuid):
            err_msg = _("tier0 %s can not be validated") % tier0_uuid
        if err_msg:
            raise n_exc.InvalidInput(error_message=err_msg)
        return (is_provider_net, "l3_ext", tier0_uuid, 0)

    def _extend_network_dict_provider(self, context, network, bindings=None):
        if not bindings:
            bindings = nsx_db.get_network_bindings(context.session,
                                                   network['id'])
        # With NSX plugin, "normal" overlay networks will have no binding
        if bindings:
            # Network came in through provider networks API
            network[pnet.NETWORK_TYPE] = bindings[0].binding_type
            network[pnet.PHYSICAL_NETWORK] = bindings[0].phy_uuid
            network[pnet.SEGMENTATION_ID] = bindings[0].vlan_id

    def create_network(self, context, network):
        net_data = network['network']
        external = net_data.get(ext_net_extn.EXTERNAL)
        if  attributes.is_attr_set(external) and external:
            is_provider_net, net_type, physical_net, vlan_id = (
                self._validate_provider_ext_net_create(net_data))
            net_id = None
        backend_network = not attributes.is_attr_set(external) or not external
        if backend_network:
            # TODO(jwy): Handle creating external network (--router:external)
            is_provider_net = any(
                attributes.is_attr_set(network['network'].get(f))
                for f in (pnet.NETWORK_TYPE,
                          pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID))
            net_type, physical_net, vlan_id = self._validate_provider_create(
                context, network['network'])
            net_name = network['network']['name']
            tags = utils.build_v3_tags_payload(network['network'])
            admin_state = network['network'].get('admin_state_up', True)

            # Create network on the backend
            LOG.debug('create_network: %(net_name)s, %(physical_net)s, '
                      '%(tags)s, %(admin_state)s, %(vlan_id)s',
                      {'net_name': net_name,
                       'physical_net': physical_net,
                       'tags': tags,
                       'admin_state': admin_state,
                       'vlan_id': vlan_id})
            result = nsxlib.create_logical_switch(net_name, physical_net, tags,
                                                  admin_state=admin_state,
                                                  vlan_id=vlan_id)
            net_id = result['id']
            network['network']['id'] = net_id
            tenant_id = self._get_tenant_id_for_create(
                context, network['network'])

            self._ensure_default_security_group(context, tenant_id)
        with context.session.begin(subtransactions=True):
            # Create network in Neutron
            try:
                new_net = super(NsxV3Plugin, self).create_network(context,
                                                                  network)
                self._process_l3_create(context, new_net, net_data)
            except Exception:
                with excutils.save_and_reraise_exception():
                    # Undo creation on the backend
                    LOG.exception(_LE('Failed to create network %s'), net_id)
                    nsxlib.delete_logical_switch(net_id)

            if is_provider_net:
                # Save provider network fields, needed by get_network()
                net_id = net_id if net_id else new_net['id']
                net_bindings = [nsx_db.add_network_binding(
                    context.session, net_id, net_type, physical_net, vlan_id)]
                self._extend_network_dict_provider(context, new_net,
                                                   bindings=net_bindings)

        return new_net
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
                                                 fields=None)
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
        return super(NsxV3Plugin, self).update_network(context, network_id,
                                                       network)

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

    def get_network(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            # Get network from Neutron database
            network = self._get_network(context, id)
            # Don't do field selection here otherwise we won't be able to add
            # provider networks fields
            net = self._make_network_dict(network, fields=None)
            self._extend_network_dict_provider(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        # Get networks from Neutron database
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            networks = (
                super(NsxV3Plugin, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            # Add provider network fields
            for net in networks:
                self._extend_network_dict_provider(context, net)
        return [self._fields(network, fields) for network in networks]

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
        port = self.get_port(context, port_id)
        if not self._network_is_external(context, port['network_id']):
            _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            nsxlib.delete_logical_port(nsx_port_id)
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

    def create_router(self, context, router):
        tags = utils.build_v3_tags_payload(router['router'])
        result = nsxlib.create_logical_router(
            display_name=router['router'].get('name', 'a_router_with_no_name'),
            tags=tags,
            tier_0=True,
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
