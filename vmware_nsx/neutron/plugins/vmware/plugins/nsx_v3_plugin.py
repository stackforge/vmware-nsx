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

import six

import netaddr
import random
import time

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
from neutron.extensions import extra_dhcp_opt as edo_ext
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
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import securitygroups_db
from neutron.i18n import _LE, _LI, _LW
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
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  portbindings_db.PortBindingMixin,
                  agentschedulers_db.DhcpAgentSchedulerDbMixin,
                  extradhcpopt_db.ExtraDhcpOptMixin):
    # NOTE(salv-orlando): Security groups are not actually implemented by this
    # plugin at the moment

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["quotas",
                                   "binding",
                                   "extra_dhcp_opt",
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
        if tier0_uuid in self.tier0_groups_dict:
            return
        err_msg = None
        try:
            lrouter = nsxlib.get_logical_router(tier0_uuid)
        except nsx_exc.ResourceNotFound:
            err_msg = _("Failed to validate tier0 router %s since it is "
                        "not found at the backend") % tier0_uuid
        edge_cluster_uuid = lrouter.get('edge_cluster_id')
        if not edge_cluster_uuid:
            err_msg = _("Failed to get edge cluster uuid from tier0 router %s "
                        "at the backend") % lrouter
        edge_cluster = nsxlib.get_edge_cluster(edge_cluster_uuid)
        member_index_list = [member['member_index']
                             for member in edge_cluster['members']]
        if len(member_index_list) < 2:
            err_msg=_("%(num)s edge members found in edge_cluster "
                      "%(cluster_id)s, however we should prepare at "
                      "least 2 edge nodes in edge cluster for "
                      "HA use.") % {'num': len(member_index_list),
                                    'cluster_id': edge_cluster_uuid}
        if err_msg:
            raise n_exc.InvalidInput(error_message=err_msg)
        else:
            self.tier0_groups_dict[tier0_uuid] = {
                'edge_cluster_uuid': edge_cluster_uuid,
                'member_index_list': member_index_list}

    def _get_edge_cluster_and_members(self, tier0_uuid):
        self._validate_tier0(tier0_uuid)
        tier0_info = self.tier0_groups_dict[tier0_uuid]
        return (tier0_info['edge_cluster_uuid'],
                tier0_info['member_index_list'])

    def _validate_provider_ext_net_create(self, net_data):
        is_provider_net = False
        if not attributes.is_attr_set(net_data.get(pnet.PHYSICAL_NETWORK)):
            tier0_uuid = cfg.CONF.nsx_v3.default_tier0_router_uuid
        else:
            tier0_uuid = net_data[pnet.PHYSICAL_NETWORK]
            is_provider_net = True
        self._validate_tier0(tier0_uuid)
        return (is_provider_net, "l3_ext", tier0_uuid, 0)

    def _create_network_at_the_backend(self, context, net_data):
            is_provider_net = any(
                attributes.is_attr_set(net_data.get(f))
                for f in (pnet.NETWORK_TYPE,
                          pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID))
            net_type, physical_net, vlan_id = self._validate_provider_create(
                context, net_data)
            net_name = net_data['name']
            tags = utils.build_v3_tags_payload(net_data)
            admin_state = net_data.get('admin_state_up', True)

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
            net_data['id'] = net_id
            return (is_provider_net, net_type, physical_net, vlan_id)

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
        if attributes.is_attr_set(external) and external:
            is_provider_net, net_type, physical_net, vlan_id = (
                self._validate_provider_ext_net_create(net_data))
        else:
            is_provider_net, net_type, physical_net, vlan_id = (
                self._create_network_at_the_backend(context, net_data))
        tenant_id = self._get_tenant_id_for_create(
            context, net_data)
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
                    LOG.exception(_LE('Failed to create network %s'),
                                  new_net['id'])
                    nsxlib.delete_logical_switch(new_net['id'])

            if is_provider_net:
                # Save provider network fields, needed by get_network()
                net_bindings = [nsx_db.add_network_binding(
                    context.session, new_net['id'],
                    net_type, physical_net, vlan_id)]
                self._extend_network_dict_provider(context, new_net,
                                                   bindings=net_bindings)

        return new_net

    def delete_network(self, context, network_id):
        # First call DB operation for delete network as it will perform
        # checks on active ports
        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, network_id)
            ret_val = super(NsxV3Plugin, self).delete_network(
                context, network_id)
        if not self._network_is_external(context, network_id):
            # TODO(salv-orlando): Handle backend failure, possibly without
            # requiring us to un-delete the DB object. For instance, ignore
            # failures occuring if logical switch is not found
            nsxlib.delete_logical_switch(network_id)
        else:
            # TODO(berlin): delete subnets public announce on the network
            pass
        return ret_val

    def update_network(self, context, network_id, network):
        # TODO(arosen) - call to backend
        net = super(NsxV3Plugin, self).update_network(context, network_id,
                                                      network)
        self._process_l3_update(context, net, network['network'])
        return net

    def create_subnet(self, context, subnet):
        # TODO(berlin): announce external subnet
        return super(NsxV3Plugin, self).create_subnet(context, subnet)

    def delete_subnet(self, context, subnet_id):
        # TODO(berlin): delete external subnet public announcement
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
            net = self._make_network_dict(network, context=context)
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

    def _get_data_from_binding_profile(self, context, port):
        if (pbin.PROFILE not in port or
                not attributes.is_attr_set(port[pbin.PROFILE])):
            return None, None

        parent_name = (
            port[pbin.PROFILE].get('parent_name'))
        tag = port[pbin.PROFILE].get('tag')
        if not any((parent_name, tag)):
            # An empty profile is fine.
            return None, None
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
            # FIXME(arosen): use neutron.plugins.common.utils.is_valid_vlan_tag
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
        # NOTE(arosen): For demo reasons the parent_port might not be a
        # a neutron managed port so for now do not perform this check.
        # self.get_port(context, parent_name)
        return parent_name, tag

    def _create_port_at_the_backend(self, context, neutron_db, port_data):
        tags = utils.build_v3_tags_payload(port_data)
        parent_name, tag = self._get_data_from_binding_profile(
            context, port_data)
        address_bindings = self._build_address_bindings(port_data)
        # FIXME(arosen): we might need to pull this out of the
        # transaction here later.
        result = nsxlib.create_logical_port(
            lswitch_id=port_data['network_id'],
            vif_uuid=port_data['id'], name=port_data['name'], tags=tags,
            admin_state=port_data['admin_state_up'],
            address_bindings=address_bindings,
            parent_name=parent_name, parent_tag=tag)

        # TODO(salv-orlando): The logical switch identifier in the
        # mapping object is not necessary anymore.
        nsx_db.add_neutron_nsx_port_mapping(
            context.session, neutron_db['id'],
            neutron_db['network_id'], result['id'])

    def create_port(self, context, port):
        dhcp_opts = port['port'].get(edo_ext.EXTRADHCPOPTS, [])
        port_id = uuidutils.generate_uuid()
        port['port']['id'] = port_id

        self._ensure_default_security_group_on_port(context, port)
        # TODO(salv-orlando): Undo logical switch creation on failure
        with context.session.begin(subtransactions=True):
            neutron_db = super(NsxV3Plugin, self).create_port(context, port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         neutron_db)

            port["port"].update(neutron_db)

            if not self._network_is_external(
                context, port['port']['network_id']):
                self._create_port_at_the_backend(
                    context, neutron_db, port['port'])
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         neutron_db)

            neutron_db[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL
            if (pbin.PROFILE in port['port'] and
                attributes.is_attr_set(port['port'][pbin.PROFILE])):
                neutron_db[pbin.PROFILE] = port['port'][pbin.PROFILE]
            sgids = self._get_security_groups_on_port(context, port)
            self._process_port_create_security_group(
                context, neutron_db, sgids)
            self._process_port_create_extra_dhcp_opts(context, neutron_db,
                                                      dhcp_opts)
        return neutron_db

    def delete_port(self, context, port_id, l3_port_check=True):
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, port_id)
        port = self.get_port(context, port_id)
        if not self._network_is_external(context, port['network_id']):
            _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            nsxlib.delete_logical_port(nsx_port_id)
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
            self._update_extra_dhcp_opts_on_port(context, id, port,
                                                 updated_port)
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
        # is removed or changed
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
        bgp_announce = (not new_enable_snat and new_tier0_uuid and
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
            # work around bug 1506494
            time.sleep(20)
            self._add_router_link_port(nsx_router_id, new_tier0_uuid, members)
        if add_snat_rules:
            self._add_gw_snat_rule(nsx_router_id, newaddr)
        if bgp_announce:
            # bgp announce on new tier0 router
            pass

        if remove_snat_rules or add_snat_rules:
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

        edge_cluster_member_index = random.sample(edge_members, 2)
        # Create Tier1 logical router link port
        nsxlib.create_logical_router_port(
            tier1_uuid, display_name="TIER1-RouterLinkPort",
            resource_type=nsxlib.LROUTERPORT_LINK,
            logical_port_id=linked_logical_port_id,
            address_groups=None,
            edge_cluster_member_index=edge_cluster_member_index)

    def _remove_router_link_port(self, tier1_uuid, tier0_uuid):
        try:
            tier1_link_port = nsxlib.get_tier1_logical_router_link_port(
                tier1_uuid)
        except nsx_exc.ResourceNotFound:
            LOG.warning(_LW("Logical router link port for tier1 router: %s "
                            "not found at the backend"), tier1_uuid)
            return
        tier1_link_port_id = tier1_link_port['id']
        tier0_link_port_id = tier1_link_port['linked_logical_router_port_id']
        nsxlib.delete_logical_router_port(tier1_link_port_id)
        nsxlib.delete_logical_router_port(tier0_link_port_id)

    def _update_advertisement(self, logical_router_id, advertise_route_nat,
                              advertise_route_connected):
        return nsxlib.update_logical_router_advertisement(
            logical_router_id,
            advertise_nat_routes=advertise_route_nat,
            advertise_connected_routes=advertise_route_connected)

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
        router = self.get_router(context, router_id)
        if router.get(l3.EXTERNAL_GW_INFO):
            self._update_router_gw_info(context, router_id, {})
        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        ret_val = super(NsxV3Plugin, self).delete_router(context,
                                                         router_id)
        # Remove logical router from the NSX backend
        # It is safe to do now as db-level checks for resource deletion were
        # passed (and indeed the resource was removed from the Neutron DB
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
                            "Neutron database"), router_id)

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

    def _get_ports_and_address_groups(self, context, router_id, network_id,
                                      exclude_sub_ids=None):
        exclude_sub_ids = [] if not exclude_sub_ids else exclude_sub_ids
        address_groups = []
        ports = self._get_router_interface_ports_by_network(
            context, router_id, network_id)
        ports = [port for port in ports
                 if port['fixed_ips'] and
                 port['fixed_ips'][0]['subnet_id'] not in exclude_sub_ids]
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

    def _validate_multiple_subnets_diff_routers(self, context, network_id):
        port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [network_id]}
        intf_ports = self.get_ports(context, filters=port_filters)
        router_ids = [port['device_id'] for port in intf_ports]
        router_id_set = set(router_ids)
        if len(router_id_set) >= 2:
            err_msg = _("Nsxv3 Can't support multiple subnets on network %s "
                        "are attached to different router in case of network "
                        "topology complexity") % network_id
            raise n_exc.InvalidInput(error_message=err_msg)

    def add_router_interface(self, context, router_id, interface_info):

        info = super(NsxV3Plugin, self).add_router_interface(
            context, router_id, interface_info)
        try:
            subnet = self.get_subnet(context, info['subnet_ids'][0])
            port = self.get_port(context, info['port_id'])
            network_id = subnet['network_id']
            # disallow multiple subnets belong to same network are attached to
            # different routers
            self._validate_multiple_subnets_diff_routers(context, network_id)
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

            # Announce the subnet on tier0 if enable_snat is False
            router_db = self._get_router(context, router_id)
            if router_db.gw_port and not router_db.enable_snat:
                pass
        except n_exc.InvalidInput:
            with excutils.save_and_reraise_exception():
                super(NsxV3Plugin, self).remove_router_interface(
                    context, router_id, interface_info)
        except nsx_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                self.remove_router_interface(
                    context, router_id, interface_info)
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
            # Revocate announce the subnet on tier0 if enable_snat is False
            router_db = self._get_router(context, router_id)
            if router_db.gw_port and not router_db.enable_snat:
                pass

            nsx_net_id, _nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            subnet = self.get_subnet(context, subnet_id)
            ports, address_groups = self._get_ports_and_address_groups(
                context, router_id, subnet['network_id'],
                exclude_sub_ids=[subnet['id']])
            nsx_router_id = nsx_db.get_nsx_router_id(
                context.session, router_id)
            if len(ports) >= 1:
                new_using_port_id = ports[0]['id']
                _net_id, new_nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                    context.session, new_using_port_id)
                nsxlib.update_logical_router_port_by_ls_id(
                    nsx_router_id, nsx_net_id,
                    linked_logical_switch_port_id=new_nsx_port_id,
                    subnets=address_groups)
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

    def extend_port_dict_binding(self, port_res, port_db):
        super(NsxV3Plugin, self).extend_port_dict_binding(port_res, port_db)
        port_res[pbin.VNIC_TYPE] = pbin.VNIC_NORMAL
