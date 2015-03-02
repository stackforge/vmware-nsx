# Copyright 2014 VMware, Inc.
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

import uuid

import netaddr
from oslo.config import cfg
from oslo.utils import excutils
from oslo_concurrency import lockutils
from sqlalchemy.orm import exc as sa_exc

from neutron.api import extensions as neutron_extensions
from neutron.api.v2 import attributes as attr
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron import context as neutron_context
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db
from neutron.extensions import external_net as ext_net_extn
from neutron.extensions import l3
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings as pbin
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as ext_sg
from neutron.i18n import _LE, _LW
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.extensions import (
    advancedserviceproviders as as_providers)
from neutron.plugins.vmware.extensions import (
    vnicindex as ext_vnic_idx)

from vmware_nsx.neutron.plugins import vmware
from vmware_nsx.neutron.plugins.vmware.common import config  # noqa
from vmware_nsx.neutron.plugins.vmware.common import utils as c_utils
from vmware_nsx.neutron.plugins.vmware.dbexts import (
    routertype as rt_rtr)
from vmware_nsx.neutron.plugins.vmware.dbexts import db as nsx_db
from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_db
from vmware_nsx.neutron.plugins.vmware.dbexts import vnic_index_db
from vmware_nsx.neutron.plugins.vmware.plugins import managers
from vmware_nsx.neutron.plugins.vmware.plugins import nsx_v_md_proxy
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    constants as vcns_const)
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    exceptions as vsh_exc)
from vmware_nsx.neutron.plugins.vmware.vshield import edge_utils
from vmware_nsx.neutron.plugins.vmware.vshield import securitygroup_utils
from vmware_nsx.neutron.plugins.vmware.vshield import vcns_driver

LOG = logging.getLogger(__name__)
PORTGROUP_PREFIX = 'dvportgroup'


class NsxVPluginV2(agents_db.AgentDbMixin,
                   db_base_plugin_v2.NeutronDbPluginV2,
                   rt_rtr.RouterType_mixin,
                   external_net_db.External_net_db_mixin,
                   extraroute_db.ExtraRoute_db_mixin,
                   l3_gwmode_db.L3_NAT_db_mixin,
                   portbindings_db.PortBindingMixin,
                   portsecurity_db.PortSecurityDbMixin,
                   securitygroups_db.SecurityGroupDbMixin,
                   vnic_index_db.VnicIndexDbMixin):

    supported_extension_aliases = ["agent",
                                   "binding",
                                   "dvr",
                                   "ext-gw-mode",
                                   "multi-provider",
                                   "port-security",
                                   "provider",
                                   "quotas",
                                   "external-net",
                                   "extraroute",
                                   "router",
                                   "security-group",
                                   "nsxv-router-type",
                                   "vnic-index",
                                   "advanced-service-providers"]

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        super(NsxVPluginV2, self).__init__()
        config.validate_nsxv_config_options()
        neutron_extensions.append_api_extensions_path([vmware.NSX_EXT_PATH])

        self.base_binding_dict = {
            pbin.VNIC_TYPE: pbin.VNIC_NORMAL,
            pbin.VIF_TYPE: pbin.VIF_TYPE_DVS,
            pbin.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                pbin.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        # Create the client to interface with the NSX-v
        _nsx_v_callbacks = edge_utils.NsxVCallbacks(self)
        self.nsx_v = vcns_driver.VcnsDriver(_nsx_v_callbacks)
        self.edge_manager = edge_utils.EdgeManager(self.nsx_v)
        self.vdn_scope_id = cfg.CONF.nsxv.vdn_scope_id
        self.dvs_id = cfg.CONF.nsxv.dvs_id
        self.nsx_sg_utils = securitygroup_utils.NsxSecurityGroupUtils(
            self.nsx_v)
        # Ensure that edges do concurrency
        self._ensure_lock_operations()
        self.sg_container_id = self._create_security_group_container()
        self._validate_config()
        self._create_cluster_default_fw_rules()
        self._router_managers = managers.RouterTypeManager(self)

        has_metadata_cfg = (
            cfg.CONF.nsxv.nova_metadata_ips
            and cfg.CONF.nsxv.mgt_net_moid
            and cfg.CONF.nsxv.mgt_net_proxy_ips
            and cfg.CONF.nsxv.mgt_net_proxy_netmask)
        self.metadata_proxy_handler = (
            nsx_v_md_proxy.NsxVMetadataProxyHandler(self)
            if has_metadata_cfg else None)

    def _create_security_group_container(self):
        name = "OpenStack Security Group container"
        container_id = self.nsx_v.vcns.get_security_group_id(name)
        if not container_id:
            description = ("OpenStack Security Group Container, "
                           "managed by Neutron nsx-v plugin.")
            container = {"securitygroup": {"name": name,
                                           "description": description}}
            h, container_id = self.nsx_v.vcns.create_security_group(container)
        return container_id

    def _find_router_driver(self, context, router_id):
        router_qry = context.session.query(l3_db.Router)
        router_db = router_qry.filter_by(id=router_id).one()
        return self._get_router_driver(context, router_db)

    def _get_router_driver(self, context, router_db):
        router_type_dict = {}
        self._extend_nsx_router_dict(router_type_dict, router_db)
        router_type = None
        if router_type_dict.get("distributed", False):
            router_type = "distributed"
        else:
            router_type = router_type_dict.get("router_type")
        return self._router_managers.get_tenant_router_driver(
            context, router_type)

    def _decide_router_type(self, context, r):
        router_type = None
        if attr.is_attr_set(r.get("distributed")) and r.get("distributed"):
            router_type = "distributed"
        elif attr.is_attr_set(r.get("router_type")):
            router_type = r.get("router_type")

        router_type = self._router_managers.decide_tenant_router_type(
            context, router_type)
        if router_type == "distributed":
            r["distributed"] = True
            r["router_type"] = "exclusive"
        else:
            r["distributed"] = False
            r["router_type"] = router_type

    def _create_cluster_default_fw_rules(self):
        # default cluster rules
        rules = [{'name': 'Default DHCP rule for OS Security Groups',
                  'action': 'allow',
                  'services': [('17', '67', None, None),
                               ('17', '68', None, None)]},
                 {'name': 'ICMPv6 neighbor protocol for Security Groups',
                  'action': 'allow',
                  'services': [('58', None, '135', None),
                               ('58', None, '136', None)]}]

        rule_list = []
        for cluster_moid in cfg.CONF.nsxv.cluster_moid:
            for rule in rules:
                rule_config = self.nsx_sg_utils.get_rule_config(
                    cluster_moid, rule['name'], rule['action'],
                    'ClusterComputeResource', services=rule['services'])
                rule_list.append(rule_config)

        block_rule = self.nsx_sg_utils.get_rule_config(
            self.sg_container_id, 'Block All', 'deny')
        rule_list.append(block_rule)

        if rule_list:
            section_name = 'OS Cluster Security Group section'
            section_id = self.nsx_v.vcns.get_section_id(section_name)
            section = self.nsx_sg_utils.get_section_with_rules(
                section_name, rule_list)
            if section_id:
                section.attrib['id'] = section_id
                self.nsx_v.vcns.update_section_by_id(
                    section_id, 'ip', self.nsx_sg_utils.to_xml_string(section))
            else:
                try:
                    self.nsx_v.vcns.create_section(
                        'ip', self.nsx_sg_utils.to_xml_string(section))
                except vsh_exc.RequestBad as e:
                    # Section already exists, log-it and return
                    LOG.debug("Could not create NSX fw section for cluster"
                              " %s: %s", cluster_moid, e.response)

    def _create_dhcp_static_binding(self, context, neutron_port_db):

        network_id = neutron_port_db['network_id']
        device_owner = neutron_port_db['device_owner']
        if device_owner.startswith("compute"):
            s_bindings = self._create_static_binding(context,
                                                     neutron_port_db)
            edge_utils.create_dhcp_bindings(context, self.nsx_v,
                                            network_id, s_bindings)

    def _delete_dhcp_static_binding(self, context, neutron_port_db):

        network_id = neutron_port_db['network_id']
        device_owner = neutron_port_db['device_owner']
        if device_owner.startswith("compute"):
            edge_utils.delete_dhcp_binding(context, self.nsx_v, network_id,
                                           neutron_port_db['mac_address'])

    def _validate_provider_create(self, context, network):
        if not attr.is_attr_set(network.get(mpnet.SEGMENTS)):
            return

        external = network.get(ext_net_extn.EXTERNAL)
        for segment in network[mpnet.SEGMENTS]:
            network_type = segment.get(pnet.NETWORK_TYPE)
            physical_network = segment.get(pnet.PHYSICAL_NETWORK)
            segmentation_id = segment.get(pnet.SEGMENTATION_ID)
            network_type_set = attr.is_attr_set(network_type)
            segmentation_id_set = attr.is_attr_set(segmentation_id)
            physical_network_set = attr.is_attr_set(physical_network)

            err_msg = None
            if not network_type_set:
                err_msg = _("%s required") % pnet.NETWORK_TYPE
            elif (attr.is_attr_set(external) and external and
                  network_type != c_utils.NsxVNetworkTypes.PORTGROUP):
                    err_msg = _("portgroup only supported on external "
                                "networks")
            elif network_type == c_utils.NsxVNetworkTypes.FLAT:
                if segmentation_id_set:
                    err_msg = _("Segmentation ID cannot be specified with "
                                "flat network type")
            elif network_type == c_utils.NsxVNetworkTypes.VLAN:
                if not segmentation_id_set:
                    err_msg = _("Segmentation ID must be specified with "
                                "vlan network type")
                elif (segmentation_id_set and
                      not utils.is_valid_vlan_tag(segmentation_id)):
                    err_msg = (_("%(segmentation_id)s out of range "
                                 "(%(min_id)s through %(max_id)s)") %
                               {'segmentation_id': segmentation_id,
                                'min_id': constants.MIN_VLAN_TAG,
                                'max_id': constants.MAX_VLAN_TAG})
                else:
                    # Verify segment is not already allocated
                    bindings = nsxv_db.get_network_bindings_by_vlanid(
                        context.session, segmentation_id)
                    if bindings:
                        phy_uuid = (physical_network if physical_network_set
                                    else self.dvs_id)
                        for binding in bindings:
                            if binding['phy_uuid'] == phy_uuid:
                                raise n_exc.VlanIdInUse(
                                    vlan_id=segmentation_id,
                                    physical_network=phy_uuid)

            elif network_type == c_utils.NsxVNetworkTypes.VXLAN:
                # Currently unable to set the segmentation id
                if segmentation_id_set:
                    err_msg = _("Segmentation ID cannot be set with VXLAN")
            elif network_type == c_utils.NsxVNetworkTypes.PORTGROUP:
                if segmentation_id_set:
                    err_msg = _("Segmentation ID cannot be set with portgroup")
                if (not attr.is_attr_set(external) or
                    attr.is_attr_set(external) and not external):
                    err_msg = _("portgroup only supported on external "
                                "networks")
                physical_net_set = attr.is_attr_set(physical_network)
                if (physical_net_set
                    and not self.nsx_v.vcns.validate_network(
                        physical_network)):
                    err_msg = _("Physical network doesn't exist")
            else:
                err_msg = (_("%(net_type_param)s %(net_type_value)s not "
                             "supported") %
                           {'net_type_param': pnet.NETWORK_TYPE,
                            'net_type_value': network_type})
            if err_msg:
                raise n_exc.InvalidInput(error_message=err_msg)
            # TODO(salvatore-orlando): Validate tranport zone uuid
            # which should be specified in physical_network

    def _extend_network_dict_provider(self, context, network,
                                      multiprovider=None, bindings=None):
        if not bindings:
            bindings = nsxv_db.get_network_bindings(context.session,
                                                    network['id'])
        if not multiprovider:
            multiprovider = nsx_db.is_multiprovider_network(context.session,
                                                            network['id'])
        # With NSX plugin 'normal' overlay networks will have no binding
        # TODO(salvatore-orlando) make sure users can specify a distinct
        # phy_uuid as 'provider network' for STT net type
        if bindings:
            if not multiprovider:
                # network came in through provider networks api
                network[pnet.NETWORK_TYPE] = bindings[0].binding_type
                network[pnet.PHYSICAL_NETWORK] = bindings[0].phy_uuid
                network[pnet.SEGMENTATION_ID] = bindings[0].vlan_id
            else:
                # network come in though multiprovider networks api
                network[mpnet.SEGMENTS] = [
                    {pnet.NETWORK_TYPE: binding.binding_type,
                     pnet.PHYSICAL_NETWORK: binding.phy_uuid,
                     pnet.SEGMENTATION_ID: binding.vlan_id}
                    for binding in bindings]

    def _get_name(self, id, name):
        if name is not None:
            return '%s (%s)' % (name, id)
        return id

    def _get_subnet_as_providers(self, context, subnet):
        net_id = subnet.get('network_id')
        if net_id is None:
            net_id = self.get_subnet(context, subnet['id']).get('network_id')
        as_provider_data = nsxv_db.get_edge_vnic_bindings_by_int_lswitch(
            context.session, net_id)

        providers = [asp['edge_id'] for asp in as_provider_data]
        return providers

    def get_subnet(self, context, id, fields=None):
        subnet = super(NsxVPluginV2, self).get_subnet(context, id, fields)

        if not context.is_admin:
            return subnet
        elif not fields or as_providers.ADV_SERVICE_PROVIDERS in fields:
            subnet[as_providers.ADV_SERVICE_PROVIDERS] = (
                self._get_subnet_as_providers(context, subnet))
        return subnet

    def get_subnets(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        subnets = super(NsxVPluginV2, self).get_subnets(context, filters,
                                                        fields, sorts, limit,
                                                        marker, page_reverse)

        if not context.is_admin:
            return subnets

        new_subnets = []
        if(not fields
           or as_providers.ADV_SERVICE_PROVIDERS in fields
           or (filters and filters.get(as_providers.ADV_SERVICE_PROVIDERS))):

            # We only deal metadata provider field when:
            # - All fields are retrieved
            # - adv_service_provider is explicitly retrieved
            # - adv_service_provider is used in a filter
            for subnet in subnets:
                as_provider = self._get_subnet_as_providers(context, subnet)
                md_filter = (
                    None if filters is None
                    else filters.get('as_providers.ADV_SERVICE_PROVIDERS'))

                if md_filter is None or len(set(as_provider) & set(md_filter)):
                    # Include metadata_providers only if requested in results
                    if(not fields
                       or as_providers.ADV_SERVICE_PROVIDERS in fields):
                        subnet[as_providers.ADV_SERVICE_PROVIDERS] = (
                            as_provider)

                    new_subnets.append(subnet)
        else:
            # No need to handle metadata providers field
            return subnets

        return new_subnets

    def _convert_to_transport_zones_dict(self, network):
        """Converts the provider request body to multiprovider.
        Returns: True if request is multiprovider False if provider
        and None if neither.
        """
        if any(attr.is_attr_set(network.get(f))
               for f in (pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                         pnet.SEGMENTATION_ID)):
            if attr.is_attr_set(network.get(mpnet.SEGMENTS)):
                raise mpnet.SegmentsSetInConjunctionWithProviders()
            # convert to transport zone list
            network[mpnet.SEGMENTS] = [
                {pnet.NETWORK_TYPE: network[pnet.NETWORK_TYPE],
                 pnet.PHYSICAL_NETWORK: network[pnet.PHYSICAL_NETWORK],
                 pnet.SEGMENTATION_ID: network[pnet.SEGMENTATION_ID]}]
            del network[pnet.NETWORK_TYPE]
            del network[pnet.PHYSICAL_NETWORK]
            del network[pnet.SEGMENTATION_ID]
            return False
        if attr.is_attr_set(network.get(mpnet.SEGMENTS)):
            return True

    def _delete_backend_network(self, moref):
        """Deletes the backend NSX network.

        This can either be a VXLAN or a VLAN network. The type is determined
        by the prefix of the moref.
        """
        if moref.startswith(PORTGROUP_PREFIX):
            self.nsx_v.delete_port_group(self.dvs_id, moref)
        else:
            self.nsx_v.delete_virtual_wire(moref)

    def _get_vlan_network_name(self, net_data):
        if net_data['name'] == '':
            return net_data['id']
        else:
            # Maximum name length is 80 characters. 'id' length is 36
            # maximum prefix for name is 43
            return '%s-%s' % (net_data['name'][:43], net_data['id'])

    def _get_default_security_group(self, context, tenant_id):
        return self._ensure_default_security_group(context, tenant_id)

    def _add_member_to_security_group(self, sg_id, vnic_id):
        with lockutils.lock(str(sg_id),
                            lock_file_prefix='neutron-security-ops'):
            try:
                h, c = self.nsx_v.vcns.add_member_to_security_group(
                    sg_id, vnic_id)
                LOG.info(_("Added %s(sg_id)s member to NSX security "
                           "group %(vnic_id)s"),
                         {'sg_id': sg_id, 'vnic_id': vnic_id})
            except Exception as e:
                LOG.debug("NSX security group %(sg_id)s member add "
                          "failed %(vnic_id)s - attempt %(attempt)d. "
                          "Exception: %(exc)s",
                          {'sg_id': sg_id,
                           'vnic_id': vnic_id,
                           'exc': e})

    def _add_security_groups_port_mapping(self, session, vnic_id,
                                          added_sgids):
        if vnic_id is None or added_sgids is None:
            return
        for add_sg in added_sgids:
            nsx_sg_id = nsx_db.get_nsx_security_group_id(session, add_sg)
            if nsx_sg_id is None:
                LOG.warning(_LW("NSX security group not found for %s"), add_sg)
            else:
                self._add_member_to_security_group(nsx_sg_id, vnic_id)

    def _remove_member_from_security_group(self, sg_id, vnic_id):
        with lockutils.lock(str(sg_id),
                            lock_file_prefix='neutron-security-ops'):
            try:
                h, c = self.nsx_v.vcns.remove_member_from_security_group(
                    sg_id, vnic_id)
            except Exception:
                LOG.debug("NSX security group %(nsx_sg_id)s member "
                          "delete failed %(vnic_id)s",
                          {'nsx_sg_id': sg_id,
                           'vnic_id': vnic_id})

    def _delete_security_groups_port_mapping(self, session, vnic_id,
                                             deleted_sgids):
        if vnic_id is None or deleted_sgids is None:
            return
        # Remove vnic from delete security groups binding
        for del_sg in deleted_sgids:
            nsx_sg_id = nsx_db.get_nsx_security_group_id(session, del_sg)
            if nsx_sg_id is None:
                LOG.warning(_LW("NSX security group not found for %s"), del_sg)
            else:
                self._remove_member_from_security_group(nsx_sg_id, vnic_id)

    def _update_security_groups_port_mapping(self, session, port_id,
                                             vnic_id, current_sgids,
                                             new_sgids):

        new_sgids = new_sgids or []
        current_sgids = current_sgids or []
        # If no vnic binding is found, nothing can be done, so return
        if vnic_id is None:
            return
        deleted_sgids = set()
        added_sgids = set()
        # Find all delete security group from port binding
        for curr_sg in current_sgids:
            if curr_sg not in new_sgids:
                deleted_sgids.add(curr_sg)
        # Find all added security group from port binding
        for new_sg in new_sgids:
            if new_sg not in current_sgids:
                added_sgids.add(new_sg)

        self._delete_security_groups_port_mapping(session, vnic_id,
                                                  deleted_sgids)
        self._add_security_groups_port_mapping(session, vnic_id,
                                               added_sgids)

    def _get_port_vnic_id(self, port_index, device_id):
        # The vnic-id format which is expected by NSXv
        return '%s.%03d' % (device_id, port_index)

    def create_network(self, context, network):
        net_data = network['network']
        tenant_id = self._get_tenant_id_for_create(context, net_data)
        self._ensure_default_security_group(context, tenant_id)
        # Process the provider network extension
        provider_type = self._convert_to_transport_zones_dict(net_data)
        self._validate_provider_create(context, net_data)
        net_data['id'] = str(uuid.uuid4())

        external = net_data.get(ext_net_extn.EXTERNAL)
        backend_network = (not attr.is_attr_set(external) or
                           attr.is_attr_set(external) and not external)
        if backend_network:
            network_type = None
            if provider_type is not None:
                segment = net_data[mpnet.SEGMENTS][0]
                network_type = segment.get(pnet.NETWORK_TYPE)

            if (provider_type is None or
                network_type == c_utils.NsxVNetworkTypes.VXLAN):
                virtual_wire = {"name": net_data['id'],
                                "tenantId": "virtual wire tenant"}
                config_spec = {"virtualWireCreateSpec": virtual_wire}
                h, c = self.nsx_v.vcns.create_virtual_wire(self.vdn_scope_id,
                                                           config_spec)
                net_moref = c
            else:
                network_name = self._get_vlan_network_name(net_data)
                vlan_tag = 0
                segment = net_data[mpnet.SEGMENTS][0]
                if (segment.get(pnet.NETWORK_TYPE) ==
                    c_utils.NsxVNetworkTypes.VLAN):
                    vlan_tag = segment.get(pnet.SEGMENTATION_ID, 0)
                physical_network = segment.get(pnet.PHYSICAL_NETWORK)
                dvs_id = (physical_network if attr.is_attr_set(
                    physical_network) else self.dvs_id)
                portgroup = {'vlanId': vlan_tag,
                             'networkBindingType': 'Static',
                             'networkName': network_name,
                             'networkType': 'Isolation'}
                config_spec = {'networkSpec': portgroup}
                try:
                    h, c = self.nsx_v.vcns.create_port_group(dvs_id,
                                                             config_spec)
                    net_moref = c
                except Exception as e:
                    LOG.debug("Failed to create port group: %s",
                              e.response)
                    err_msg = (_("Physical network %s is not an existing DVS")
                               % dvs_id)
                    raise n_exc.InvalidInput(error_message=err_msg)
        try:
            # Create SpoofGuard policy for network anti-spoofing
            if cfg.CONF.nsxv.spoofguard_enabled and backend_network:
                sg_policy_id = None
                s, sg_policy_id = self.nsx_v.vcns.create_spoofguard_policy(
                    net_moref, net_data['id'], net_data[psec.PORTSECURITY])

            with context.session.begin(subtransactions=True):
                new_net = super(NsxVPluginV2, self).create_network(context,
                                                                   network)
                # Process port security extension
                self._process_network_port_security_create(
                    context, net_data, new_net)

                # DB Operations for setting the network as external
                self._process_l3_create(context, new_net, net_data)
                if (net_data.get(mpnet.SEGMENTS) and
                    isinstance(provider_type, bool)):
                    net_bindings = []
                    for tz in net_data[mpnet.SEGMENTS]:
                        network_type = tz.get(pnet.NETWORK_TYPE)
                        segmentation_id = tz.get(pnet.SEGMENTATION_ID, 0)
                        segmentation_id_set = attr.is_attr_set(segmentation_id)
                        if not segmentation_id_set:
                            segmentation_id = 0
                        physical_network = tz.get(pnet.PHYSICAL_NETWORK, '')
                        physical_net_set = attr.is_attr_set(physical_network)
                        if not physical_net_set:
                            physical_network = self.dvs_id
                        net_bindings.append(nsxv_db.add_network_binding(
                            context.session, new_net['id'],
                            network_type,
                            physical_network,
                            segmentation_id))
                    if provider_type:
                        nsx_db.set_multiprovider_network(context.session,
                                                         new_net['id'])
                    self._extend_network_dict_provider(context, new_net,
                                                       provider_type,
                                                       net_bindings)
                if backend_network:
                    # Save moref in the DB for future access
                    nsx_db.add_neutron_nsx_network_mapping(
                        context.session, new_net['id'],
                        net_moref)
                    if cfg.CONF.nsxv.spoofguard_enabled:
                        nsxv_db.map_spoofguard_policy_for_network(
                            context.session, new_net['id'], sg_policy_id)

        except Exception:
            with excutils.save_and_reraise_exception():
                # Delete the backend network
                if backend_network:
                    if cfg.CONF.nsxv.spoofguard_enabled and sg_policy_id:
                        self.nsx_v.vcns.delete_spoofguard_policy(sg_policy_id)
                    self._delete_backend_network(net_moref)
                LOG.exception(_LE('Failed to create network'))

        return new_net

    @lockutils.synchronized('vmware', 'neutron-dhcp-')
    def _cleanup_dhcp_edge_before_deletion(self, context, net_id):
        if self.metadata_proxy_handler:
            # Find if this is the last network which is bound
            # to DHCP Edge. If it is - cleanup Edge metadata config
            dhcp_edge = nsxv_db.get_dhcp_edge_network_binding(
                context.session, net_id)

            if dhcp_edge:
                edge_vnics = nsxv_db.get_edge_vnic_bindings_by_edge(
                    context.session, dhcp_edge['edge_id'])

                # If the DHCP Edge is connected to two networks:
                # the delete network and the inter-edge network, we can delete
                # the inter-edge interface
                if len(edge_vnics) == 2:
                    rtr_binding = nsxv_db.get_nsxv_router_binding_by_edge(
                        context.session, dhcp_edge['edge_id'])
                    if rtr_binding:
                        rtr_id = rtr_binding['router_id']
                        self.metadata_proxy_handler.cleanup_router_edge(rtr_id)

    @lockutils.synchronized('vmware', 'neutron-dhcp-')
    def _update_dhcp_edge_service(self, context, network_id, address_groups):
        self.edge_manager.update_dhcp_edge_service(
            context, network_id, address_groups=address_groups)

    @lockutils.synchronized('vmware', 'neutron-dhcp-')
    def _delete_dhcp_edge_service(self, context, id):
        self.edge_manager.delete_dhcp_edge_service(context, id)

    def delete_network(self, context, id):
        mappings = nsx_db.get_nsx_switch_ids(context.session, id)
        bindings = nsxv_db.get_network_bindings(context.session, id)
        if cfg.CONF.nsxv.spoofguard_enabled:
            sg_policy_id = nsxv_db.get_spoofguard_policy_id(
                context.session, id)

        # Update the DHCP edge for metadata and clean the vnic in DHCP edge
        # if there is only no other existing port besides DHCP port
        filters = {'network_id': [id]}
        subnet_ids = self.get_subnets(context, filters=filters, fields=['id'])
        dhcp_port_count = 0
        for subnet_id in subnet_ids:
            filters = {'fixed_ips': {'subnet_id': [subnet_id['id']]}}
            dhcp_port_count += self.get_ports_count(context, filters=filters)
        if (dhcp_port_count == len(subnet_ids)) and dhcp_port_count > 0:
            try:
                self._cleanup_dhcp_edge_before_deletion(context, id)
                self._delete_dhcp_edge_service(context, id)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_('Failed to delete network'))

        with context.session.begin(subtransactions=True):
            self._process_l3_delete(context, id)
            super(NsxVPluginV2, self).delete_network(context, id)

        # Do not delete a predefined port group that was attached to
        # an external network
        if (bindings and
            bindings[0].binding_type == c_utils.NsxVNetworkTypes.PORTGROUP):
            return

        # Delete the backend network if necessary. This is done after
        # the base operation as that may throw an exception in the case
        # that there are ports defined on the network.
        if mappings:
            if cfg.CONF.nsxv.spoofguard_enabled and sg_policy_id:
                self.nsx_v.vcns.delete_spoofguard_policy(sg_policy_id)
            edge_utils.check_network_in_use_at_backend(context, id)
            self._delete_backend_network(mappings[0])

    def get_network(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            # goto to the plugin DB and fetch the network
            network = self._get_network(context, id)
            # Don't do field selection here otherwise we won't be able
            # to add provider networks fields
            net_result = self._make_network_dict(network)
            self._extend_network_dict_provider(context, net_result)
        return self._fields(net_result, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        filters = filters or {}
        with context.session.begin(subtransactions=True):
            networks = (
                super(NsxVPluginV2, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            for net in networks:
                self._extend_network_dict_provider(context, net)
        return [self._fields(network, fields) for network in networks]

    def update_network(self, context, id, network):
        net_attrs = network['network']
        original_network = self.get_network(context, id)

        pnet._raise_if_updates_provider_attributes(net_attrs)
        if net_attrs.get("admin_state_up") is False:
            raise NotImplementedError(_("admin_state_up=False networks "
                                        "are not supported."))

        # PortSecurity validation checks
        # TODO(roeyc): enacapsulate validation in a method
        psec_update = (psec.PORTSECURITY in net_attrs and
                       original_network[psec.PORTSECURITY] !=
                       net_attrs[psec.PORTSECURITY])
        if psec_update and not net_attrs[psec.PORTSECURITY]:
            LOG.warning(_("Disabling port-security on network %s would "
                          "require instance in the network to have VM tools "
                          "installed in order for security-groups to "
                          "function properly."))

        with context.session.begin(subtransactions=True):
            net_res = super(NsxVPluginV2, self).update_network(context, id,
                                                               network)
            self._process_network_port_security_update(
                context, net_attrs, net_res)
            self._process_l3_update(context, net_res, net_attrs)
            self._extend_network_dict_provider(context, net_res)

        # Updating SpoofGuard policy if exists, on failure revert to network
        # old state
        if cfg.CONF.nsxv.spoofguard_enabled and psec_update:
            policy_id = nsxv_db.get_spoofguard_policy_id(context.session, id)
            net_moref = nsx_db.get_nsx_switch_ids(context.session, id)
            try:
                self.nsx_v.vcns.update_spoofguard_policy(
                    policy_id, net_moref[0], id,
                    net_attrs[psec.PORTSECURITY])
            except Exception:
                with excutils.save_and_reraise_exception():
                    revert_update = self._fields(original_network,
                                                 ['shared', psec.PORTSECURITY])
                    self._process_network_port_security_update(
                        context, revert_update, net_res)
                    super(NsxVPluginV2, self).update_network(
                        context, id, {'network': revert_update})
        return net_res

    def create_port(self, context, port):
        port_data = port['port']
        with context.session.begin(subtransactions=True):
            # First we allocate port in neutron database
            neutron_db = super(NsxVPluginV2, self).create_port(context, port)
            # Port port-security is decided by the port-security state on the
            # network it belongs to
            port_security = self._get_network_security_binding(
                context, neutron_db['network_id'])
            port_data[psec.PORTSECURITY] = port_security
            self._process_port_port_security_create(
                context, port_data, neutron_db)
            # Update fields obtained from neutron db (eg: MAC address)
            port["port"].update(neutron_db)
            has_ip = self._ip_on_port(neutron_db)

            # security group extension checks
            if has_ip:
                self._ensure_default_security_group_on_port(context, port)
            elif attr.is_attr_set(port_data.get(ext_sg.SECURITYGROUPS)):
                raise psec.PortSecurityAndIPRequiredForSecurityGroups()
            port_data[ext_sg.SECURITYGROUPS] = (
                self._get_security_groups_on_port(context, port))
            self._process_port_create_security_group(
                context, port_data, port_data[ext_sg.SECURITYGROUPS])
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         port_data)
        try:
            # Configure NSX - this should not be done in the DB transaction
            # Configure the DHCP Edge service
            self._create_dhcp_static_binding(context, neutron_db)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to create network'))
                # Revert what we have created and raise the exception
                self.delete_port(context, port_data['id'])
        return port_data

    def update_port(self, context, id, port):
        port_data = port['port']
        original_port = super(NsxVPluginV2, self).get_port(context, id)
        is_compute_port = self._is_compute_port(original_port)
        device_id = original_port['device_id']
        has_port_security = (cfg.CONF.nsxv.spoofguard_enabled and
                             original_port[psec.PORTSECURITY])

        # TODO(roeyc): create a method '_process_vnic_index_update' from the
        # following code block
        # Process update for vnic-index
        vnic_idx = port_data.get(ext_vnic_idx.VNIC_INDEX)
        # Only set the vnic index for a compute VM
        if attr.is_attr_set(vnic_idx) and is_compute_port:
            # Update database only if vnic index was changed
            if original_port.get(ext_vnic_idx.VNIC_INDEX) != vnic_idx:
                self._set_port_vnic_index_mapping(
                    context, id, device_id, vnic_idx)
            vnic_id = self._get_port_vnic_id(vnic_idx, device_id)
            self._add_security_groups_port_mapping(
                context.session, vnic_id, original_port['security_groups'])
            if has_port_security:
                self._update_vnic_assigned_addresses(
                    context.session, original_port, vnic_id)
            else:
                LOG.warning(_("port-security is disabled on port %(id)s, "
                              "VM tools must be installed on instance "
                              "%(device_id)s for security-groups to function "
                              "properly "),
                            {'id': id,
                             'device_id': original_port['device_id']})

        delete_security_groups = self._check_update_deletes_security_groups(
            port)
        has_security_groups = self._check_update_has_security_groups(port)
        comp_owner_update = ('device_owner' in port_data and
                             port_data['device_owner'].startswith('compute:'))

        with context.session.begin(subtransactions=True):
            ret_port = super(NsxVPluginV2, self).update_port(
                context, id, port)
            if psec.PORTSECURITY in port['port']:
                raise NotImplementedError()
            # copy values over - except fixed_ips as
            # they've already been processed
            updates_fixed_ips = port['port'].pop('fixed_ips', [])
            ret_port.update(port['port'])
            has_ip = self._ip_on_port(ret_port)

            # checks that if update adds/modify security groups,
            # then port has ip
            if not has_ip:
                if has_security_groups:
                    raise psec.PortSecurityAndIPRequiredForSecurityGroups()
                security_groups = (
                    super(NsxVPluginV2,
                          self)._get_port_security_group_bindings(
                              context, {'port_id': [id]})
                )
                if security_groups and not delete_security_groups:
                    raise psec.PortSecurityAndIPRequiredForSecurityGroups()

            if delete_security_groups or has_security_groups:
                # delete the port binding and read it with the new rules.
                self._delete_port_security_group_bindings(context, id)
                new_sgids = self._get_security_groups_on_port(context, port)
                self._process_port_create_security_group(context, ret_port,
                                                         new_sgids)

            LOG.debug("Updating port: %s", port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         ret_port)

        if comp_owner_update:
            # Create dhcp bindings, the port is now owned by an instance
            self._create_dhcp_static_binding(context, ret_port)

        # Processing compute port update
        vnic_idx = original_port.get(ext_vnic_idx.VNIC_INDEX)
        if attr.is_attr_set(vnic_idx) and is_compute_port:
            vnic_id = self._get_port_vnic_id(vnic_idx, device_id)
            curr_sgids = original_port.get(ext_sg.SECURITYGROUPS)
            if ret_port['device_id'] != device_id:
                # Update change device_id - remove port-vnic assosiation and
                # delete security-groups memberships for the vnic
                self._delete_security_groups_port_mapping(
                    context.session, vnic_id, curr_sgids)
                if cfg.CONF.nsxv.spoofguard_enabled:
                    self._remove_vnic_from_spoofguard_policy(
                        context.session, port['network_id'], vnic_id)
                self._delete_port_vnic_index_mapping(context, id)
            else:
                # Update vnic with the newest approved IP addresses
                if has_port_security and updates_fixed_ips:
                    self._update_vnic_assigned_addresses(
                        context.session, ret_port, vnic_id)
                if not has_port_security and has_security_groups:
                    LOG.warning(_("port-security is disabled on port %(id)s, "
                                  "VM tools must be installed on instance "
                                  "%(device_id)s for security-groups to "
                                  "function properly "),
                                {'id': id,
                                 'device_id': original_port['device_id']})
                if delete_security_groups or has_security_groups:
                    # Update security-groups,
                    # calculate differences and update vnic membership
                    # accordingly.
                    self._update_security_groups_port_mapping(
                        context.session, id, vnic_id, curr_sgids, new_sgids)

        return ret_port

    def delete_port(self, context, id, l3_port_check=True,
                    nw_gw_port_check=True):
        """Deletes a port on a specified Virtual Network.

        If the port contains a remote interface attachment, the remote
        interface is first un-plugged and then the port is deleted.

        :returns: None
        :raises: exception.PortInUse
        :raises: exception.PortNotFound
        :raises: exception.NetworkNotFound
        """
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        neutron_db_port = self.get_port(context, id)

        # If this port is attached to a device, remove the corresponding vnic
        # from all NSXv Security-Groups and the spoofguard policy
        port_index = neutron_db_port.get(ext_vnic_idx.VNIC_INDEX)
        if attr.is_attr_set(port_index):
            vnic_id = self._get_port_vnic_id(port_index,
                                             neutron_db_port['device_id'])
            sgids = neutron_db_port.get(ext_sg.SECURITYGROUPS)
            self._delete_security_groups_port_mapping(
                context.session, vnic_id, sgids)
            if (cfg.CONF.nsxv.spoofguard_enabled and
                neutron_db_port[psec.PORTSECURITY]):
                self._remove_vnic_from_spoofguard_policy(
                    context.session, neutron_db_port['network_id'], vnic_id)

        self.disassociate_floatingips(context, id)
        with context.session.begin(subtransactions=True):
            super(NsxVPluginV2, self).delete_port(context, id)

        self._delete_dhcp_static_binding(context, neutron_db_port)

    def delete_subnet(self, context, id):
        subnet = self._get_subnet(context, id)
        filters = {'fixed_ips': {'subnet_id': [id]}}
        ports = self.get_ports(context, filters=filters)

        with context.session.begin(subtransactions=True):
            super(NsxVPluginV2, self).delete_subnet(context, id)

        if subnet['enable_dhcp']:
            # There is only DHCP port available
            if len(ports) == 1:
                port = ports.pop()
                self._delete_port(context, port['id'])

            # Delete the DHCP edge service
            network_id = subnet['network_id']
            filters = {'network_id': [network_id]}
            remaining_subnets = self.get_subnets(context, filters=filters)
            if len(remaining_subnets) == 0:
                self._cleanup_dhcp_edge_before_deletion(context, network_id)
                LOG.debug("Delete the DHCP Edge for network %s", network_id)
                self._delete_dhcp_edge_service(context, network_id)
            else:
                # Update address group and delete the DHCP port only
                address_groups = self._create_network_dhcp_address_group(
                    context, network_id)
                self._update_dhcp_edge_service(context, network_id,
                                               address_groups)

    def create_subnet(self, context, subnet):
        """Create subnet on nsx_v provider network.

        If the subnet is created with DHCP enabled, and the network which
        the subnet is attached is not bound to an DHCP Edge, nsx_v will
        create the Edge and make sure the network is bound to the Edge
        """
        if subnet['subnet']['enable_dhcp']:
            filters = {'id': [subnet['subnet']['network_id']],
                       'router:external': [True]}
            nets = self.get_networks(context, filters=filters)
            if len(nets) > 0:
                err_msg = _("Can not enable DHCP on external network")
                raise n_exc.InvalidInput(error_message=err_msg)
            if netaddr.IPNetwork(subnet['subnet']['cidr']) == 6:
                err_msg = _("No support for DHCP for IPv6")
                raise n_exc.InvalidInput(error_message=err_msg)

        with context.session.begin(subtransactions=True):
            s = super(NsxVPluginV2, self).create_subnet(context, subnet)

        if s['enable_dhcp']:
            try:
                self._update_dhcp_service_with_subnet(context, s)
            except Exception:
                with excutils.save_and_reraise_exception():
                    self.delete_subnet(context, s['id'])
        return s

    @lockutils.synchronized('vmware', 'neutron-dhcp-')
    def _get_conflict_network_ids_by_overlapping(self, context, subnets):
        conflict_network_ids = []
        subnet_ids = [subnet['id'] for subnet in subnets]
        conflict_set = netaddr.IPSet([subnet['cidr'] for subnet in subnets])
        subnets_qry = context.session.query(models_v2.Subnet).all()
        subnets_all = [subnet for subnet in subnets_qry
                       if subnet['id'] not in subnet_ids]
        for subnet in subnets_all:
            cidr_set = netaddr.IPSet([subnet['cidr']])
            if cidr_set & conflict_set:
                conflict_network_ids.append(subnet['network_id'])
        return conflict_network_ids

    def _update_dhcp_service_with_subnet(self, context, subnet):
        network_id = subnet['network_id']
        # Create DHCP port
        port_dict = {'name': '',
                     'admin_state_up': True,
                     'network_id': network_id,
                     'tenant_id': subnet['tenant_id'],
                     'fixed_ips': [{'subnet_id': subnet['id']}],
                     'device_owner': constants.DEVICE_OWNER_DHCP,
                     'device_id': '',
                     'mac_address': attr.ATTR_NOT_SPECIFIED
                     }
        self.create_port(context, {'port': port_dict})
        # The DHCP for network with different physical network can not be used
        # The flat network should be located in different DHCP
        conflicting_networks = []
        network_ids = self.get_networks(neutron_context.get_admin_context(),
                                        fields=['id'])
        phy_net = nsxv_db.get_network_bindings(context.session, network_id)
        if phy_net:
            binding_type = phy_net[0]['binding_type']
            phy_uuid = phy_net[0]['phy_uuid']
            for net_id in network_ids:
                p_net = nsxv_db.get_network_bindings(context.session,
                                                    net_id['id'])
                if (p_net and binding_type == p_net[0]['binding_type']
                    and binding_type == c_utils.NsxVNetworkTypes.FLAT):
                    conflicting_networks.append(net_id['id'])
                elif (p_net and phy_uuid != p_net[0]['phy_uuid']):
                    conflicting_networks.append(net_id['id'])
        # Query all networks with overlap subnet
        if cfg.CONF.allow_overlapping_ips:
            conflicting_networks.extend(
                self._get_conflict_network_ids_by_overlapping(
                    context, [subnet]))

        conflicting_networks = list(set(conflicting_networks))

        try:
            resource_id = self.edge_manager.create_dhcp_edge_service(
                context, network_id, conflicting_networks)
            # Create all dhcp ports within the network
            address_groups = self._create_network_dhcp_address_group(
                context, network_id)
            self.edge_manager.update_dhcp_edge_service(
                context, network_id, address_groups=address_groups)

            if resource_id and self.metadata_proxy_handler:
                self.metadata_proxy_handler.configure_router_edge(resource_id)
                fw_rules = {
                    'firewall_rule_list':
                    self.metadata_proxy_handler.get_router_fw_rules()}
                edge_utils.update_firewall(
                    self.nsx_v, context, resource_id, fw_rules,
                    allow_external=False)

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update DHCP for subnet %s"),
                              subnet['id'])

    def _create_network_dhcp_address_group(self, context, network_id):
        """Create dhcp address group for subnets attached to the network."""

        filters = {'network_id': [network_id],
                   'device_owner': [constants.DEVICE_OWNER_DHCP]}
        ports = self.get_ports(context, filters=filters)

        filters = {'network_id': [network_id], 'enable_dhcp': [True]}
        subnets = self.get_subnets(context, filters=filters)

        address_groups = []
        for subnet in subnets:
            address_group = {}
            net = netaddr.IPNetwork(subnet['cidr'])
            address_group['subnetPrefixLength'] = str(net.prefixlen)
            for port in ports:
                fixed_ips = port['fixed_ips']
                for fip in fixed_ips:
                    s_id = fip['subnet_id']
                    ip_addr = fip['ip_address']
                    if s_id == subnet['id'] and self._is_valid_ip(ip_addr):
                        address_group['primaryAddress'] = ip_addr
                        break
            address_groups.append(address_group)
        LOG.debug("Update the DHCP address group to %s", address_groups)
        return address_groups

    def _create_static_binding(self, context, port):
        """Create the DHCP Edge static binding configuration

        <staticBinding>
            <macAddress></macAddress>
            <ipAddress></ipAddress>
            <hostname></hostname> <!--disallow duplicate-->
            <defaultGateway></defaultGateway> <!--optional.-->
            <primaryNameServer></primaryNameServer> <!--optional-->
            <secondaryNameServer></secondaryNameServer> <!--optional-->
        </staticBinding>
        """
        static_bindings = []
        static_config = {}
        static_config['macAddress'] = port['mac_address']
        static_config['hostname'] = port['id']

        for fixed_ip in port['fixed_ips']:
            static_config['ipAddress'] = fixed_ip['ip_address']
            # Query the subnet to get gateway and DNS
            try:
                subnet_id = fixed_ip['subnet_id']
                subnet = self._get_subnet(context, subnet_id)
            except n_exc.SubnetNotFound:
                LOG.debug("No related subnet for port %s", port['id'])
                continue
            # Set gateway for static binding
            static_config['defaultGateway'] = subnet['gateway_ip']
            # set primary and secondary dns
            name_servers = [dns['address']
                            for dns in subnet['dns_nameservers']]
            if len(name_servers) == 1:
                static_config['primaryNameServer'] = name_servers[0]
            elif len(name_servers) >= 2:
                static_config['primaryNameServer'] = name_servers[0]
                static_config['secondaryNameServer'] = name_servers[1]

            static_bindings.append(static_config)
        return static_bindings

    def _extract_external_gw(self, context, router, is_extract=True):
        r = router['router']
        gw_info = None
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

    def create_router(self, context, router, allow_metadata=True):
        # First extract the gateway info in case of updating
        # gateway before edge is deployed.
        # TODO(berlin): admin_state_up and routes update
        if router['router'].get('admin_state_up') is False:
            LOG.warning(_LW("admin_state_up=False router is not supported."))
        gw_info = self._extract_external_gw(context, router)
        lrouter = super(NsxVPluginV2, self).create_router(context, router)
        r = router['router']
        self._decide_router_type(context, r)
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, lrouter['id'])
            self._process_nsx_router_create(context, router_db, r)
        router_driver = self._get_router_driver(context, router_db)
        router_driver.create_router(
            context, lrouter,
            allow_metadata=(allow_metadata and self.metadata_proxy_handler))
        if gw_info is not None:
            router_driver._update_router_gw_info(
                context, lrouter['id'], gw_info)
        return self.get_router(context, lrouter['id'])

    def update_router(self, context, router_id, router):
        # TODO(berlin): admin_state_up update
        if router['router'].get('admin_state_up') is False:
            LOG.warning(_LW("admin_state_up=False router is not supported."))
        router_driver = self._find_router_driver(context, router_id)
        return router_driver.update_router(context, router_id, router)

    def _check_router_in_use(self, context, router_id):
        with context.session.begin(subtransactions=True):
            # Ensure that the router is not used
            router_filter = {'router_id': [router_id]}
            fips = self.get_floatingips_count(context.elevated(),
                                              filters=router_filter)
            if fips:
                raise l3.RouterInUse(router_id=router_id)

            device_filter = {'device_id': [router_id],
                             'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF]}
            ports = self.get_ports_count(context.elevated(),
                                         filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=router_id)

    def delete_router(self, context, id):
        self._check_router_in_use(context, id)
        router_driver = self._find_router_driver(context, id)
        router_driver.delete_router(context, id)
        super(NsxVPluginV2, self).delete_router(context, id)

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

    def _add_network_info_for_routes(self, context, routes, ports):
        for route in routes:
            for port in ports:
                for ip in port['fixed_ips']:
                    subnet = self.get_subnet(context, ip['subnet_id'])
                    if netaddr.all_matching_cidrs(
                        route['nexthop'], [subnet['cidr']]):
                        net = self.get_network(context, subnet['network_id'])
                        route['network_id'] = net['id']
                        if net.get(ext_net_extn.EXTERNAL):
                            route['external'] = True

    def _prepare_edge_extra_routes(self, context, router_id):
        routes = self._get_extra_routes_by_router_id(context, router_id)
        filters = {'device_id': [router_id]}
        ports = self.get_ports(context, filters)
        self._add_network_info_for_routes(context, routes, ports)
        return routes

    def _update_routes(self, context, router_id, nexthop):
        routes = self._prepare_edge_extra_routes(context, router_id)
        edge_utils.update_routes(self.nsx_v, context, router_id,
                                 routes, nexthop)

    def _update_router_gw_info(self, context, router_id, info):
        router_driver = self._find_router_driver(context, router_id)
        router_driver._update_router_gw_info(context, router_id, info)

    def _get_router_interface_ports_by_network(
        self, context, router_id, network_id):
        port_filters = {'device_id': [router_id],
                        'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [network_id]}
        return self.get_ports(context, filters=port_filters)

    def _get_address_groups(self, context, router_id, network_id):
        address_groups = []
        ports = self._get_router_interface_ports_by_network(
            context, router_id, network_id)
        for port in ports:
            address_group = {}
            gateway_ip = port['fixed_ips'][0]['ip_address']
            subnet = self.get_subnet(context,
                                     port['fixed_ips'][0]['subnet_id'])
            prefixlen = str(netaddr.IPNetwork(subnet['cidr']).prefixlen)
            address_group['primaryAddress'] = gateway_ip
            address_group['subnetPrefixLength'] = prefixlen
            address_groups.append(address_group)
        return address_groups

    def _get_port_by_device_id(self, context, device_id, device_owner):
        """Retrieve ports associated with a specific device id.

        Used for retrieving all neutron ports attached to a given router.
        """
        port_qry = context.session.query(models_v2.Port)
        return port_qry.filter_by(
            device_id=device_id,
            device_owner=device_owner,).all()

    def _find_router_subnets_cidrs(self, context, router_id):
        """Retrieve subnets attached to the specified router."""
        ports = self._get_port_by_device_id(context, router_id,
                                            l3_db.DEVICE_OWNER_ROUTER_INTF)
        # No need to check for overlapping CIDRs
        cidrs = []
        for port in ports:
            for ip in port.get('fixed_ips', []):
                subnet_qry = context.session.query(models_v2.Subnet)
                subnet = subnet_qry.filter_by(id=ip.subnet_id).one()
                cidrs.append(subnet.cidr)
        return sorted(cidrs)

    def _get_nat_rules(self, context, router):
        fip_qry = context.session.query(l3_db.FloatingIP)
        fip_db = fip_qry.filter_by(router_id=router['id']).all()

        snat = []

        dnat = [{'dst': fip.floating_ip_address,
                 'translated': fip.fixed_ip_address}
                for fip in fip_db if fip.fixed_port_id]

        gw_port = router.gw_port
        if gw_port and router.enable_snat:
            snat_ip = gw_port['fixed_ips'][0]['ip_address']
            subnets = self._find_router_subnets_cidrs(context.elevated(),
                                                      router['id'])
            for subnet in subnets:
                snat.append({
                    'src': subnet,
                    'translated': snat_ip
                })
        return (snat, dnat)

    def _update_nat_rules(self, context, router, router_id=None):
        snat, dnat = self._get_nat_rules(context, router)
        if not router_id:
            router_id = router['id']
        edge_utils.update_nat_rules(
            self.nsx_v, context, router_id, snat, dnat)

    def _check_intf_number_of_router(self, context, router_id):
        intf_ports = self._get_port_by_device_id(
            context, router_id, l3_db.DEVICE_OWNER_ROUTER_INTF)
        if len(intf_ports) >= (vcns_const.MAX_INTF_NUM):
            err_msg = _("interfaces number on router: %(router_id)s "
                        "has reached the maximum %(number)d which NSXv can "
                        "support. Please use vdr if you want to add unlimited "
                        "interfaces") % {'router_id': router_id,
                                         'number': vcns_const.MAX_INTF_NUM}
            raise nsx_exc.ServiceOverQuota(overs="router-interface-add",
                                           err_msg=err_msg)

    def add_router_interface(self, context, router_id, interface_info):
        router_driver = self._find_router_driver(context, router_id)
        return router_driver.add_router_interface(
            context, router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        router_driver = self._find_router_driver(context, router_id)
        return router_driver.remove_router_interface(
            context, router_id, interface_info)

    def _get_floatingips_by_router(self, context, router_id):
        fip_qry = context.session.query(l3_db.FloatingIP)
        fip_db = fip_qry.filter_by(router_id=router_id).all()
        return [fip.floating_ip_address
                for fip in fip_db if fip.fixed_port_id]

    def _update_external_interface(self, context, router, router_id=None):
        ext_net_id = router.gw_port_id and router.gw_port.network_id
        addr, mask, nexthop = self._get_external_attachment_info(
            context, router)
        secondary = self._get_floatingips_by_router(context, router['id'])
        if not router_id:
            router_id = router['id']
        edge_utils.update_external_interface(
            self.nsx_v, context, router_id, ext_net_id,
            addr, mask, secondary)

    def _set_floatingip_status(self, context, floatingip_db, status=None):
        if not status:
            status = (constants.FLOATINGIP_STATUS_ACTIVE
                      if floatingip_db.get('router_id')
                      else constants.FLOATINGIP_STATUS_DOWN)
        if floatingip_db['status'] != status:
            floatingip_db['status'] = status
            self.update_floatingip_status(context, floatingip_db['id'], status)

    def _update_edge_router(self, context, router_id):
        router_driver = self._find_router_driver(context, router_id)
        router_driver._update_edge_router(context, router_id)

    def create_floatingip(self, context, floatingip):
        fip_db = super(NsxVPluginV2, self).create_floatingip(
            context, floatingip)
        router_id = fip_db['router_id']
        if router_id:
            try:
                self._update_edge_router(context, router_id)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Failed to update edge router"))
                    super(NsxVPluginV2, self).delete_floatingip(context,
                                                                fip_db['id'])
        self._set_floatingip_status(context, fip_db)
        return fip_db

    def update_floatingip(self, context, id, floatingip):
        old_fip = self._get_floatingip(context, id)
        old_router_id = old_fip.router_id
        old_port_id = old_fip.fixed_port_id
        fip_db = super(NsxVPluginV2, self).update_floatingip(
            context, id, floatingip)
        router_id = fip_db.get('router_id')
        try:
            # Update old router's nat rules if old_router_id is not None.
            if old_router_id:
                self._update_edge_router(context, old_router_id)
            # Update current router's nat rules if router_id is not None.
            if router_id:
                self._update_edge_router(context, router_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update edge router"))
                super(NsxVPluginV2, self).update_floatingip(
                    context, id, {'floatingip': {'port_id': old_port_id}})
        self._set_floatingip_status(context, fip_db)
        return fip_db

    def delete_floatingip(self, context, id):
        fip_db = self._get_floatingip(context, id)
        router_id = None
        if fip_db.fixed_port_id:
            router_id = fip_db.router_id
        super(NsxVPluginV2, self).delete_floatingip(context, id)
        if router_id:
            self._update_edge_router(context, router_id)

    def disassociate_floatingips(self, context, port_id):
        router_id = None
        try:
            fip_qry = context.session.query(l3_db.FloatingIP)
            fip_db = fip_qry.filter_by(fixed_port_id=port_id)
            for fip in fip_db:
                if fip.router_id:
                    router_id = fip.router_id
                    break
        except sa_exc.NoResultFound:
            router_id = None
        super(NsxVPluginV2, self).disassociate_floatingips(context, port_id)
        if router_id:
            self._update_edge_router(context, router_id)

    def _update_subnets_and_dnat_firewall(self, context, router,
                                          router_id=None, allow_external=True):
        fake_fw_rules = []
        if not router_id:
            router_id = router['id']
        subnet_cidrs = self._find_router_subnets_cidrs(context, router['id'])
        if subnet_cidrs:
            # Fake fw rule to open subnets firewall flows
            fake_subnet_fw_rule = {
                'action': 'allow',
                'enabled': True,
                'source_ip_address': sorted(subnet_cidrs),
                'destination_ip_address': sorted(subnet_cidrs)}
            fake_fw_rules.append(fake_subnet_fw_rule)
        _, dnat_rules = self._get_nat_rules(context, router)

        # If metadata service is enabled, block access to inter-edge network
        if self.metadata_proxy_handler:
            fake_fw_rules += self.metadata_proxy_handler.get_router_fw_rules()

        dnat_cidrs = [rule['dst'] for rule in dnat_rules]
        if dnat_cidrs:
            # Fake fw rule to open dnat firewall flows
            fake_dnat_fw_rule = {
                'action': 'allow',
                'enabled': True,
                'destination_ip_address': sorted(dnat_cidrs)}
            fake_fw_rules.append(fake_dnat_fw_rule)
        # TODO(berlin): Add fw rules if fw service is supported
        fake_fw = {'firewall_rule_list': fake_fw_rules}
        edge_utils.update_firewall(self.nsx_v, context, router_id, fake_fw,
                                   allow_external=allow_external)

    # Security group handling section #
    def _delete_security_group(self, nsx_sg_id):
        """Helper method to delete nsx security group."""
        if nsx_sg_id is not None:
            h, c = self.nsx_v.vcns.delete_security_group(nsx_sg_id)

    def _delete_section(self, section_uri):
        """Helper method to delete nsx rule section."""
        if section_uri is not None:
            h, c = self.nsx_v.vcns.delete_section(section_uri)

    def _get_section_uri(self, session, security_group_id, type):
        mapping = nsxv_db.get_nsx_section(session, security_group_id)
        if mapping is not None:
            if type == 'ip':
                return mapping['ip_section_id']
            else:
                None

    def create_security_group(self, context, security_group,
                              default_sg=False):
        """Create a security group."""
        sg_data = security_group["security_group"]
        tenant_id = self._get_tenant_id_for_create(context, sg_data)
        if not default_sg:
            self._ensure_default_security_group(context, tenant_id)

        sg_data["id"] = str(uuid.uuid4())

        nsx_sg_name = self._get_name(sg_data['id'],
                                     sg_data['name'])
        security_group_config = {"name": nsx_sg_name,
                                 "description": sg_data["name"]}
        security_group_dict = {"securitygroup": security_group_config}

        # Create the nsx security group container
        h, c = self.nsx_v.vcns.create_security_group(security_group_dict)
        nsx_sg_id = c
        section_uri = None
        try:
            with context.session.begin(subtransactions=True):
                new_security_group = super(
                    NsxVPluginV2, self).create_security_group(
                        context, security_group, default_sg)

                # Save moref in the DB for future access
                nsx_db.add_neutron_nsx_security_group_mapping(
                    context.session, new_security_group['id'],
                    nsx_sg_id)

                # (shadabs): For now only IPv4 rules are processed while group
                # creation. This is to avoid duplicate rules since NSXv manager
                # does not distinguish between IPv4 and IPv6 rules. Remove the
                # TODO(shadabs): comment once NSXv provides API to define ether
                # type.
                nsx_rules = []
                rules = new_security_group['security_group_rules']
                for rule in rules:
                    _r, _n = self._create_nsx_rule(context, rule, nsx_sg_id)
                    nsx_rules.append(_r)

                section_name = ('SG Section: %(name)s (%(id)s)'
                                % new_security_group)
                section = self.nsx_sg_utils.get_section_with_rules(
                    section_name, nsx_rules)

                # Execute REST API for creating the section
                h, c = self.nsx_v.vcns.create_section(
                    'ip', self.nsx_sg_utils.to_xml_string(section))

                # Save ip section uri in DB for furture access
                section_uri = h['location']
                nsxv_db.add_neutron_nsx_section_mapping(
                    context.session, new_security_group['id'],
                    section_uri)

                # Parse the rule id pairs and save in db
                rule_pairs = self.nsx_sg_utils.get_rule_id_pair_from_section(c)
                for pair in rule_pairs:
                    _nsx_id = pair.get('nsx_id')  # nsx_rule_id
                    _neutron_id = pair.get('neutron_id')  # neutron_rule_id
                    # Save nsx rule id in the DB for future access
                    LOG.debug('rules %s-%s', _nsx_id, _neutron_id)
                    nsxv_db.add_neutron_nsx_rule_mapping(
                        context.session, _neutron_id, _nsx_id)

                # Add this Security Group to the Security Groups container
                self._add_member_to_security_group(self.sg_container_id,
                                                   nsx_sg_id)

        except Exception:
            with excutils.save_and_reraise_exception():
                # Delete the nsx rule section
                self._delete_section(section_uri)
                # Delete the nsx security group container
                self._delete_security_group(nsx_sg_id)
                LOG.exception(_LE('Failed to create security group'))

        return new_security_group

    def delete_security_group(self, context, id):
        """Delete a security group."""
        try:
            with context.session.begin(subtransactions=True):
                security_group = super(
                    NsxVPluginV2, self).get_security_group(context, id)

                # Find nsx rule sections
                section_mapping = nsxv_db.get_nsx_section(
                    context.session, security_group['id'])

                # Find nsx security group
                nsx_sg_id = nsx_db.get_nsx_security_group_id(
                    context.session, security_group['id'])

                # Delete neutron security group
                super(NsxVPluginV2, self).delete_security_group(
                    context, id)

                # Delete nsx rule sections
                self._delete_section(section_mapping['ip_section_id'])

                # Delete nsx security group
                self._delete_security_group(nsx_sg_id)

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to delete security group'))

    def _create_nsx_rule(self, context, rule, nsx_sg_id):
        src = None
        dest = None
        port = None
        protocol = None
        icmptype = None
        icmpcode = None
        flags = {}

        if nsx_sg_id is None:
            # Find nsx security group for neutron security group
            nsx_sg_id = nsx_db.get_nsx_security_group_id(
                context.session, rule['security_group_id'])
            if nsx_sg_id is None:
                # TODO(shadabs): raise an exception here
                LOG.warning(_LW("NSX security group not found for %s"),
                            rule['security_group_id'])

        # Find the remote nsx security group id, if given in rule
        remote_nsx_sg_id = nsx_db.get_nsx_security_group_id(
            context.session, rule['remote_group_id'])

        # Get source and destination containers from rule
        if rule['direction'] == 'ingress':
            src = self.nsx_sg_utils.get_remote_container(
                remote_nsx_sg_id, rule['remote_ip_prefix'])
            dest = self.nsx_sg_utils.get_container(nsx_sg_id)
            flags['direction'] = 'in'
        else:
            dest = self.nsx_sg_utils.get_remote_container(
                remote_nsx_sg_id, rule['remote_ip_prefix'])
            src = self.nsx_sg_utils.get_container(nsx_sg_id)
            flags['direction'] = 'out'

        protocol = rule.get('protocol')
        if rule['port_range_min'] is not None:
            if protocol == '1' or protocol == 'icmp':
                icmptype = str(rule['port_range_min'])
                if rule['port_range_max'] is not None:
                    icmpcode = str(rule['port_range_max'])
            else:
                port = str(rule['port_range_min'])
                if rule['port_range_max'] != rule['port_range_min']:
                    port = port + '-' + str(rule['port_range_max'])

        # Get the neutron rule id to use as name in nsxv rule
        name = rule.get('id')
        services = [(protocol, port, icmptype, icmpcode)] if protocol else []

        flags['ethertype'] = rule.get('ethertype')
        # Add rule in nsx rule section
        nsx_rule = self.nsx_sg_utils.get_rule_config(
            applied_to_id=nsx_sg_id,
            name=name,
            source=src,
            destination=dest,
            services=services,
            flags=flags)
        return nsx_rule, nsx_sg_id

    def create_security_group_rule(self, context, security_group_rule):
        """Create a single security group rule."""
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rule):
        """Create security group rules.

        :param security_group_rule: list of rules to create
        """
        try:
            with context.session.begin(subtransactions=True):
                # Validate and store rule in neutron DB
                new_rule_list = super(
                    NsxVPluginV2, self).create_security_group_rule_bulk_native(
                        context, security_group_rule)
                ruleids = set()
                nsx_sg_id = None
                section_uri = None
                section = None
                _h = None
                for rule in new_rule_list:
                    # Find nsx rule section for neutron security group
                    if section_uri is None:
                        section_uri = self._get_section_uri(
                            context.session, rule['security_group_id'], 'ip')
                        if section_uri is None:
                            # TODO(shadabs): raise an exception here
                            LOG.warning(_LW("NSX rule section not found for "
                                            "%s"), rule['security_group_id'])

                    # Parse neutron rule and get nsx rule xml
                    _r, _n = self._create_nsx_rule(context, rule, nsx_sg_id)
                    nsx_rule = _r
                    nsx_sg_id = _n
                    if section is None:
                        _h, _c = self.nsx_v.vcns.get_section(section_uri)
                        section = self.nsx_sg_utils.parse_section(_c)

                    # Insert rule in nsx section
                    self.nsx_sg_utils.insert_rule_in_section(section, nsx_rule)
                    ruleids.add(rule['id'])

                # Update the section
                h, c = self.nsx_v.vcns.update_section(
                    section_uri, self.nsx_sg_utils.to_xml_string(section), _h)

                # Parse the rule id pairs and save in db
                rule_pairs = self.nsx_sg_utils.get_rule_id_pair_from_section(c)
                for pair in rule_pairs:
                    _nsx_id = pair.get('nsx_id')  # nsx_rule_id
                    _neutron_id = pair.get('neutron_id')  # neutron_rule_id
                    # Save nsx rule id in the DB for future access
                    if _neutron_id in ruleids:
                        nsxv_db.add_neutron_nsx_rule_mapping(
                            context.session, _neutron_id, _nsx_id)

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to update security group rule'))

        return new_rule_list

    def delete_security_group_rule(self, context, sgrid):
        """Delete a security group rule."""
        try:
            with context.session.begin(subtransactions=True):
                # Get security group rule from DB
                security_group_rule = super(
                    NsxVPluginV2, self).get_security_group_rule(
                        context, sgrid)
                if not security_group_rule:
                    raise ext_sg.SecurityGroupRuleNotFound(id=sgrid)

                # Get the nsx rule from neutron DB
                nsx_rule_id = nsxv_db.get_nsx_rule_id(
                    context.session, security_group_rule['id'])
                section_uri = self._get_section_uri(
                    context.session, security_group_rule['security_group_id'],
                    'ip')

                # Delete the rule from neutron DB
                ret = super(NsxVPluginV2, self).delete_security_group_rule(
                    context, sgrid)

                # Delete the nsx rule
                if nsx_rule_id is not None and section_uri is not None:
                    h, c = self.nsx_v.vcns.remove_rule_from_section(
                        section_uri, nsx_rule_id)

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Failed to delete security group rule'))

        return ret

    def _remove_vnic_from_spoofguard_policy(self, session, net_id, vnic_id):
        policy_id = nsxv_db.get_spoofguard_policy_id(session, net_id)
        try:
            self.nsx_v.vcns.inactivate_vnic_assigned_addresses(policy_id,
                                                               vnic_id)
        except Exception:
            LOG.debug("Failed to remove vnic %(vnic_id)s "
                      "from spoofguard policy %(policy_id)s",
                      {'vnic_id': vnic_id,
                       'policy_id': policy_id})

    def _update_vnic_assigned_addresses(self, session, port, vnic_id):
        sg_policy_id = nsxv_db.get_spoofguard_policy_id(
            session, port['network_id'])
        mac_addr = port['mac_address']
        approved_addrs = [addr['ip_address'] for addr in port['fixed_ips']]
        self.nsx_v.vcns.approve_assigned_addresses(
            sg_policy_id, vnic_id, mac_addr, approved_addrs)
        self.nsx_v.vcns.publish_assigned_addresses(sg_policy_id)

    def _is_compute_port(self, port):
        try:
            if (port['device_id'] and uuidutils.is_uuid_like(port['device_id'])
                and port['device_owner'].startswith('compute:')):
                return True
        except (KeyError, AttributeError):
            pass
        return False

    def _is_valid_ip(self, ip_addr):
        return netaddr.valid_ipv4(ip_addr) or netaddr.valid_ipv6(ip_addr)

    def _ensure_lock_operations(self):
        try:
            self.nsx_v.vcns.edges_lock_operation()
        except Exception:
            LOG.info(_("Unable to set manager lock operation"))

    def _validate_config(self):
        if not self.nsx_v.vcns.validate_dvs(cfg.CONF.nsxv.dvs_id):
            error = _("configured dvs_id not found")
            raise nsx_exc.NsxPluginException(err_msg=error)

        if not self.nsx_v.vcns.validate_datacenter_moid(
                cfg.CONF.nsxv.datacenter_moid):
            error = _("configured datacenter_moid not found")
            raise nsx_exc.NsxPluginException(err_msg=error)

        if not self.nsx_v.vcns.validate_network(
                cfg.CONF.nsxv.external_network):
            error = _("configured external_network not found")
            raise nsx_exc.NsxPluginException(err_msg=error)

        if not self.nsx_v.vcns.validate_vdn_scope(cfg.CONF.nsxv.vdn_scope_id):
            error = _("configured vdn_scope_id not found")
            raise nsx_exc.NsxPluginException(err_msg=error)

        if (cfg.CONF.nsxv.mgt_net_moid
            and not self.nsx_v.vcns.validate_network(
                cfg.CONF.nsxv.mgt_net_moid)):
            error = _("configured mgt_net_moid not found")
            raise nsx_exc.NsxPluginException(err_msg=error)
