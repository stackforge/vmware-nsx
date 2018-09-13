# Copyright 2017 VMware, Inc.
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


from oslo_log import log as logging

from neutron.db import _resource_extend as resource_extend
from neutron.db import address_scope_db
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron.db import l3_attrs_db
from neutron.db import l3_db
from neutron.db import models_v2
from neutron_lib.api.definitions import address_scope as ext_address_scope
from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api import validators
from neutron_lib.api.validators import availability_zone as az_validator
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts
from neutron_lib.utils import net

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.extensions import maclearning as mac_ext
from vmware_nsx.services.qos.common import utils as qos_com_utils
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class NsxPluginBase(db_base_plugin_v2.NeutronDbPluginV2,
                    address_scope_db.AddressScopeDbMixin):
    """Common methods for NSX-V and NSX-V3 plugins"""

    @property
    def plugin_type(self):
        return "Unknown"

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _ext_extend_network_dict(result, netdb):
        ctx = n_context.get_admin_context()
        # get the core plugin as this is a static method with no 'self'
        plugin = directory.get_plugin()
        with db_api.context_manager.writer.using(ctx):
            plugin._extension_manager.extend_network_dict(
                ctx.session, netdb, result)

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _ext_extend_port_dict(result, portdb):
        ctx = n_context.get_admin_context()
        # get the core plugin as this is a static method with no 'self'
        plugin = directory.get_plugin()
        with db_api.context_manager.writer.using(ctx):
            plugin._extension_manager.extend_port_dict(
                ctx.session, portdb, result)

    @staticmethod
    @resource_extend.extends([subnet_def.COLLECTION_NAME])
    def _ext_extend_subnet_dict(result, subnetdb):
        ctx = n_context.get_admin_context()
        # get the core plugin as this is a static method with no 'self'
        plugin = directory.get_plugin()
        with db_api.context_manager.writer.using(ctx):
            plugin._extension_manager.extend_subnet_dict(
                ctx.session, subnetdb, result)

    def get_network_az_by_net_id(self, context, network_id):
        try:
            network = self.get_network(context, network_id)
        except Exception:
            return self.get_default_az()

        return self.get_network_az(network)

    def _get_router_interface_ports_by_network(
        self, context, router_id, network_id):
        port_filters = {'device_id': [router_id],
                        'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [network_id]}
        return self.get_ports(context, filters=port_filters)

    def get_router_for_floatingip(self, context, internal_port,
                                  internal_subnet, external_network_id):
        router_id = super(NsxPluginBase, self).get_router_for_floatingip(
            context, internal_port, internal_subnet, external_network_id)
        if router_id:
            router = self._get_router(context.elevated(), router_id)
            if not router.enable_snat:
                msg = _("Unable to assign a floating IP to a router that "
                        "has SNAT disabled")
                raise n_exc.InvalidInput(error_message=msg)
        return router_id

    def _get_network_address_scope(self, context, net_id):
        network = self.get_network(context, net_id)
        return network.get(ext_address_scope.IPV4_ADDRESS_SCOPE)

    def _get_subnet_address_scope(self, context, subnet_id):
        subnet = self.get_subnet(context, subnet_id)
        if not subnet['subnetpool_id']:
            return
        subnetpool = self.get_subnetpool(context, subnet['subnetpool_id'])
        return subnetpool.get('address_scope_id', '')

    def _get_subnetpool_address_scope(self, context, subnetpool_id):
        if not subnetpool_id:
            return
        subnetpool = self.get_subnetpool(context, subnetpool_id)
        return subnetpool.get('address_scope_id', '')

    def _validate_address_scope_for_router_interface(self, context, router_id,
                                                     gw_network_id, subnet_id):
        """Validate that the GW address scope is the same as the interface"""
        gw_address_scope = self._get_network_address_scope(context,
                                                           gw_network_id)
        if not gw_address_scope:
            return
        subnet_address_scope = self._get_subnet_address_scope(context,
                                                              subnet_id)
        if (not subnet_address_scope or
            subnet_address_scope != gw_address_scope):
            raise nsx_exc.NsxRouterInterfaceDoesNotMatchAddressScope(
                router_id=router_id, address_scope_id=gw_address_scope)

    def _get_router_interfaces(self, context, router_id):
        port_filters = {'device_id': [router_id],
                        'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF]}
        return self.get_ports(context, filters=port_filters)

    def _find_router_subnets_cidrs(self, context, router_id):
        """Retrieve cidrs of subnets attached to the specified router."""
        subnets = self._find_router_subnets(context, router_id)
        return [subnet['cidr'] for subnet in subnets]

    def _find_router_subnets_cidrs_per_addr_scope(self, context, router_id):
        """Generate a list of cidrs per address pool.

        Go over all the router interface subnets.
        return a list of lists of subnets cidrs belonging to same
        address pool.
        """
        subnets = self._find_router_subnets(context, router_id)
        cidrs_map = {}
        for subnet in subnets:
            ads = self._get_subnetpool_address_scope(
                context, subnet['subnetpool_id']) or ''
            if ads not in cidrs_map:
                cidrs_map[ads] = []
            cidrs_map[ads].append(subnet['cidr'])
        return list(cidrs_map.values())

    def _get_port_by_device_id(self, context, device_id, device_owner):
        """Retrieve ports associated with a specific device id.

        Used for retrieving all neutron ports attached to a given router.
        """
        port_qry = context.session.query(models_v2.Port)
        return port_qry.filter_by(
            device_id=device_id,
            device_owner=device_owner,).all()

    def _update_filters_with_sec_group(self, context, filters=None):
        if filters is not None:
            security_groups = filters.pop("security_groups", None)
            if security_groups:
                bindings = (
                    super(NsxPluginBase, self)
                    ._get_port_security_group_bindings(context,
                        filters={'security_group_id': security_groups}))
                if 'id' in filters:
                    filters['id'] = [entry['port_id'] for
                                     entry in bindings
                                     if entry['port_id'] in filters['id']]
                else:
                    filters['id'] = [entry['port_id'] for entry in bindings]

    def _find_router_subnets(self, context, router_id):
        """Retrieve subnets attached to the specified router."""
        ports = self._get_port_by_device_id(context, router_id,
                                            l3_db.DEVICE_OWNER_ROUTER_INTF)
        # No need to check for overlapping CIDRs
        subnets = []
        for port in ports:
            for ip in port.get('fixed_ips', []):
                subnet_qry = context.session.query(models_v2.Subnet)
                subnet = subnet_qry.filter_by(id=ip.subnet_id).one()
                subnets.append({'id': subnet.id, 'cidr': subnet.cidr,
                                'subnetpool_id': subnet.subnetpool_id,
                                'ip_version': subnet.ip_version,
                                'network_id': subnet.network_id})
        return subnets

    def _find_router_gw_subnets(self, context, router):
        """Retrieve external subnets attached to router GW"""
        if not router['external_gateway_info']:
            return []

        subnets = []
        for fip in router['external_gateway_info']['external_fixed_ips']:
            subnet = self.get_subnet(context, fip['subnet_id'])
            subnets.append(subnet)

        return subnets

    def recalculate_snat_rules_for_router(self, context, router, subnets):
        """Method to recalculate router snat rules for specific subnets.
        Invoked when subnetpool address scope changes.
        Implemented in child plugin classes
        """
        pass

    def recalculate_fw_rules_for_router(self, context, router, subnets):
        """Method to recalculate router FW rules for specific subnets.
        Invoked when subnetpool address scope changes.
        Implemented in child plugin classes
        """
        pass

    def _filter_subnets_by_subnetpool(self, subnets, subnetpool_id):
        return [subnet for subnet in subnets
                if subnet['subnetpool_id'] == subnetpool_id]

    def on_subnetpool_address_scope_updated(self, resource, event,
                                            trigger, **kwargs):
        context = kwargs['context']

        routers = self.get_routers(context)
        subnetpool_id = kwargs['subnetpool_id']
        elevated_context = context.elevated()
        LOG.info("Inspecting routers for potential configuration changes "
                 "due to address scope change on subnetpool %s", subnetpool_id)
        for rtr in routers:
            subnets = self._find_router_subnets(elevated_context,
                                                rtr['id'])
            gw_subnets = self._find_router_gw_subnets(elevated_context,
                                                      rtr)

            affected_subnets = self._filter_subnets_by_subnetpool(
                subnets, subnetpool_id)
            affected_gw_subnets = self._filter_subnets_by_subnetpool(
                gw_subnets, subnetpool_id)

            if not affected_subnets and not affected_gw_subnets:
                # No subnets were affected by address scope change
                continue

            if (affected_subnets == subnets and
                affected_gw_subnets == gw_subnets):
                # All subnets remain under the same address scope
                # (all router subnets were allocated from subnetpool_id)
                continue

            # Update east-west FW rules
            self.recalculate_fw_rules_for_router(context, rtr,
                                                 affected_subnets)

            if not rtr['external_gateway_info']:
                continue

            if not rtr['external_gateway_info']['enable_snat']:
                LOG.warning("Due to address scope change on subnetpool "
                            "%(subnetpool)s, uniqueness on interface "
                            "addresses on no-snat router %(router) is no "
                            "longer guaranteed, which may result in faulty "
                            "operation.", {'subnetpool': subnetpool_id,
                                           'router': rtr['id']})
                continue

            if affected_gw_subnets:
                # GW address scope have changed - we need to revisit snat
                # rules for all router interfaces
                affected_subnets = subnets

            self.recalculate_snat_rules_for_router(context, rtr,
                                                   affected_subnets)

    def _validate_max_ips_per_port(self, fixed_ip_list, device_owner):
        """Validate the number of fixed ips on a port

        Do not allow multiple ip addresses on a port since the nsx backend
        cannot add multiple static dhcp bindings with the same port
        """
        if (device_owner and
            net.is_port_trusted({'device_owner': device_owner})):
            return

        if validators.is_attr_set(fixed_ip_list) and len(fixed_ip_list) > 1:
            msg = _('Exceeded maximum amount of fixed ips per port')
            raise n_exc.InvalidInput(error_message=msg)

    def _extract_external_gw(self, context, router, is_extract=True):
        r = router['router']
        gw_info = constants.ATTR_NOT_SPECIFIED
        # First extract the gateway info in case of updating
        # gateway before edge is deployed.
        if 'external_gateway_info' in r:
            gw_info = r.get('external_gateway_info', {})
            if is_extract:
                del r['external_gateway_info']
            network_id = (gw_info.get('network_id') if gw_info
                          else None)
            if network_id:
                ext_net = self._get_network(context.elevated(), network_id)
                if not ext_net.external:
                    msg = (_("Network '%s' is not a valid external network") %
                           network_id)
                    raise n_exc.BadRequest(resource='router', msg=msg)

                subnets = self._get_subnets_by_network(context.elevated(),
                                                       network_id)
                if not subnets:
                    msg = _("Cannot update gateway on Network '%s' "
                            "with no subnet") % network_id
                    raise n_exc.BadRequest(resource='router', msg=msg)
        return gw_info

    def get_subnets_by_network(self, context, network_id):
        return [self._make_subnet_dict(subnet_obj) for subnet_obj in
                self._get_subnets_by_network(context.elevated(), network_id)]

    def _validate_routes(self, context, router_id, routes):
        super(NsxPluginBase, self)._validate_routes(
            context, router_id, routes)
        # do not allow adding a default route. NSX-v/v3 don't support it
        for route in routes:
            if route.get('destination', '').startswith('0.0.0.0/'):
                msg = _("Cannot set a default route using static routes")
                raise n_exc.BadRequest(resource='router', msg=msg)

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _extend_availability_zone_hints(net_res, net_db):
        net_res[az_def.AZ_HINTS] = az_validator.convert_az_string_to_list(
            net_db[az_def.AZ_HINTS])

    def _validate_external_subnet(self, context, network_id):
        filters = {'id': [network_id], 'router:external': [True]}
        nets = self.get_networks(context, filters=filters)
        if len(nets) > 0:
            err_msg = _("Can not enable DHCP on external network")
            raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_host_routes_input(self, subnet_input,
                                    orig_enable_dhcp=None,
                                    orig_host_routes=None):
        s = subnet_input['subnet']
        request_host_routes = (validators.is_attr_set(s.get('host_routes')) and
                               s['host_routes'])
        clear_host_routes = (validators.is_attr_set(s.get('host_routes')) and
                             not s['host_routes'])
        request_enable_dhcp = s.get('enable_dhcp')
        if request_enable_dhcp is False:
            if (request_host_routes or
                not clear_host_routes and orig_host_routes):
                err_msg = _("Can't disable DHCP while using host routes")
                raise n_exc.InvalidInput(error_message=err_msg)

        if request_host_routes:
            if not request_enable_dhcp and orig_enable_dhcp is False:
                err_msg = _("Host routes can only be supported when DHCP "
                            "is enabled")
                raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_qos_policy_id(self, context, qos_policy_id):
        if qos_policy_id:
            qos_com_utils.validate_policy_accessable(context, qos_policy_id)

    def _validate_create_network(self, context, net_data):
        """Validate the parameters of the new network to be created

        This method includes general validations that does not depend on
        provider attributes, or plugin specific configurations
        """
        external = net_data.get(extnet_apidef.EXTERNAL)
        is_external_net = validators.is_attr_set(external) and external
        with_qos = validators.is_attr_set(
            net_data.get(qos_consts.QOS_POLICY_ID))

        if with_qos:
            self._validate_qos_policy_id(
                context, net_data.get(qos_consts.QOS_POLICY_ID))
            if is_external_net:
                raise nsx_exc.QoSOnExternalNet()

    def _validate_update_netowrk(self, context, id, original_net, net_data):
        """Validate the updated parameters of a network

        This method includes general validations that does not depend on
        provider attributes, or plugin specific configurations
        """
        extern_net = self._network_is_external(context, id)
        with_qos = validators.is_attr_set(
            net_data.get(qos_consts.QOS_POLICY_ID))

        # Do not allow QoS on external networks
        if with_qos and extern_net:
            raise nsx_exc.QoSOnExternalNet()

        # Do not support changing external/non-external networks
        if (extnet_apidef.EXTERNAL in net_data and
            net_data[extnet_apidef.EXTERNAL] != extern_net):
            err_msg = _("Cannot change the router:external flag of a network")
            raise n_exc.InvalidInput(error_message=err_msg)

    def _assert_on_illegal_port_with_qos(self, device_owner):
        # Prevent creating/update port with QoS policy
        # on router-interface/network-dhcp ports.
        if ((device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF or
             device_owner == constants.DEVICE_OWNER_DHCP)):
            err_msg = _("Unable to create or update %s port with a QoS "
                        "policy") % device_owner
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def _assert_on_external_net_with_compute(self, port_data):
        # Prevent creating port with device owner prefix 'compute'
        # on external networks.
        device_owner = port_data.get('device_owner')
        if (device_owner is not None and
            device_owner.startswith(constants.DEVICE_OWNER_COMPUTE_PREFIX)):
            err_msg = _("Unable to update/create a port with an external "
                        "network")
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_create_port(self, context, port_data):
        self._validate_max_ips_per_port(port_data.get('fixed_ips', []),
                                        port_data.get('device_owner'))

        is_external_net = self._network_is_external(
            context, port_data['network_id'])
        qos_selected = validators.is_attr_set(port_data.get(
            qos_consts.QOS_POLICY_ID))
        device_owner = port_data.get('device_owner')

        # QoS validations
        if qos_selected:
            self._validate_qos_policy_id(
                context, port_data.get(qos_consts.QOS_POLICY_ID))
            self._assert_on_illegal_port_with_qos(device_owner)
            if is_external_net:
                raise nsx_exc.QoSOnExternalNet()

        # External network validations:
        if is_external_net:
            self._assert_on_external_net_with_compute(port_data)

        self._assert_on_port_admin_state(port_data, device_owner)

    def _assert_on_vpn_port_change(self, port_data):
        if port_data['device_owner'] == ipsec_utils.VPN_PORT_OWNER:
            msg = _('Can not update/delete VPNaaS port %s') % port_data['id']
            raise n_exc.InvalidInput(error_message=msg)

    def _assert_on_lb_port_fixed_ip_change(self, port_data, orig_dev_own):
        if orig_dev_own == constants.DEVICE_OWNER_LOADBALANCERV2:
            if "fixed_ips" in port_data and port_data["fixed_ips"]:
                msg = _('Can not update Loadbalancer port with fixed IP')
                raise n_exc.InvalidInput(error_message=msg)

    def _assert_on_device_owner_change(self, port_data, orig_dev_own):
        """Prevent illegal device owner modifications
        """
        if orig_dev_own == constants.DEVICE_OWNER_LOADBALANCERV2:
            if ("allowed_address_pairs" in port_data and
                    port_data["allowed_address_pairs"]):
                msg = _('Loadbalancer port can not be updated '
                        'with address pairs')
                raise n_exc.InvalidInput(error_message=msg)

        if 'device_owner' not in port_data:
            return
        new_dev_own = port_data['device_owner']
        if new_dev_own == orig_dev_own:
            return

        err_msg = (_("Changing port device owner '%(orig)s' to '%(new)s' is "
                     "not allowed") % {'orig': orig_dev_own,
                                       'new': new_dev_own})

        # Do not allow changing nova <-> neutron device owners
        if ((orig_dev_own.startswith(constants.DEVICE_OWNER_COMPUTE_PREFIX) and
             new_dev_own.startswith(constants.DEVICE_OWNER_NETWORK_PREFIX)) or
            (orig_dev_own.startswith(constants.DEVICE_OWNER_NETWORK_PREFIX) and
             new_dev_own.startswith(constants.DEVICE_OWNER_COMPUTE_PREFIX))):
            raise n_exc.InvalidInput(error_message=err_msg)

        # Do not allow removing the device owner in some cases
        if orig_dev_own == constants.DEVICE_OWNER_DHCP:
            raise n_exc.InvalidInput(error_message=err_msg)

    def _assert_on_port_sec_change(self, port_data, device_owner):
        """Do not allow enabling port security/mac learning of some ports

        Trusted ports are created with port security and mac learning disabled
        in neutron, and it should not change.
        """
        if net.is_port_trusted({'device_owner': device_owner}):
            if port_data.get(psec.PORTSECURITY) is True:
                err_msg = _("port_security_enabled=True is not supported for "
                            "trusted ports")
                LOG.warning(err_msg)
                raise n_exc.InvalidInput(error_message=err_msg)

            mac_learning = port_data.get(mac_ext.MAC_LEARNING)
            if (validators.is_attr_set(mac_learning) and mac_learning is True):
                err_msg = _("mac_learning_enabled=True is not supported for "
                            "trusted ports")
                LOG.warning(err_msg)
                raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_update_port(self, context, id, original_port, port_data):
        qos_selected = validators.is_attr_set(port_data.get
                                              (qos_consts.QOS_POLICY_ID))
        is_external_net = self._network_is_external(
            context, original_port['network_id'])
        device_owner = (port_data['device_owner']
                        if 'device_owner' in port_data
                        else original_port.get('device_owner'))

        # QoS validations
        if qos_selected:
            self._validate_qos_policy_id(
                context, port_data.get(qos_consts.QOS_POLICY_ID))
            if is_external_net:
                raise nsx_exc.QoSOnExternalNet()
            self._assert_on_illegal_port_with_qos(device_owner)

        # External networks validations:
        if is_external_net:
            self._assert_on_external_net_with_compute(port_data)

        # Device owner validations:
        orig_dev_owner = original_port.get('device_owner')
        self._assert_on_device_owner_change(port_data, orig_dev_owner)
        self._assert_on_port_admin_state(port_data, device_owner)
        self._assert_on_port_sec_change(port_data, device_owner)
        self._validate_max_ips_per_port(
            port_data.get('fixed_ips', []), device_owner)
        self._assert_on_vpn_port_change(original_port)
        self._assert_on_lb_port_fixed_ip_change(port_data, orig_dev_owner)

    def _process_extra_attr_router_create(self, context, router_db, r):
        for extra_attr in l3_attrs_db.get_attr_info().keys():
            if (extra_attr in r and
                validators.is_attr_set(r.get(extra_attr))):
                self.set_extra_attr_value(context, router_db,
                                          extra_attr, r[extra_attr])

    def _get_interface_network(self, context, interface_info):
        is_port, is_sub = self._validate_interface_info(interface_info)
        if is_port:
            net_id = self.get_port(context,
                                   interface_info['port_id'])['network_id']
        elif is_sub:
            net_id = self.get_subnet(context,
                                     interface_info['subnet_id'])['network_id']
        return net_id

    def get_housekeeper(self, context, name, fields=None):
        # run the job in readonly mode and get the results
        self.housekeeper.run(context, name, readonly=True)
        return self.housekeeper.get(name)

    def get_housekeepers(self, context, filters=None, fields=None, sorts=None,
                         limit=None, marker=None, page_reverse=False):
        return self.housekeeper.list()

    def update_housekeeper(self, context, name, housekeeper):
        # run the job in non-readonly mode and get the results
        if not self.housekeeper.readwrite_allowed(name):
            err_msg = (_("Can not run housekeeper job %s in readwrite "
                         "mode") % name)
            raise n_exc.InvalidInput(error_message=err_msg)
        self.housekeeper.run(context, name, readonly=False)
        return self.housekeeper.get(name)

    def get_housekeeper_count(self, context, filters=None):
        return len(self.housekeeper.list())


# Register the callback
def _validate_network_has_subnet(resource, event, trigger, **kwargs):
    network_id = kwargs.get('network_id')
    subnets = kwargs.get('subnets')
    if not subnets:
        msg = _('No subnet defined on network %s') % network_id
        raise n_exc.InvalidInput(error_message=msg)


def subscribe():
    registry.subscribe(_validate_network_has_subnet,
                       resources.ROUTER_GATEWAY, events.BEFORE_CREATE)


subscribe()
