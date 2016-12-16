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

import abc
import six

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _, _LE
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as nsxv_exc
from vmware_nsx.services.lbaas.nsx_v.common import base_mgr
from vmware_nsx.services.lbaas.nsx_v.common import lbaas_common as lb_common

LOG = logging.getLogger(__name__)


def enable_edge_acceleration(vcns, edge_id):
    with locking.LockManager.get_lock(edge_id):
        # Query the existing load balancer config in case metadata lb is set
        _, config = vcns.get_loadbalancer_config(edge_id)
        config['accelerationEnabled'] = True
        config['enabled'] = True
        config['featureType'] = 'loadbalancer_4.0'
        vcns.enable_service_loadbalancer(edge_id, config)


def get_lbaas_edge_id(context, plugin, lb_id, vip_addr, subnet_id, tenant_id):
    subnet = plugin.get_subnet(context, subnet_id)
    network_id = subnet.get('network_id')
    availability_zone = plugin.get_network_az(context, network_id)

    resource_id = lb_common.get_lb_resource_id(lb_id)

    edge_id = plugin.edge_manager.allocate_lb_edge_appliance(
        context, resource_id, availability_zone=availability_zone)

    lb_common.create_lb_interface(context, plugin, lb_id, subnet_id, tenant_id,
                                  vip_addr=vip_addr, subnet=subnet)

    gw_ip = subnet.get('gateway_ip')
    if gw_ip:
        plugin.nsx_v.update_routes(edge_id, gw_ip, [])

    return edge_id


@six.add_metaclass(abc.ABCMeta)
class EdgeLoadBalancerManager(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeLoadBalancerManager, self).__init__(vcns_driver)
        registry.subscribe(
            self._handle_subnet_gw_change,
            resources.SUBNET_GATEWAY, events.AFTER_UPDATE)

    @log_helpers.log_method_call
    def create(self, context, lb):
        edge_id = get_lbaas_edge_id(
            context, self.core_plugin, lb.id, lb.vip_address, lb.vip_subnet_id,
            lb.tenant_id)

        if not edge_id:
            msg = _('Failed to allocate Edge on subnet %(sub)s for '
                    'loadbalancer %(lb)s') % {'sub': lb.vip_subnet_id,
                                              'lb': lb.id}
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        try:
            enable_edge_acceleration(self.vcns, edge_id)

            edge_fw_rule_id = lb_common.add_vip_fw_rule(
                self.vcns, edge_id, lb.id, lb.vip_address)

            # set LB default rule
            lb_common.set_lb_firewall_default_rule(self.vcns, edge_id,
                                                   'accept')

            nsxv_db.add_nsxv_lbaas_loadbalancer_binding(
                context.session, lb.id, edge_id, edge_fw_rule_id,
                lb.vip_address)
            self.complete_success(context, lb)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.complete_failed(context, lb)
                LOG.error(_LE('Failed to create pool %s'), lb.id)

    @log_helpers.log_method_call
    def update(self, context, old_lb, new_lb):
        self.complete_success(context, new_lb)

    @log_helpers.log_method_call
    def delete(self, context, lb):
        # Discard any ports which are associated with LB
        filters = {
            'device_id': [lb.id],
            'device_owner': [constants.DEVICE_OWNER_NEUTRON_PREFIX + 'LB']}
        lb_ports = self.core_plugin.get_ports(context.elevated(),
                                              filters=filters)
        for lb_port in lb_ports:
            self.core_plugin.delete_port(context.elevated(), lb_port['id'])

        binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb.id)
        if binding:
            edge_binding = nsxv_db.get_nsxv_router_binding_by_edge(
                context.session, binding['edge_id'])

            # set LB default rule
            lb_common.set_lb_firewall_default_rule(
                self.vcns, binding['edge_id'], 'deny')
            if edge_binding:
                if edge_binding['router_id'].startswith('lbaas-'):
                    resource_id = lb_common.get_lb_resource_id(lb.id)
                    self.core_plugin.edge_manager.delete_lrouter(
                        context, resource_id, dist=False)
                else:
                    # Edge was created on an exclusive router with the old code
                    try:
                        lb_common.del_vip_fw_rule(
                            self.vcns, binding['edge_id'],
                            binding['edge_fw_rule_id'])
                    except nsxv_exc.VcnsApiException as e:
                        LOG.error(_LE('Failed to delete loadbalancer %(lb)s '
                                      'FW rule. exception is %(exc)s'),
                                  {'lb': lb.id, 'exc': e})
                    try:
                        lb_common.del_vip_as_secondary_ip(self.vcns,
                                                          binding['edge_id'],
                                                          lb.vip_address)
                    except Exception as e:
                        LOG.error(_LE('Failed to delete loadbalancer %(lb)s '
                                      'interface IP. exception is %(exc)s'),
                                  {'lb': lb.id, 'exc': e})

            nsxv_db.del_nsxv_lbaas_loadbalancer_binding(context.session, lb.id)
            self.complete_success(context, lb, delete=True)

    @log_helpers.log_method_call
    def refresh(self, context, lb):
        # TODO(kobis): implememnt
        pass

    @log_helpers.log_method_call
    def stats(self, context, lb):
        # TODO(kobis): implement
        stats = {'bytes_in': 0,
                 'bytes_out': 0,
                 'active_connections': 0,
                 'total_connections': 0}

        return stats

    def _handle_subnet_gw_change(self, *args, **kwargs):
        # As the Edge appliance doesn't use DHCP, we should change the
        # default gateway here when the subnet GW changes.
        context = kwargs.get('context')
        subnet_id = kwargs.get('subnet_id')
        subnet = self.core_plugin.get_subnet(context.elevated(), subnet_id)

        filters = {'fixed_ips': {'subnet_id': [subnet_id]},
                   'device_owner': [constants.DEVICE_OWNER_LOADBALANCERV2]}
        lb_ports = self.core_plugin.get_ports(context.elevated(),
                                              filters=filters)

        if lb_ports:
            for lb_port in lb_ports:
                if lb_port['device_id']:
                    edge_bind = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                        context.session, lb_port['device_id'])
                    edge_id = edge_bind['edge_id']

                    self.core_plugin.nsx_v.update_routes(
                        edge_id, subnet['gateway_ip'], [])
