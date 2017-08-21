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

from neutron_lib import context as n_context
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver_base \
    as base_driver
from vmware_nsxlib.v3 import nsx_constants as consts

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas V2 NSX-V3 driver'
RULE_NAME_PREFIX = 'Fwaas-'
NSX_FW_TAG = 'os-neutron-fw-id'


class EdgeFwaasV3DriverV2(base_driver.CommonEdgeFwaasV3Driver):
    """NSX-V3 driver for Firewall As A Service - V2."""

    @log_helpers.log_method_call
    def create_firewall_group(self, agent_mode, apply_list, firewall_group):
        """Create the Firewall with a given policy. """
        self._update_backend_routers(apply_list, firewall_group['id'])

    @log_helpers.log_method_call
    def update_firewall_group(self, agent_mode, apply_list, firewall_group):
        """Remove previous policy and apply the new policy."""
        self._update_backend_routers(apply_list, firewall_group['id'])

    @log_helpers.log_method_call
    def delete_firewall_group(self, agent_mode, apply_list, firewall_group):
        """Delete firewall.

        Removes rules created by this instance from the backend firewall
        And add the default allow rule.
        """
        self._update_backend_routers(apply_list, firewall_group['id'])

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall_group):
        """Apply the default policy (deny all).

        The backend firewall always has this policy (=deny all) as default,
        so we only need to delete the current rules.
        """
        self._update_backend_routers(apply_list, firewall_group['id'])

    def _update_backend_routers(self, apply_list, fwg_id):
        """Update all the affected router on the backend"""
        self.validate_backend_version()
        LOG.info("Updating routers firewall for firewall group %s", fwg_id)
        context = n_context.get_admin_context()
        routers = set()
        # the apply_list is a list of tuples: routerInfo, port-id
        for router_info, port_id in apply_list:
            # Skip unsupported routers
            if not self.should_apply_firewall_to_router(router_info.router):
                continue
            routers.add(router_info.router_id)

        # update each router once
        for router_id in routers:
            self.core_plugin.update_router_firewall(context, router_id)

    def get_port_translated_rules(self, nsx_port_id, firewall_group):
        """Return the list of translated rules per port"""
        port_rules = []

        # Add the firewall group ingress/egress rules only if the fw is up
        if firewall_group['admin_state_up']:
            port_rules.extend(self._translate_rules(
                firewall_group['ingress_rule_list'],
                replace_dest=nsx_port_id))
            port_rules.extend(self._translate_rules(
                firewall_group['egress_rule_list'],
                replace_src=nsx_port_id))

        # Add ingress/egress block rules for this port
        port_rules.extend([
            {'display_name': "Block port ingress",
             'action': consts.FW_ACTION_DROP,
             'destinations': [{'target_type': 'LogicalPort',
                               'target_id': nsx_port_id}],
             'direction': 'IN'},
            {'display_name': "Block port egress",
             'action': consts.FW_ACTION_DROP,
             'sources': [{'target_type': 'LogicalPort',
                          'target_id': nsx_port_id}],
             'direction': 'OUT'}])

        return port_rules

    #TODO(asarfaty): log error when setting engress/egress policy with
    # source/dest ips
