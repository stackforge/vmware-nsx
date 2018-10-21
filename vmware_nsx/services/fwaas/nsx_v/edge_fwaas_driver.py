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
from neutron_lib.exceptions import firewall_v1 as exceptions
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx.common import locking
from vmware_nsx.services.fwaas.nsx_v import edge_fwaas_driver_base

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas V1 NSX-V driver'


class EdgeFwaasDriver(edge_fwaas_driver_base.EdgeFwaasDriverBase):
    """NSX-V driver for Firewall As A Service - V1."""

    def __init__(self):
        LOG.debug("Loading FWaaS V1 NsxVDriver.")
        super(EdgeFwaasDriver, self).__init__()
        self.driver_name = FWAAS_DRIVER_NAME

    def _set_rules_on_router_edge(self, context, router_id, neutron_id,
                                  edge_id, fw_id, translated_rules,
                                  delete_fw=False):
        """Recreate router edge firewall rules

        Using the plugin code to recreate all the rules with the additional
        FWaaS rules.

        router_id is the is of the router about to be updated
            (in case of distributed router - the plr)
        neutron_id is the neutron router id
        """
        # update the backend
        router_db = self.core_plugin._get_router(context, neutron_id)
        try:
            with locking.LockManager.get_lock(str(edge_id)):
                self.core_plugin.update_router_firewall(
                    context, router_id, router_db,
                    fwaas_rules=translated_rules)
        except Exception as e:
            # catch known library exceptions and raise Fwaas generic exception
            LOG.error("Failed to update firewall %(fw)s on edge %(edge_id)s: "
                      "%(e)s", {'e': e, 'fw': fw_id, 'edge_id': edge_id})
            raise exceptions.FirewallInternalDriverError(
                driver=self.driver_name)

    def _create_or_update_firewall(self, agent_mode, apply_list, firewall):
        # admin state down means default block rule firewall
        if not firewall['admin_state_up']:
            self.apply_default_policy(agent_mode, apply_list, firewall)
            return

        # get router-edge mapping
        context = n_context.get_admin_context()
        edges_map = self._get_routers_edges(context, apply_list)
        if not edges_map:
            routers = [r.router_id for r in apply_list]
            LOG.warning("Cannot apply the firewall %(fw)s to any of the "
                        "routers %(rtrs)s",
                        {'fw': firewall['id'], 'rtrs': routers})
            return

        # Translate the FWaaS rules
        # TODO(asarfaty): get this value from the firewall extensions
        logged = False
        rules = self._translate_rules(firewall['firewall_rule_list'],
                                      logged=logged)

        # update each relevant edge with the new rules
        for router_info in apply_list:
            neutron_id = router_info.router_id
            info = edges_map.get(neutron_id)
            if info:
                self._set_rules_on_router_edge(
                    context, info['lookup_id'], neutron_id, info['edge_id'],
                    firewall['id'], rules)

    @log_helpers.log_method_call
    def create_firewall(self, agent_mode, apply_list, firewall):
        """Create the Firewall with a given policy. """
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    @log_helpers.log_method_call
    def update_firewall(self, agent_mode, apply_list, firewall):
        """Remove previous policy and apply the new policy."""
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    def _delete_firewall_or_set_default_policy(self, apply_list, firewall,
                                               delete_fw=False):
        # get router-edge mapping
        context = n_context.get_admin_context()
        edges_map = self._get_routers_edges(context, apply_list,
                                            delete_fw=delete_fw)

        # if the firewall is deleted, rules should be None
        rules = None if delete_fw else []

        # Go over all routers and update them on backend
        for router_info in apply_list:
            neutron_id = router_info.router_id
            info = edges_map.get(neutron_id)
            if info:
                self._set_rules_on_router_edge(
                    context, info['lookup_id'], neutron_id, info['edge_id'],
                    firewall['id'], rules, delete_fw=delete_fw)

    @log_helpers.log_method_call
    def delete_firewall(self, agent_mode, apply_list, firewall):
        """Delete firewall.

        Removes rules created by this instance from the backend firewall
        And add the default allow-external rule.
        """
        self._delete_firewall_or_set_default_policy(apply_list, firewall,
                                                    delete_fw=True)

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        """Apply the default policy (deny all).

        The backend firewall always has this policy (=deny all) as default,
        so we only need to delete the current rules.
        """
        self._delete_firewall_or_set_default_policy(apply_list, firewall,
                                                    delete_fw=False)

    def get_firewall_translated_rules(self, firewall):
        if firewall['admin_state_up']:
            # TODO(asarfaty): get this value from the firewall extensions
            logged = False
            return self._translate_rules(firewall['firewall_rule_list'],
                                         logged=logged)
        return []
