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
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_fwaas.services.firewall.drivers import fwaas_base

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas NSX-V3 driver'
RULE_NAME_PREFIX = 'Fwaas-'


class EdgeFwaasV3Driver(fwaas_base.FwaasDriverBase):
    """NSX-V3 driver for Firewall As A Service - V1."""

    @property
    def core_plugin(self):
        return directory.get_plugin()

    def __init__(self):
        LOG.debug("Loading FWaaS NsxV3Driver.")
        super(EdgeFwaasV3Driver, self).__init__()

    def should_apply_firewall_to_router(self, router_data):
        """Return True if the firewall rules should be added the router

        Right now this is supported for all routers.
        """
        return True

    def _translate_rules(self, fwaas_rules):
        translated_rules = []
        for rule in fwaas_rules:
            nsx_rule = {}
            if not rule['enabled']:
                # skip disabled rules
                continue
            # Make sure the rule has a name, and it starts with the prefix
            # (backend max name length is 30)
            if rule.get('name'):
                nsx_rule['name'] = RULE_NAME_PREFIX + rule['name']
            else:
                nsx_rule['name'] = RULE_NAME_PREFIX + rule['id']
            nsx_rule['name'] = nsx_rule['name'][:30]

            # DEBUG ADIT translate action, service, source, dest

            translated_rules.append(nsx_rule)

        return translated_rules

    def _update_backend_routers(self, context, apply_list, rules,
                                allow_external=False):
        # update each router using the core plugin code
        for router_info in apply_list:

            # Skip unsupported routers
            if not self.should_apply_firewall_to_router(router_info.router):
                continue

            router_id = router_info.router_id
            plugin_router = self.core_plugin._get_router(context, router_id)
            self.core_plugin._update_router_firewall(
                context, plugin_router, fwaas_rules=rules,
                fwaas_allow_external=allow_external)

    def _create_or_update_firewall(self, agent_mode, apply_list, firewall):
        # admin state down means default block rule firewall
        if not firewall['admin_state_up']:
            self.apply_default_policy(agent_mode, apply_list, firewall)
            return

        context = n_context.get_admin_context()

        rules = self._translate_rules(firewall['firewall_rule_list'])
        # update each router using the core plugin code
        self._update_backend_routers(context, apply_list, rules)

    @log_helpers.log_method_call
    def create_firewall(self, agent_mode, apply_list, firewall):
        """Create the Firewall with a given policy. """
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    @log_helpers.log_method_call
    def update_firewall(self, agent_mode, apply_list, firewall):
        """Remove previous policy and apply the new policy."""
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    def _delete_firewall_or_set_default_policy(self, apply_list, firewall,
                                               allow_external):
        context = n_context.get_admin_context()
        self._update_backend_routers(context, apply_list, rules=[],
                                     allow_external=allow_external)

    @log_helpers.log_method_call
    def delete_firewall(self, agent_mode, apply_list, firewall):
        """Delete firewall.

        Removes rules created by this instance from the backend firewall
        And add the default allow-external rule.
        """
        self._delete_firewall_or_set_default_policy(apply_list, firewall,
                                                    allow_external=True)

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        """Apply the default policy (deny all).

        The backend firewall always has this policy (=deny all) as default,
        so we only need to delete the current rules.
        """
        self._delete_firewall_or_set_default_policy(apply_list, firewall,
                                                    allow_external=False)

    def get_firewall_translated_rules(self, firewall):
        if firewall['admin_state_up']:
            return self._translate_rules(firewall['firewall_rule_list'])
        return []
