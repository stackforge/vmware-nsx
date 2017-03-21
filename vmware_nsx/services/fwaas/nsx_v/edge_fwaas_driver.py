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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_lib import context as n_context
from neutron_lib.plugins import directory

from neutron_fwaas.extensions import firewall as fw_ext
from neutron_fwaas.services.firewall.drivers import fwaas_base

from vmware_nsx.plugins.nsx_v.vshield.common import (
    exceptions as vcns_exc)
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas NSX-V driver'
RULE_NAME_PREFIX = 'Fwaas-'


class EdgeFwaasDriver(fwaas_base.FwaasDriverBase):
    """NSX-V driver for Firewall As A Service - V1."""

    @property
    def edge_manager(self):
        return directory.get_plugin().edge_manager

    def __init__(self):
        LOG.debug("Loading FWaaS NsxVDriver.")
        super(EdgeFwaasDriver, self).__init__()
        self._nsxv = vcns_driver.VcnsDriver(None)

    def _get_routers_edges(self, context, apply_list):
        # Get edges for all the routers in the apply list.
        # note that shared routers are currently not supported
        edge_manager = self.edge_manager
        edges = []
        for router_info in apply_list:
            lookup_id = None
            router_id = router_info.router_id
            if router_info.router.get('distributed'):
                # we need the plr edge id
                lookup_id = edge_manager.get_plr_by_tlr_id(
                    context, router_id)
            if router_info.router.get('router_type') == 'shared':
                LOG.info("Cannot apply firewall to shared router %s",
                         router_id)
            else:
                # exclusive router
                lookup_id = router_id
            if lookup_id:
                # look for the edge id in the DB
                edge_id = edge_utils.get_router_edge_id(context, lookup_id)
                if edge_id:
                    edges.append(edge_id)
        return edges

    def _translate_rules(self, fwaas_rules):
        translated_rules = []
        for rule in fwaas_rules:
            if not rule['enabled']:
                # skip disabled rules
                continue
            # Make sure the rule has a name, and it starts with the prefix
            # (backend max name length is 30)
            if rule.get('name'):
                rule['name'] = RULE_NAME_PREFIX + rule['name']
            else:
                rule['name'] = RULE_NAME_PREFIX + rule['id']
            rule['name'] = rule['name'][:30]
            # source & destination should be lists
            if rule.get('destination_ip_address'):
                rule['destination_ip_address'] = [
                    rule['destination_ip_address']]
            if rule.get('source_ip_address'):
                rule['source_ip_address'] = [rule['source_ip_address']]
            translated_rules.append(rule)

        return translated_rules

    def _get_relevant_backend_rules(self, context, edge_id):
        """Get a list of current backend rules from other applications

        Those rules should stay on the backend firewall, when updating the
        FWaaS rules.
        """
        try:
            backend_fw = self._nsxv.get_firewall(context, edge_id)
            backend_rules = backend_fw['firewall_rule_list']
        except vcns_exc.VcnsApiException:
            # Need to create a new one
            backend_rules = []

        # remove old FWaaS rules from the rules list
        relevant_rules = []
        for rule_item in backend_rules:
            rule = rule_item['firewall_rule']
            if not rule.get('name', '').startswith(RULE_NAME_PREFIX):
                relevant_rules.append(rule)

        return relevant_rules

    def _set_rules_on_edge(self, context, edge_id, fw_id, translated_rules):
        """delete old FWaaS rules from the Edge, and add new ones

        Note that the edge might have other FW rules like NAT or LBaas
        that should remain there.
        """
        # Get the current backend rules which do not belong to FWaaS
        backend_rules = self._get_relevant_backend_rules(context, edge_id)

        # add new FWaaS rules at the end by their original order
        backend_rules.extend(translated_rules)

        # update the backend
        # allow_external is False because it was already added
        try:
            self._nsxv.update_firewall(
                edge_id,
                {'firewall_rule_list': backend_rules},
                context,
                allow_external=False)
        except Exception as e:
            # catch known library exceptions and raise Fwaas generic exception
            LOG.exception("Failed to up;date backend firewall %(fw)s: "
                          "%(e)s", {'e': e, 'fw': fw_id})
            raise fw_ext.FirewallInternalDriverError(driver=FWAAS_DRIVER_NAME)

    def _create_or_update_firewall(self, agent_mode, apply_list, firewall):
        # admin state down means default block rule firewall
        if not firewall['admin_state_up']:
            self.apply_default_policy(agent_mode, apply_list, firewall)
            return

        context = n_context.get_admin_context()

        # Find out the relevant edges
        router_edges = self._get_routers_edges(context, apply_list)
        if not router_edges:
            LOG.warning("Cannot apply the firewall to any of the routers %s",
                        apply_list)
            return

        rules = self._translate_rules(firewall['firewall_rule_list'])
        # update each edge
        for edge_id in router_edges:
            self._set_rules_on_edge(
                context, edge_id, firewall['id'], rules)

    @log_helpers.log_method_call
    def create_firewall(self, agent_mode, apply_list, firewall):
        """Create the Firewall with a given policy. """
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    @log_helpers.log_method_call
    def update_firewall(self, agent_mode, apply_list, firewall):
        """Remove previous policy and apply the new policy."""
        self._create_or_update_firewall(agent_mode, apply_list, firewall)

    def _delete_firewall_or_set_default_policy(self, apply_list, firewall):
        context = n_context.get_admin_context()
        router_edges = self._get_routers_edges(context, apply_list)
        if router_edges:
            for edge_id in router_edges:
                self._set_rules_on_edge(context, edge_id, firewall['id'], [])

    @log_helpers.log_method_call
    def delete_firewall(self, agent_mode, apply_list, firewall):
        """Delete firewall.

        Removes rules created by this instance from the backend firewall.
        """
        self._delete_firewall_or_set_default_policy(apply_list, firewall)

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        """Apply the default policy (deny all).

        The backend firewall alway has this policy as default, so we only need
        to delete the current rules.
        """
        self._delete_firewall_or_set_default_policy(apply_list, firewall)

    def get_firewall_translated_rules(self, firewall):
        if firewall['admin_state_up']:
            return self._translate_rules(firewall['firewall_rule_list'])
        return []
