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

import netaddr

from neutron_fwaas.extensions import firewall as fwaas_consts
from neutron_fwaas.services.firewall.drivers import fwaas_base
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsxlib.v3 import nsx_constants as consts

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas NSX-V3 driver'
RULE_NAME_PREFIX = 'Fwaas-'


class EdgeFwaasV3Driver(fwaas_base.FwaasDriverBase):
    """NSX-V3 driver for Firewall As A Service - V1."""

    def __init__(self):
        LOG.debug("Loading FWaaS NsxV3Driver.")
        super(EdgeFwaasV3Driver, self).__init__()

    @property
    def core_plugin(self):
        return directory.get_plugin()

    @property
    def nsx_firewall(self):
        return self.core_plugin.nsxlib.firewall_section

    def should_apply_firewall_to_router(self, router_data):
        """Return True if the firewall rules should be added the router

        Right now the driver supports for all routers.
        """
        return True

    @staticmethod
    def _translate_action(fwaas_action, fwaas_rule_id):
        """Translate FWaaS action to NSX action"""
        if fwaas_action == fwaas_consts.FWAAS_ALLOW:
            return consts.FW_ACTION_ALLOW
        if fwaas_action == fwaas_consts.FWAAS_DENY:
            return consts.FW_ACTION_DROP
        if fwaas_action == fwaas_consts.FWAAS_REJECT:
            # reject is not supported by the nsx router firewall
            LOG.warning("Reject action is not supported by the NSX backend "
                        "for router firewall. Using %(action)s instead for "
                        "rule %(id)s",
                  {'action': consts.FW_ACTION_DROP,
                   'id': fwaas_rule_id})
            return consts.FW_ACTION_DROP
        # Unexpected action
        msg = _("Unsupported FWAAS action %(action)s for rule %(id)s") % {
            'action': fwaas_action, 'id': fwaas_rule_id}
        LOG.error(msg)
        raise n_exc.InvalidInput(error_message=msg)

    def _translate_cidr(self, cidr):
        return self.nsx_firewall.get_ip_cidr_reference(
            cidr,
            consts.IPV6 if netaddr.valid_ipv6(cidr) else consts.IPV4)

    def _translate_addresses(self, cidrs):
        return [self._translate_cidr(ip) for ip in cidrs]

    @staticmethod
    def _translate_protocol(fwaas_protocol):
        """Translate FWaaS L4 protocol to NSX protocol"""
        if fwaas_protocol.lower() == 'tcp':
            return consts.TCP
        if fwaas_protocol.lower() == 'udp':
            return consts.UDP
        if fwaas_protocol.lower() == 'icmp':
            # This will cover icmpv6 too, when adding  the rule.
            return consts.ICMPV4

    def _translate_services(self, fwaas_rule):
        l4_protocol = self._translate_protocol(fwaas_rule['protocol'])
        if l4_protocol in [consts.TCP, consts.UDP]:
            source_ports = []
            destination_ports = []
            if fwaas_rule.get('source_port'):
                source_ports = [fwaas_rule['source_port']]
            if fwaas_rule.get('destination_port'):
                destination_ports = [fwaas_rule['destination_port']]

            return [self.nsx_firewall.get_nsservice(
                consts.L4_PORT_SET_NSSERVICE,
                l4_protocol=l4_protocol,
                source_ports=source_ports,
                destination_ports=destination_ports)]
        elif l4_protocol == consts.ICMPV4:
            # Add both icmp v4 & v6 services
            return [
                self.nsx_firewall.get_nsservice(
                    consts.ICMP_TYPE_NSSERVICE,
                    protocol=consts.ICMPV4),
                self.nsx_firewall.get_nsservice(
                    consts.ICMP_TYPE_NSSERVICE,
                    protocol=consts.ICMPV6),
            ]

    def _translate_rules(self, fwaas_rules):
        translated_rules = []
        for rule in fwaas_rules:
            nsx_rule = {}
            if not rule['enabled']:
                # skip disabled rules
                continue
            # Make sure the rule has a name, and it starts with the prefix
            # (backend max name length is 255)
            if rule.get('name'):
                name = RULE_NAME_PREFIX + rule['name']
            else:
                name = RULE_NAME_PREFIX + rule['id']
            nsx_rule['display_name'] = name[:255]
            if rule.get('description'):
                nsx_rule['notes'] = rule['description']
            nsx_rule['action'] = self._translate_action(
                rule['action'], rule['id'])
            if rule.get('destination_ip_address'):
                nsx_rule['destinations'] = self._translate_addresses(
                    [rule['destination_ip_address']])
            if rule.get('source_ip_address'):
                nsx_rule['sources'] = self._translate_addresses(
                    [rule['source_ip_address']])
            if rule.get('protocol', 'any') != 'any':
                nsx_rule['services'] = self._translate_services(rule)

            translated_rules.append(nsx_rule)

        return translated_rules

    def _update_backend_routers(self, context, apply_list, rules,
                                allow_external=False):
        # update each router using the core plugin code
        for router_info in apply_list:

            # Skip unsupported routers
            if not self.should_apply_firewall_to_router(router_info.router):
                continue

            # get the full router info from the plugin
            router_id = router_info.router_id
            plugin_router = self.core_plugin._get_router(context, router_id)

            # update the routers firewall
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
