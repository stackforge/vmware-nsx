# Copyright 2019 VMware, Inc.
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
import random

from neutron_lib.api.definitions import constants as fwaas_consts
from neutron_lib import context as n_context
from neutron_lib.exceptions import firewall_v2 as exceptions
from neutron_lib.plugins import directory
from oslo_log import log as logging

from vmware_nsx.services.fwaas.common import fwaas_driver_base
from vmware_nsxlib.v3 import nsx_constants as consts
from vmware_nsxlib.v3.policy import constants as policy_constants

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas V2 NSX-P driver'
RULE_NAME_PREFIX = 'Fwaas-'
DEFAULT_RULE_ID = 'default_rule' # DEBUG ADIT in callbacks too


class EdgeFwaasPDriverV2(fwaas_driver_base.EdgeFwaasDriverBaseV2):
    """NSX-P driver for Firewall As A Service - V2."""

    def __init__(self):
        super(EdgeFwaasPDriverV2, self).__init__(FWAAS_DRIVER_NAME)
        self._core_plugin = None

    @property
    def core_plugin(self):
        """Get the NSX-P core plugin"""
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
            # make sure plugin init was completed
            if not self._core_plugin.init_is_complete:
                self._core_plugin.init_complete(None, None, {})
        return self._core_plugin

    @property
    def nsxpolicy(self):
        return self.core_plugin.nsxpolicy

    def should_apply_firewall_to_router(self, router_data):
        """Return True if the firewall rules should be added the router

        Right now the driver supports for all routers.
        """
        # TODO(asarfaty): move to common_v3
        return True

    def _translate_action(self, fwaas_action, fwaas_rule_id):
        """Translate FWaaS action to NSX action"""
        # TODO(asarfaty): move to common_v3
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
        LOG.error("Unsupported FWAAS action %(action)s for rule %(id)s", {
            'action': fwaas_action, 'id': fwaas_rule_id})
        raise exceptions.FirewallInternalDriverError(driver=self.driver_name)

    def _translate_cidr(self, cidr, fwaas_rule_id):
        if cidr and cidr.startswith('0.0.0.0/'):
            LOG.warning("Unsupported FWAAS cidr %(cidr)s for rule %(id)s", {
                'cidr': cidr, 'id': fwaas_rule_id})
            return

        return self.nsx_firewall.get_ip_cidr_reference(
            cidr,
            consts.IPV6 if netaddr.valid_ipv6(cidr) else consts.IPV4)

    def translate_addresses_to_target(self, cidrs, plugin_type,
                                      fwaas_rule_id=None):
        translated_cidrs = []
        for ip in cidrs:
            res = self._translate_cidr(ip, fwaas_rule_id)
            if res:
                translated_cidrs.append(res)
        return translated_cidrs

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

    @staticmethod
    def _translate_ports(ports):
        return [ports.replace(':', '-')]

    # DEBUG ADIT all those can be in the callbacks file instead of here?
    def _translate_services(self, fwaas_rule):
        l4_protocol = self._translate_protocol(fwaas_rule['protocol'])
        if l4_protocol in [consts.TCP, consts.UDP]:
            source_ports = []
            destination_ports = []
            if fwaas_rule.get('source_port'):
                source_ports = self._translate_ports(
                    fwaas_rule['source_port'])
            if fwaas_rule.get('destination_port'):
                destination_ports = self._translate_ports(
                    fwaas_rule['destination_port'])
            # DEBUG ADIT...
            return []
            # return [self.nsx_firewall.get_nsservice(
            #     consts.L4_PORT_SET_NSSERVICE,
            #     l4_protocol=l4_protocol,
            #     source_ports=source_ports,
            #     destination_ports=destination_ports)]
        elif l4_protocol == consts.ICMPV4:
            # Add both icmp v4 & v6 services
            return []
            # return [
            #     # DEBUG ADIT...
            #     self.nsx_firewall.get_nsservice(
            #         consts.ICMP_TYPE_NSSERVICE,
            #         protocol=consts.ICMPV4),
            #     self.nsx_firewall.get_nsservice(
            #         consts.ICMP_TYPE_NSSERVICE,
            #         protocol=consts.ICMPV6),
            # ]

    def _translate_rules(self, domain_id, router_id,
                         fwaas_rules, replace_src=None,
                         replace_dest=None, logged=False):
        translated_rules = []
        for rule in fwaas_rules:
            if not rule['enabled']:
                # skip disabled rules
                continue
            nsx_rule = {}
            # Make sure the rule has a name, and it starts with the prefix
            # (backend max name length is 255)
            if rule.get('name'):
                rule_name = RULE_NAME_PREFIX + rule['name']
            else:
                rule_name = RULE_NAME_PREFIX + rule['id']
            rule_name = rule_name[:255]
            rule_id = rule['id']  + str(random.randint(1, 10000000)) # DEBUG ADIT concatenate the interface id + direction
            action = self._translate_action(
                rule['action'], rule['id'])
            if (rule.get('destination_ip_address') and
                not rule['destination_ip_address'].startswith('0.0.0.0/')):
                nsx_rule['destinations'] = self.translate_addresses_to_target(
                    [rule['destination_ip_address']], rule['id'])
            elif replace_dest:
                # set this value as the destination logical switch
                # (only if no dest IP)
                nsx_rule['destinations'] = [{'target_type': 'LogicalSwitch',
                                             'target_id': replace_dest}]
            if (rule.get('source_ip_address') and
                not rule['source_ip_address'].startswith('0.0.0.0/')):
                nsx_rule['sources'] = self.translate_addresses_to_target(
                    [rule['source_ip_address']], rule['id'])
            elif replace_src:
                # set this value as the source logical switch,
                # (only if no source IP)
                nsx_rule['sources'] = [{'target_type': 'LogicalSwitch',
                                        'target_id': replace_src}]
            if rule.get('protocol'):
                nsx_rule['services'] = self._translate_services(rule)
            if logged:
                nsx_rule['logged'] = logged
            # Set rule direction
            if replace_src:
                direction = 'OUT' # DEBUG ADIT use constant
            elif replace_dest:
                direction = 'IN' # DEBUG ADIT use constant

            rule_entry = self.nsxpolicy.gateway_policy.build_entry(
                rule_name, domain_id, router_id, rule_id,
                description=rule['description'],
                #sequence_number=None,
                #service_ids=None,
                action=action,
                #source_groups=None,
                #dest_groups=None
                logged=logged,
                scope=[self.nsxpolicy.tier1.get_path(router_id)],
                direction=direction)
            translated_rules.append(rule_entry)

# build_entry(self, name, domain_id, map_id, entry_id,
#                     description=None,
#                     sequence_number=None, service_ids=None,
#                     action=constants.ACTION_ALLOW,
#                     scope=None,
#                     source_groups=None, dest_groups=None,
#                     direction=nsx_constants.IN_OUT, logged=False,

        return translated_rules

    def validate_backend_version(self):
        pass

    def _update_backend_routers(self, apply_list, fwg_id):
        """Update all the affected router on the backend"""
        # TODO(asarfaty): move to common_v3
        self.validate_backend_version()
        LOG.info("Updating routers firewall for firewall group %s", fwg_id)
        context = n_context.get_admin_context()
        routers = set()
        # the apply_list is a list of tuples: routerInfo, port-id
        for router_info, port_id in apply_list:
            # Skip dummy entries that were added only to avoid errors
            if isinstance(router_info, str):
                continue
            # Skip unsupported routers
            if not self.should_apply_firewall_to_router(router_info.router):
                continue
            routers.add(router_info.router_id)

        # update each router once
        for router_id in routers:
            self.core_plugin.update_router_firewall(context, router_id,
                                                    from_fw=True)

    def get_port_translated_rules(self, domain_id, router_id, nsx_ls_id,
                                  firewall_group):
        """Return the list of translated rules per port"""
        port_rules = []
        # TODO(asarfaty): get this value from the firewall group extensions
        logged = False
        # Add the firewall group ingress/egress rules only if the fw is up
        if firewall_group['admin_state_up']:
            port_rules.extend(self._translate_rules(
                domain_id, router_id,
                firewall_group['ingress_rule_list'],
                replace_dest=nsx_ls_id,
                logged=logged))
            port_rules.extend(self._translate_rules(
                domain_id, router_id,
                firewall_group['egress_rule_list'],
                replace_src=nsx_ls_id,
                logged=logged))

        # Add ingress/egress block rules for this port
        port_rules.extend([
            self.nsxpolicy.gateway_policy.build_entry(
                "Block port ingress", domain_id, router_id, DEFAULT_RULE_ID + nsx_ls_id + 'ingress',
                action=consts.FW_ACTION_DROP,
                #source_groups=None, dest_groups=None,
                scope=[self.nsxpolicy.tier1.get_path(router_id)],
                direction=consts.IN),
            self.nsxpolicy.gateway_policy.build_entry(
                "Block port egress", domain_id, router_id, DEFAULT_RULE_ID + nsx_ls_id + 'egress',
                action=consts.FW_ACTION_DROP,
                scope=[self.nsxpolicy.tier1.get_path(router_id)],
                #source_groups=None, dest_groups=None,
                direction=consts.OUT)])

        # DEBUG ADIT
        # {'display_name': "Block port ingress",
        #  'action': consts.FW_ACTION_DROP,
        #  'destinations': [{'target_type': 'LogicalSwitch',
        #                    'target_id': nsx_ls_id}],
        #  'direction': 'IN'},
        # {'display_name': "Block port egress",
        #  'action': consts.FW_ACTION_DROP,
        #  'sources': [{'target_type': 'LogicalSwitch',
        #               'target_id': nsx_ls_id}],
        #  'direction': 'OUT'}])

        return port_rules
