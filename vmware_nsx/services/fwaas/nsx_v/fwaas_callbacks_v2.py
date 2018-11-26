# Copyright 2018 VMware, Inc.
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

from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx_v.vshield import edge_firewall_driver
from vmware_nsx.services.fwaas.common import fwaas_callbacks_v2 as \
    com_callbacks
from vmware_nsx.services.fwaas.nsx_tv import edge_fwaas_driver_v2 as tv_driver

LOG = logging.getLogger(__name__)
RULE_NAME_PREFIX = 'Fwaas-'


class NsxvFwaasCallbacksV2(com_callbacks.NsxFwaasCallbacksV2):
    """NSX-V RPC callbacks for Firewall As A Service - V2."""

    def __init__(self):
        super(NsxvFwaasCallbacksV2, self).__init__()
        # update the fwaas driver in case of TV plugin
        self.internal_driver = None
        if self.fwaas_enabled:
            if self.fwaas_driver.driver_name == tv_driver.FWAAS_DRIVER_NAME:
                self.internal_driver = self.fwaas_driver.get_V_driver()
            else:
                self.internal_driver = self.fwaas_driver

    @property
    def plugin_type(self):
        return projectpluginmap.NsxPlugins.NSX_V

    def should_apply_firewall_to_router(self, context, router, router_id):
        """Return True if the FWaaS rules should be added to this router."""
        # in case of a distributed-router:
        # router['id'] is the id of the neutron router (=tlr)
        # and router_id is the plr/tlr (the one that is being updated)

        # First check if there are rules attached to this router
        if not super(NsxvFwaasCallbacksV2,
                     self).should_apply_firewall_to_router(
            context, router['id']):
            return False

        # get all the relevant router info
        # ("router" does not have all the fields)
        ctx_elevated = context.elevated()
        router_data = self.core_plugin.get_router(ctx_elevated, router['id'])
        if not router_data:
            LOG.error("Couldn't read router %s data", router['id'])
            return False

        if router_data.get('distributed'):
            if router_id == router['id']:
                # Do not add firewall rules on the tlr router.
                return False

        # Check if the FWaaS driver supports this router
        if not self.internal_driver.should_apply_firewall_to_router(
            router_data, raise_exception=False):
            return False

        return True

    def get_fwaas_rules_for_router(self, context, router_id):
        """Return the list of (translated) FWaaS rules for this router."""
        ctx_elevated = context.elevated()
        router_interfaces = self.core_plugin._get_router_interfaces(
            ctx_elevated, router_id)

        fw_rules = []
        # Add firewall rules per port attached to a firewall group
        for port in router_interfaces:
            fwg = self.get_port_fwg(ctx_elevated, port['id'])
            if fwg:
                # get the nsx-id of the port network
                net_morefs = nsx_db.get_nsx_switch_ids(
                    context.session, port['network_id'])
                if net_morefs:
                    # Add the FWaaS rules for this port
                    fw_rules.extend(
                        self.get_port_translated_rules(net_morefs[0], fwg))

        return fw_rules

    def get_port_translated_rules(self, nsx_net_id, firewall_group):
        """Return the list of translated rules per port

        Ingress/Egress firewall rules + default ingress/egress drop
        """
        port_rules = []
        logged = False
        # Add the firewall group ingress/egress rules only if the fw is up
        if firewall_group['admin_state_up']:
            port_rules.extend(self.translate_rules(
                firewall_group['ingress_rule_list'],
                replace_dest=nsx_net_id,
                logged=logged))
            port_rules.extend(self.translate_rules(
                firewall_group['egress_rule_list'],
                replace_src=nsx_net_id,
                logged=logged))

        # Add the per-port plugin rules
        #if plugin_rules and isinstance(plugin_rules, list):
        #    port_rules.extend(plugin_rules)

        # Add ingress/egress block rules for this port
        port_rules.extend([
            {'name': "Block port ingress",
             'action': edge_firewall_driver.FWAAS_DENY,
             'destination_gouping_obj': [nsx_net_id],
             'logged': logged},
            {'name': "Block port egress",
             'action': edge_firewall_driver.FWAAS_DENY,
             'source_gouping_obj': [nsx_net_id],
             'logged': logged}])

        return port_rules

    def translate_rules(self, fwaas_rules, replace_dest=None, replace_src=None,
                        logged=False):
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
            if replace_dest:
                rule['destination_gouping_obj'] = [replace_dest]
            elif rule.get('destination_ip_address'):
                rule['destination_ip_address'] = [
                    rule['destination_ip_address']]
            if replace_src:
                rule['source_gouping_obj'] = [replace_src]
            elif rule.get('source_ip_address'):
                rule['source_ip_address'] = [rule['source_ip_address']]
            if logged:
                rule['logged'] = True
            translated_rules.append(rule)

        return translated_rules
