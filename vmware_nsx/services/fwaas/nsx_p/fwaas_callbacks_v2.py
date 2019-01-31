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

from oslo_log import log as logging

from neutron_lib import constants as nl_constants

from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.fwaas.common import fwaas_callbacks_v2 as \
    com_callbacks

LOG = logging.getLogger(__name__)
GATEWAY_POLICY_NAME = 'Gateway policy for Tier1 %s'


class NsxpFwaasCallbacksV2(com_callbacks.NsxFwaasCallbacksV2):
    """NSX-P RPC callbacks for Firewall As A Service - V2."""

    def __init__(self):
        super(NsxpFwaasCallbacksV2, self).__init__()
        # update the fwaas driver in case of TV plugin
        self.internal_driver = None
        if self.fwaas_enabled:
                self.internal_driver = self.fwaas_driver

    @property
    def plugin_type(self):
        return projectpluginmap.NsxPlugins.NSX_P

    def should_apply_firewall_to_router(self, context, router_id):
        """Return True if the FWaaS rules should be added to this router."""
        # TODO(asarfaty): move to common_v3
        if not super(NsxpFwaasCallbacksV2,
                     self).should_apply_firewall_to_router(context,
                                                           router_id):
            return False

        # get all the relevant router info
        ctx_elevated = context.elevated()
        router_data = self.core_plugin.get_router(ctx_elevated, router_id)
        if not router_data:
            LOG.error("Couldn't read router %s data", router_id)
            return False

        # Check if the FWaaS driver supports this router
        if not self.internal_driver.should_apply_firewall_to_router(
            router_data):
            return False

        return True

    def get_port_rules(self, nsx_ls_id, fwg, plugin_rules):
        # TODO(asarfaty): move to common_v3
        return self.internal_driver.get_port_translated_rules(
            nsx_ls_id, fwg, plugin_rules)

    def router_with_fwg(self, context, router_interfaces):
        # TODO(asarfaty): move to common_v3
        for port in router_interfaces:
            fwg = self.get_port_fwg(context, port['id'])
            if fwg and fwg.get('status') == nl_constants.ACTIVE:
                return True
        return False

    def update_router_firewall(self, context, nsxlib, router_id, router,
                               router_interfaces, nsx_router_id, section_id,
                               from_fw=False):
        """Rewrite all the FWaaS v2 rules in the router edge firewall

        This method should be called on FWaaS updates, and on router
        interfaces changes.
        The purpose of from_fw is to differ between fw calls and other router
        calls, and if it is True - add the service router accordingly.
        """

        fw_rules = []
        with_fw = False
        # Add firewall rules per port attached to a firewall group
        for port in router_interfaces:
            nsx_ls_id, _nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port['id'])

            # Check if this port has a firewall
            fwg = self.get_port_fwg(context, port['id'])
            if fwg:
                with_fw = True
                # Add plugin additional allow rules
                plugin_rules = self.core_plugin.get_extra_fw_rules(
                    context, router_id, port['id'])

                # add the FWaaS rules for this port
                # ingress/egress firewall rules + default ingress/egress drop
                # rule for this port
                fw_rules.extend(self.get_port_rules(nsx_ls_id, fwg,
                                                    plugin_rules))

        # add a default allow-all rule to all other traffic & ports
        fw_rules.append(self.internal_driver.get_default_backend_rule(
            section_id, allow_all=True))

        # update the backend router firewall
        exists_on_backend = self.core_plugin.verify_sr_at_backend(context,
                                                                  router_id)
        if from_fw:
            # fw action required
            if with_fw:
                # firewall exists in Neutron and not on backend - create
                if not exists_on_backend:
                    self.core_plugin.create_service_router(context, router_id)
                    exists_on_backend = True
            else:
                # First, check if other services exist and use the sr
                sr_exists = self.core_plugin.service_router_has_services(
                    context, router_id)
                if not sr_exists and exists_on_backend:
                    # No other services that require service router - delete
                    self.core_plugin.delete_service_router(context, router_id)
                    exists_on_backend = False

        if exists_on_backend:
            # update the edge firewall
            self._ensure_router_gateway_policy(context, router_id, router)
            nsxlib.firewall_section.update(section_id, rules=fw_rules)
        else:
            # No fwaas for this router - delete the gateway policy
            self._delete_router_gateway_policy(context, router_id, router)

    def _ensure_router_gateway_policy(self, context, router_id, router):
        """Create a new gateway policy for a router, if does not exist yet"""
        domain_id = router['project_id']
        try:
            self.nsxpolicy.gateway_policy.get(domain_id, map_id=router_id)
        except nsx_lib_exc.ResourceNotFound:
            LOG.info("Going to create gateway policy for router %s", router_id)
        else:
            return

        tags = self.nsxpolicy.build_v3_tags_payload(
            router, resource_type='os-neutron-router-id',
            project_name=context.tenant_name)
        policy_name = GATEWAY_POLICY_NAME % router_id
        self.nsxpolicy.gateway_policy.create_or_overwrite_map_only(
            policy_name, domain_id, map_id=router_id,
            description=policy_name,
            tags=tags,
            category='LocalGatewayRules') # this is the only one where you can later select

    def _delete_router_gateway_policy(self, context, router_id, router):
        """Delete the gateway policy associated with a router, it it exists.
        Should be called when the router is deleted / FW removed from it
        """
        domain_id = router['project_id']
        try:
            self.nsxpolicy.gateway_policy.get(domain_id, map_id=router_id)
        except nsx_lib_exc.ResourceNotFound:
            return
        self.nsxpolicy.gateway_policy.delete(domain_id, map_id=router_id)

    def DEBUG_ADIT_add_edge_firewall_rules(self, context, router_id, router):
        # DEBUG ADIT - temp test

        # Create a gateway policy for this project (Domain) & router
        # DEBUG ADIT - if not created yet
        domain_id = router['project_id']
        try:
            policy_name = 'Gateway policy for Tier1 %s' % router_id
            self.core_plugin.nsxpolicy.gateway_policy.create_or_overwrite_map_only(
                policy_name, domain_id, map_id=router_id,
                description=policy_name,
                #tags=tags,
                category='LocalGatewayRules') # this is the only one where you can later select
        except Exception as e:
            msg = (_("Failed to create gateway policy router %(rtr)s: "
                     "%(e)s") % {'rtr': router_id, 'e': e})

        # Add rule
        rule_name = 'dummy rule 1'
        rule_id = 'dummy_id'
        sg_rule = {}
        self.nsxpolicy.gateway_policy.create_entry(
            rule_name, domain_id, router_id,
            entry_id=rule_id,
            description=sg_rule.get('description'),
            #service_ids=[service] if service else None,
            action=policy_constants.ACTION_ALLOW,
            #source_groups=[source] if source else None,
            #dest_groups=[destination] if destination else None,
            direction=nsxlib_consts.IN,
            scope=['/infra/tier-1s/%s' % router_id], # DEBUG ADIT - add api for this
            #logged=logging
            )

    def delete_port(self, context, port_id):
        # TODO(asarfaty): move to common_v3
        # Mark the FW group as inactive if this is the last port
        fwg = self.get_port_fwg(context, port_id)
        if (fwg and fwg.get('status') == nl_constants.ACTIVE and
            len(fwg.get('ports', [])) <= 1):
            self.fwplugin_rpc.set_firewall_group_status(
                context, fwg['id'], nl_constants.INACTIVE)
