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

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.fwaas.common import fwaas_callbacks_v2 as \
    com_callbacks
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3.policy import constants as policy_constants


LOG = logging.getLogger(__name__)
GATEWAY_POLICY_NAME = 'Gateway policy for Tier1 %s'
DEFAULT_RULE_NAME = 'Default LR Layer3 Rule'
DEFAULT_RULE_ID = 'default_rule'


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

    @property
    def nsxpolicy(self):
        return self.core_plugin.nsxpolicy

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

    def get_port_rules(self, domain_id, router_id, port_id, fwg):
        return self.internal_driver.get_port_translated_rules(
            domain_id, router_id, port_id, fwg)

    def router_with_fwg(self, context, router_interfaces):
        # TODO(asarfaty): move to common_v3
        for port in router_interfaces:
            fwg = self.get_port_fwg(context, port['id'])
            if fwg and fwg.get('status') == nl_constants.ACTIVE:
                return True
        return False

    def get_default_backend_rule(self, domain_id, router_id):
        return self.nsxpolicy.gateway_policy.build_entry(
            DEFAULT_RULE_NAME, domain_id, router_id, DEFAULT_RULE_ID,
            description=DEFAULT_RULE_NAME + ' adit testing',
            sequence_number=None,
            action=nsx_constants.FW_ACTION_ALLOW,
            scope=[self.nsxpolicy.tier1.get_path(router_id)],
            source_groups=None, dest_groups=None,
            direction=nsx_constants.IN_OUT)
        #     'is_default': True,

    def update_router_firewall(self, context, nsxlib, router_id, router,
                               router_interfaces, from_fw=False):
        """Rewrite all the FWaaS v2 rules in the router edge firewall

        This method should be called on FWaaS updates, and on router
        interfaces changes.
        The purpose of from_fw is to differ between fw calls and other router
        calls, and if it is True - add the service router accordingly.
        """

        domain_id = router['project_id']
        fw_rules = []
        with_fw = False
        # Add firewall rules per port attached to a firewall group
        for port in router_interfaces:

            # Check if this port has a firewall
            fwg = self.get_port_fwg(context, port['id'])
            if fwg:
                with_fw = True
                # add the FWaaS rules for this port
                # ingress/egress firewall rules + default ingress/egress drop
                # rule for this port
                fw_rules.extend(self.get_port_rules(domain_id, router_id,
                                                    port['id'], fwg))

        # add a default allow-all rule to all other traffic & ports
        fw_rules.append(self.get_default_backend_rule(domain_id, router_id))

        # DEBUG ADIT add nsxlib api for this?
        # add sequence numbers to keep rules in order
        seq_num = 0
        for rule in fw_rules:
            rule.attrs['sequence_number'] = seq_num
            seq_num = seq_num + 1

        # update the backend router firewall
        exists_on_backend = self.core_plugin.verify_sr_at_backend(router_id)
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
            self._create_router_gateway_policy(context, domain_id, router_id,
                                               router, fw_rules)
        else:
            # No fwaas for this router - delete the gateway policy
            self._delete_router_gateway_policy(context, domain_id, router_id)

    def _create_router_gateway_policy(self, context, domain_id, router_id,
                                      router, fw_rules):
        """Create/Overwrite gateway policy for a router with firewall rules"""
        # DEBUG ADIT add error handling
        # Check if the gateway policy already exists
        try:
            self.nsxpolicy.gateway_policy.get(domain_id, map_id=router_id)
        except nsx_lib_exc.ResourceNotFound:
            LOG.info("Going to create gateway policy for router %s", router_id)
        else:
            # only update the rules of this policy
            LOG.error("DEBUG ADIT _create_router_gateway_policy update policy with rules %s", fw_rules)
            self.nsxpolicy.gateway_policy.update_entries(
                domain_id, router_id,fw_rules)
            return

        tags = self.nsxpolicy.build_v3_tags_payload(
            router, resource_type='os-neutron-router-id',
            project_name=context.tenant_name)
        policy_name = GATEWAY_POLICY_NAME % router_id
        LOG.error("DEBUG ADIT _create_router_gateway_policy create policy with rules %s", fw_rules)
        self.nsxpolicy.gateway_policy.create_with_entries(
            policy_name, domain_id, map_id=router_id,
            description=policy_name,
            tags=tags,
            entries=fw_rules,
            category=policy_constants.CATEGORY_LOCAL_GW)

    def _delete_router_gateway_policy(self, context, domain_id, router_id):
        """Delete the gateway policy associated with a router, it it exists.
        Should be called when the router is deleted / FW removed from it
        """
        try:
            self.nsxpolicy.gateway_policy.get(domain_id, map_id=router_id)
        except nsx_lib_exc.ResourceNotFound:
            return
        self.nsxpolicy.gateway_policy.delete(domain_id, map_id=router_id)

    def delete_port(self, context, port_id):
        # TODO(asarfaty): move to common_v3
        # Mark the FW group as inactive if this is the last port
        fwg = self.get_port_fwg(context, port_id)
        if (fwg and fwg.get('status') == nl_constants.ACTIVE and
            len(fwg.get('ports', [])) <= 1):
            self.fwplugin_rpc.set_firewall_group_status(
                context, fwg['id'], nl_constants.INACTIVE)
