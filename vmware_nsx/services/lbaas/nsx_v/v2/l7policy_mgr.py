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
from oslo_utils import excutils

from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _, _LE
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vcns_exc
from vmware_nsx.services.lbaas.nsx_v import lbaas_common as lb_common
from vmware_nsx.services.lbaas.nsx_v import lbaas_const as lb_const
from vmware_nsx.services.lbaas.nsx_v.v2 import base_mgr

LOG = logging.getLogger(__name__)


class EdgeL7PolicyManager(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeL7PolicyManager, self).__init__(vcns_driver)

    def _policy_to_application_rule(self, policy):
        # DEBUG ADIT - build the condition out of all the rules
        condition = 'TRUE'

        if policy.action == lb_const.L7_POLICY_ACTION_REJECT:
            action = "tcp-request content reject"
        elif policy.action == lb_const.L7_POLICY_ACTION_REDIRECT_TO_POOL:
            action = "use_backend pool_%s" % policy.redirect_pool_id
        elif policy.action == lb_const.L7_POLICY_ACTION_REDIRECT_TO_URL:
            action = "redirect location %s" % policy.redirect_url
        else:
            msg = _('Unsupported L7policy action %s') % policy.action
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        script = "%(action)s if %(cond)s" % {'action': action,
                                             'cond': condition}
        app_rule = {'name': 'pol_' + policy.id,
                    'script': script}
        return app_rule

    def _add_app_rule_to_virtual_server(self, edge_id, vse_id, app_rule_id,
                                        policy_position):
        """Add the new nsx application rule to the virtual server"""
        # Get the current virtual server configuration
        vse = self.vcns.get_vip(edge_id, vse_id)[1]
        if 'applicationRuleId' not in vse:
            vse['applicationRuleId'] = []

        # Add the policy (=application rule) in the correct position
        # (position begins at 1)
        if len(vse['applicationRuleId']) < policy_position:
            vse['applicationRuleId'].append(app_rule_id)
        else:
            vse['applicationRuleId'].insert(policy_position - 1, app_rule_id)

        # update the backend with the new configuration
        self.vcns.update_vip(edge_id, vse_id, vse)

    def _del_app_rule_from_virtual_server(self, edge_id, vse_id, app_rule_id):
        """Delete nsx application rule from the virtual server"""
        # Get the current virtual server configuration
        vse = self.vcns.get_vip(edge_id, vse_id)[1]
        if 'applicationRuleId' not in vse:
            vse['applicationRuleId'] = []

        # Remove the rule from the list
        if ('applicationRuleId' in vse and
            app_rule_id in vse['applicationRuleId']):
            vse['applicationRuleId'].remove(app_rule_id)

        # update the backend with the new configuration
        self.vcns.update_vip(edge_id, vse_id, vse)

    @log_helpers.log_method_call
    def create(self, context, pol):
        # find out the edge to be updated, by the listener of this policy
        lb_id = pol.listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        if not lb_binding:
            msg = _(
                'No suitable Edge found for listener %s') % pol.listener_id
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        edge_id = lb_binding['edge_id']
        app_rule = self._policy_to_application_rule(pol)

        try:
            with locking.LockManager.get_lock(edge_id):
                # create the backend application rule for this policy
                h = (self.vcns.create_app_rule(edge_id, app_rule))[0]
                app_rule_id = lb_common.extract_resource_id(h['location'])

                # add the nsx application rule (neutron policy) to the nsx
                # virtual server (neutron listener)
                listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
                    context.session, lb_id, pol.listener.id)
                if listener_binding:
                    self._add_app_rule_to_virtual_server(
                        edge_id, listener_binding['vse_id'], app_rule_id,
                        pol.position)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.l7policy.failed_completion(context, pol)
                LOG.error(_LE('Failed to create L7policy on edge: %s'),
                          edge_id)

        # save the nsx application rule id in the DB
        nsxv_db.add_nsxv_lbaas_l7policy_binding(context.session, pol.id,
                                                edge_id, app_rule_id)
        # complete the transaction
        self.lbv2_driver.l7policy.successful_completion(context, pol)

    def _get_edge_and_rule_id(self, context, policy_id):
        # get the nsx application rule id and edge id
        binding = nsxv_db.get_nsxv_lbaas_l7policy_binding(
            context.session, policy_id)
        if not binding:
            msg = _('No suitable Edge found for policy %s') % policy_id
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        return binding['edge_id'], binding['edge_app_rule_id']

    @log_helpers.log_method_call
    def update(self, context, old_pol, new_pol):
        # get the nsx application rule id and edge id
        edge_id, app_rule_id = self._get_edge_and_rule_id(context, new_pol.id)
        # create the script for the new policy data
        app_rule = self._policy_to_application_rule(new_pol)
        try:
            with locking.LockManager.get_lock(edge_id):
                # update the backend application rule for the new policy
                self.vcns.update_app_rule(edge_id, app_rule_id, app_rule)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.l7policy.failed_completion(context, new_pol)
                LOG.error(_LE('Failed to update L7policy on edge: %s'),
                          edge_id)

        # complete the transaction
        self.lbv2_driver.l7policy.successful_completion(context, new_pol)

    @log_helpers.log_method_call
    def delete(self, context, pol):
        # get the nsx application rule id and edge id
        edge_id, app_rule_id = self._get_edge_and_rule_id(context, pol.id)
        with locking.LockManager.get_lock(edge_id):
            try:
                # remove the nsx application rule from the virtual server
                lb_id = pol.listener.loadbalancer_id
                listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
                    context.session, lb_id, pol.listener.id)
                if listener_binding:
                    vse_id = listener_binding['vse_id']
                    self._del_app_rule_from_virtual_server(
                        edge_id, vse_id, app_rule_id)

                # delete the nsx application rule
                self.vcns.delete_app_rule(edge_id, app_rule_id)

            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.l7policy.failed_completion(context, pol)
                    LOG.error(_LE('Failed to delete l7policy on edge: %s'),
                              edge_id)

        # complete the transaction
        self.lbv2_driver.l7policy.successful_completion(context, pol,
                                                        delete=True)

        # delete the nsxv db entry
        nsxv_db.del_nsxv_lbaas_l7policy_binding(context.session, pol.id)
