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

from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas.nsx_v3 import lb_utils

LOG = logging.getLogger(__name__)


class EdgeL7RuleManager(base_mgr.Nsxv3LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeL7RuleManager, self).__init__()

    @staticmethod
    def _validate_rule_in_policy(policy):
        # Only one l7rule is allowed for each l7policy in pike release.
        # This validation is to allow only one l7rule per l7policy.
        if len(policy.rules) > 1:
            msg = (_('Only one l7rule is allowed on l7policy'
                     '%(policy)s') % {'policy': policy.id})
            raise n_exc.BadRequest(resource='lbaas-l7rule-create',
                                   msg=msg)

    def _update_l7rule_change(self, context, rule, delete=False):
        rule_client = self.core_plugin.nsxlib.load_balancer.rule
        if delete:
            lb_utils.remove_rule_from_policy(rule)
        rule_body = lb_utils.convert_l7policy_to_lb_rule(context, rule.policy)
        try:
            lb_rule_id = lb_utils.get_nsx_rule_from_policy(
                self.core_plugin.nsxlib, rule.policy)
            rule_client.update(lb_rule_id, **rule_body)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.l7rule.failed_completion(context, rule)
                LOG.error('Failed to update L7policy %(policy)s: '
                          '%(err)s', {'policy': rule.policy.id, 'err': e})

        self.lbv2_driver.l7rule.successful_completion(context, rule,
                                                      delete=delete)

    @log_helpers.log_method_call
    def create(self, context, rule):
        self._validate_rule_in_policy(rule.policy)
        self._update_l7rule_change(context, rule)

    @log_helpers.log_method_call
    def update(self, context, old_rule, new_rule):
        self._update_l7rule_change(context, new_rule)

    @log_helpers.log_method_call
    def delete(self, context, rule):
        self._update_l7rule_change(context, rule, delete=True)
