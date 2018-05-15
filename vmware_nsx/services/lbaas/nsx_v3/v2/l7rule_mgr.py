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

from vmware_nsx.services.lbaas import lb_translators
from vmware_nsx.services.lbaas.nsx_v3.common import l7rule_mgr

LOG = logging.getLogger(__name__)


class EdgeL7RuleManager(l7rule_mgr.EdgeL7RuleManagerFromDict):
    """Wrapper class for NSX-V3 LBaaS V2

    This class will call the actual NSX-V LBaaS logic after translating
    the LB object into a dictionary, and will also handle success/failure cases
    """
    @log_helpers.log_method_call
    def create(self, context, rule):
        rule_dict = lb_translators.lb_l7rule_obj_to_dict(rule)
        super(EdgeL7RuleManager, self).create(
            context, rule_dict, rule_obj=rule)

    @log_helpers.log_method_call
    def update(self, context, old_rule, new_rule):
        old_rule_dict = lb_translators.lb_l7rule_obj_to_dict(old_rule)
        new_rule_dict = lb_translators.lb_l7rule_obj_to_dict(new_rule)
        super(EdgeL7RuleManager, self).update(
            context, old_rule_dict, new_rule_dict, rule_obj=new_rule)

    @log_helpers.log_method_call
    def delete(self, context, rule):
        rule_dict = lb_translators.lb_l7rule_obj_to_dict(rule)
        super(EdgeL7RuleManager, self).delete(
            context, rule_dict, rule_obj=rule)

    def successful_completion(self, context, rule_obj, delete=False,
                              lb_create=False):
        self.lbv2_driver.l7rule.successful_completion(
            context, rule_obj, delete=delete, lb_create=lb_create)

    def failed_completion(self, context, rule_obj):
        self.lbv2_driver.l7rule.failed_completion(context, rule_obj)
