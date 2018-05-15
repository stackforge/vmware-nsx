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
from vmware_nsx.services.lbaas.nsx_v.common import l7policy_mgr

LOG = logging.getLogger(__name__)


class EdgeL7PolicyManager(l7policy_mgr.EdgeL7PolicyManagerFromDict):
    """Wrapper class for NSX-V LBaaS V2

    This class will call the actual NSX-V LBaaS logic after translating
    the LB object into a dictionary, and will also handle success/failure cases
    """
    @log_helpers.log_method_call
    def create(self, context, policy):
        policy_dict = lb_translators.lb_l7policy_obj_to_dict(policy)
        super(EdgeL7PolicyManager, self).create(
            context, policy_dict, policy_obj=policy)

    @log_helpers.log_method_call
    def update(self, context, old_policy, new_policy):
        old_policy_dict = lb_translators.lb_l7policy_obj_to_dict(old_policy)
        new_policy_dict = lb_translators.lb_l7policy_obj_to_dict(new_policy)
        super(EdgeL7PolicyManager, self).update(
            context, old_policy_dict, new_policy_dict, policy_obj=new_policy)

    @log_helpers.log_method_call
    def delete(self, context, policy):
        policy_dict = lb_translators.lb_l7policy_obj_to_dict(policy)
        super(EdgeL7PolicyManager, self).delete(
            context, policy_dict, policy_obj=policy)

    def successful_completion(self, context, policy_obj, delete=False,
                              lb_create=False):
        self.lbv2_driver.l7policy.successful_completion(
            context, policy_obj, delete=delete, lb_create=lb_create)

    def failed_completion(self, context, policy_obj):
        self.lbv2_driver.l7policy.failed_completion(context, policy_obj)
