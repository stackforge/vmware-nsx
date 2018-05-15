# Copyright 2015 VMware, Inc.
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
from vmware_nsx.services.lbaas.nsx_v.common import member_mgr

LOG = logging.getLogger(__name__)


class EdgeMemberManager(member_mgr.EdgeMemberManagerFromDict):
    """Wrapper class for NSX-V LBaaS V2

    This class will call the actual NSX-V LBaaS logic after translating
    the LB object into a dictionary, and will also handle success/failure cases
    """
    @log_helpers.log_method_call
    def create(self, context, member):
        member_dict = lb_translators.lb_member_obj_to_dict(member)
        super(EdgeMemberManager, self).create(
            context, member_dict, member_obj=member)

    @log_helpers.log_method_call
    def update(self, context, old_member, new_member):
        old_member_dict = lb_translators.lb_member_obj_to_dict(old_member)
        new_member_dict = lb_translators.lb_member_obj_to_dict(new_member)
        super(EdgeMemberManager, self).update(
            context, old_member_dict, new_member_dict, member_obj=new_member)

    @log_helpers.log_method_call
    def delete(self, context, member):
        member_dict = lb_translators.lb_member_obj_to_dict(member)
        super(EdgeMemberManager, self).delete(
            context, member_dict, member_obj=member)

    def successful_completion(self, context, member_obj, delete=False,
                              lb_create=False):
        self.lbv2_driver.member.successful_completion(
            context, member_obj, delete=delete, lb_create=lb_create)

    def failed_completion(self, context, member_obj):
        self.lbv2_driver.member.failed_completion(context, member_obj)
