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
from vmware_nsx.services.lbaas.nsx_v.common import healthmon_mgr

LOG = logging.getLogger(__name__)


class EdgeHealthMonitorManager(healthmon_mgr.EdgeHealthMonitorManagerFromDict):
    """Wrapper class for NSX-V LBaaS V2

    This class will call the actual NSX-V LBaaS logic after translating
    the LB object into a dictionary, and will also handle success/failure cases
    """

    @log_helpers.log_method_call
    def create(self, context, hm):
        hm_dict = lb_translators.lb_hm_obj_to_dict(hm)
        super(EdgeHealthMonitorManager, self).create(
            context, hm_dict, hm_obj=hm)

    @log_helpers.log_method_call
    def update(self, context, old_hm, new_hm):
        old_hm_dict = lb_translators.lb_hm_obj_to_dict(old_hm)
        new_hm_dict = lb_translators.lb_hm_obj_to_dict(new_hm)
        super(EdgeHealthMonitorManager, self).update(
            context, old_hm_dict, new_hm_dict, hm_obj=new_hm)

    @log_helpers.log_method_call
    def delete(self, context, hm):
        hm_dict = lb_translators.lb_hm_obj_to_dict(hm)
        super(EdgeHealthMonitorManager, self).delete(
            context, hm_dict, hm_obj=hm)

    def successful_completion(self, context, hm_obj, delete=False,
                              lb_create=False):
        self.lbv2_driver.health_monitor.successful_completion(
            context, hm_obj, delete=delete, lb_create=lb_create)

    def failed_completion(self, context, hm_obj):
        self.lbv2_driver.health_monitor.failed_completion(context, hm_obj)
