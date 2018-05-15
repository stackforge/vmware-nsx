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
from vmware_nsx.services.lbaas.nsx_v3.common import loadbalancer_mgr as lb_mgr

LOG = logging.getLogger(__name__)


class EdgeLoadBalancerManager(lb_mgr.EdgeLoadBalancerManagerFromDict):
    """Wrapper class for NSX-V3 LBaaS V2

    This class will call the actual NSX-V LBaaS logic after translating
    the LB object into a dictionary, and will also handle success/failure cases
    """
    @log_helpers.log_method_call
    def create(self, context, lb):
        lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(lb)
        super(EdgeLoadBalancerManager, self).create(
            context, lb_dict, lb_obj=lb)

    @log_helpers.log_method_call
    def update(self, context, old_lb, new_lb):
        old_lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(old_lb)
        new_lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(new_lb)
        super(EdgeLoadBalancerManager, self).update(
            context, old_lb_dict, new_lb_dict, lb_obj=new_lb)

    @log_helpers.log_method_call
    def refresh(self, context, lb):
        lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(lb)
        super(EdgeLoadBalancerManager, self).refresh(
            context, lb_dict)

    @log_helpers.log_method_call
    def delete(self, context, lb):
        lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(lb)
        super(EdgeLoadBalancerManager, self).delete(
            context, lb_dict, lb_obj=lb)

    @log_helpers.log_method_call
    def stats(self, context, lb, lb_obj=None):
        lb_dict = lb_translators.lb_loadbalancer_obj_to_dict(lb)
        super(EdgeLoadBalancerManager, self).stats(
            context, lb_dict)

    def successful_completion(self, context, lb_obj, delete=False,
                              lb_create=False):
        self.lbv2_driver.load_balancer.successful_completion(
            context, lb_obj, delete=delete, lb_create=lb_create)

    def failed_completion(self, context, lb_obj):
        self.lbv2_driver.load_balancer.failed_completion(context, lb_obj)
