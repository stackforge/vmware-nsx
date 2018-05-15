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
from vmware_nsx.services.lbaas.nsx_v3.common import pool_mgr

LOG = logging.getLogger(__name__)


class EdgePoolManager(pool_mgr.EdgePoolManagerFromDict):
    """Wrapper class for NSX-V3 LBaaS V2

    This class will call the actual NSX-V LBaaS logic after translating
    the LB object into a dictionary, and will also handle success/failure cases
    """
    @log_helpers.log_method_call
    def create(self, context, pool):
        pool_dict = lb_translators.lb_pool_obj_to_dict(pool)
        super(EdgePoolManager, self).create(
            context, pool_dict, pool_obj=pool)

    @log_helpers.log_method_call
    def update(self, context, old_pool, new_pool):
        old_pool_dict = lb_translators.lb_pool_obj_to_dict(old_pool)
        new_pool_dict = lb_translators.lb_pool_obj_to_dict(new_pool)
        super(EdgePoolManager, self).update(
            context, old_pool_dict, new_pool_dict, pool_obj=new_pool)

    @log_helpers.log_method_call
    def delete(self, context, pool):
        pool_dict = lb_translators.lb_pool_obj_to_dict(pool)
        super(EdgePoolManager, self).delete(
            context, pool_dict, pool_obj=pool)

    def successful_completion(self, context, pool_obj, delete=False,
                              lb_create=False):
        self.lbv2_driver.pool.successful_completion(
            context, pool_obj, delete=delete, lb_create=lb_create)

    def failed_completion(self, context, pool_obj):
        self.lbv2_driver.pool.failed_completion(context, pool_obj)
