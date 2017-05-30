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
from oslo_utils import excutils

from vmware_nsx.common import locking
from vmware_nsx.services.lbaas import base_mgr

LOG = logging.getLogger(__name__)


class EdgeHealthMonitorManager(base_mgr.EdgeLoadbalancerBaseManager):

    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeHealthMonitorManager, self).__init__()

    @log_helpers.log_method_call
    def create(self, context, hm):
        lb_id = hm.pool.loadbalancer_id
        self.lbv2_driver.health_monitor.successful_completion(context, hm)

    @log_helpers.log_method_call
    def update(self, context, old_hm, new_hm):
        lb_id = new_hm.pool.loadbalancer_id
        self.lbv2_driver.health_monitor.successful_completion(context, new_hm)

    @log_helpers.log_method_call
    def delete(self, context, hm):
        lb_id = hm.pool.loadbalancer_id
        self.lbv2_driver.health_monitor.successful_completion(
            context, hm, delete=True)
