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

from vmware_nsx.services.lbaas.nsx_v.v2 import base_mgr

LOG = logging.getLogger(__name__)


class EdgeL7PolicyManager(base_mgr.EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeL7PolicyManager, self).__init__(vcns_driver)

    @log_helpers.log_method_call
    def create(self, context, pol):
        pass

    @log_helpers.log_method_call
    def update(self, context, old_pol, new_pol):
        pass

    @log_helpers.log_method_call
    def delete(self, context, pol):
        pass
