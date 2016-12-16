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

from vmware_nsx.services.lbaas.nsx_v.common import pool_mgr
from vmware_nsx.services.lbaas.nsx_v.v2 import base_mgr


class EdgePoolManager(base_mgr.EdgeLBaaSv2BaseManager,
                      pool_mgr.EdgePoolManager):
    def __init__(self, vcns_driver):
        super(EdgePoolManager, self).__init__(vcns_driver)

    @property
    def lbv2_mgr(self):
        return self.lbv2_driver.pool
