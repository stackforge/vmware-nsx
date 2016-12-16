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

from neutron.plugins.common import constants

from vmware_nsx.services.lbaas.nsx_v.common import base_mgr


class EdgeLBaaSv2BaseManager(base_mgr.EdgeLoadbalancerBaseManager):
    _lbv2_driver = None

    def __init__(self, vcns_driver):
        super(EdgeLBaaSv2BaseManager, self).__init__(vcns_driver)

    @property
    def lbv2_driver(self):
        if not EdgeLBaaSv2BaseManager._lbv2_driver:
            plugin = self._get_plugin(
                constants.LOADBALANCERV2)
            EdgeLBaaSv2BaseManager._lbv2_driver = (
                plugin.drivers['vmwareedge'])

        return EdgeLBaaSv2BaseManager._lbv2_driver

    def complete_success(self, context, obj, *args, **kwargs):
        self.lbv2_mgr.successful_completion(context, obj, *args, **kwargs)

    def complete_failed(self, context, obj):
        self.lbv2_mgr.failed_completion(context, obj)
