# Copyright (c) 2016 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import mock

from neutron_taas.tests.unit.services.taas import test_taas_plugin

from vmware_nsx.services.neutron_taas.nsx_v3 import driver as nsx_v3_driver


class TestNsxV3TaaSDriver(test_taas_plugin.TestTaasPlugin):
    def setUp(self):
        super(TestNsxV3TaaSDriver, self).setUp()
        self.driver = nsx_v3_driver.NsxV3Driver(mock.MagicMock())
