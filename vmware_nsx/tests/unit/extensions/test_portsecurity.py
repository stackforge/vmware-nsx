# Copyright (c) 2014 OpenStack Foundation.
# All Rights Reserved.
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

from neutron.tests.unit.extensions import test_portsecurity as psec
from vmware_nsx.tests.unit.nsx_v3 import test_constants as v3_constants
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsxv3


class TestPortSecurityNSXv3(psec.TestPortSecurity,
                            test_nsxv3.NsxV3PluginTestCaseMixin):
    def setUp(self, plugin=v3_constants.PLUGIN_NAME):
        super(TestPortSecurityNSXv3, self).setUp(plugin=plugin)
