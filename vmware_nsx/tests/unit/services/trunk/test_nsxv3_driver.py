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

from neutron.objects import trunk as trunk_objects
from neutron.tests import base

from oslo_config import cfg
from oslo_utils import uuidutils

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common.nsx_constants import VMWARE_NSX_V3_PLUGIN_NAME
from vmware_nsx.services.trunk.nsx_v3 import driver as trunk_driver
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsx_v3_plugin


class TestNsxV3TrunkDriver(base.BaseTestCase):
    def setUp(self):
        super(TestNsxV3TrunkDriver, self).setUp()

    def test_is_loaded(self):
        driver = trunk_driver.NsxV3TrunkDriver.create(mock.Mock())
        cfg.CONF.set_override('core_plugin', VMWARE_NSX_V3_PLUGIN_NAME)
        self.assertTrue(driver.is_loaded)

        cfg.CONF.set_override('core_plugin', 'not_vmware_nsx_plugin')
        self.assertFalse(driver.is_loaded)
