# Copyright (c) 2015 VMware, Inc.
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

import contextlib
from neutron.tests import base

from vmware_nsx.neutron.services.l2gateway import plugin as l2gw_plugin
from vmware_nsx.neutron.services.l2gateway import nsx_v3_driver

from oslo_config import cfg


NSX_V3_DRIVER_CLASS_PATH = ('vmware_nsx.neutron.services.l2gateway.'
                            'nsx_v3_driver.NsxV3Driver')

class TestNsxV3L2GatewayDriver(base.BaseTestCase):

    def setUp(self):
        super(TestNsxV3L2GatewayDriver, self).setUp()
        cfg.CONF.set_override("nsx_l2gw_driver",
                              NSX_V3_DRIVER_CLASS_PATH, 'NSX')
        self.plugin = l2gw_plugin.NsxL2GatewayPlugin()
        self.context = mock.ANY

    def test_nsxl2gw_driver_init(self):
        with contextlib.nested(
            mock.patch.object(nsx_v3_driver.NsxV3Driver,
                              '_ensure_default_l2_gateway'),
            mock.patch.object(nsx_v3_driver.NsxV3Driver,
                              'subscribe_callback_notifications'),
            mock.patch.object(nsx_v3_driver.LOG,
                              'debug')
        ) as (ensure_default_l2gw,
              subscribe,
              debug):
            l2gw_plugin.NsxL2GatewayPlugin()
            self.assertTrue(ensure_default_l2gw.called)
            self.assertTrue(subscribe.called)
            self.assertTrue(debug.called)
