# Copyright (c) 2015 OpenStack Foundation.
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
from oslo_config import cfg

import neutron.tests.unit.db.test_db_base_plugin_v2 as test_plugin
import test_constants_v3
from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib

PLUGIN_NAME = ('vmware_nsx.neutron.plugins.vmware.'
               'plugins.nsx_v3_plugin.NsxV3Plugin')


class NsxPluginV3TestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(NsxPluginV3TestCase, self).setUp(plugin=plugin,
                                               ext_mgr=ext_mgr)
        cfg.CONF.set_override('nsx_controllers', ["1.1.1.1"])
        # Mock entire nsxlib methods as this is the best approach to perform
        # white-box testing on the plugin class
        # TODO(salv-orlando): supply unit tests for nsxlib.v3
        nsxlib.create_logical_switch = mock.Mock()
        nsxlib.create_logical_switch.return_value = \
            test_constants_v3.FAKE_SWITCH


class TestNetworksV3(test_plugin.TestNetworksV2, NsxPluginV3TestCase):
    def test_create_logical_switch(self):
        name = test_constants_v3.FAKE_NAME
        expected =[
            ('name', test_constants_v3.FAKE_NAME),
            ('admin_state_up', True),
            ('id', test_constants_v3.FAKE_UUID),
            ('status', "ACTIVE"),
            ('shared', False),
            ('subnets', [])
        ]
        with self.network(name=name) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)
