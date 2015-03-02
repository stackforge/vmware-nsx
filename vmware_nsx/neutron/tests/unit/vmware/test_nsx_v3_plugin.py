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

from oslo.config import cfg
import mock

import neutron.tests.unit.test_db_plugin as test_plugin
from vmware_nsx.neutron.plugins.vmware import nsx_v3_lib


PLUGIN_NAME = ('vmware_nsx.neutron.plugins.vmware.'
               'plugins.nsx_v3_plugin.NSXv3Plugin')


class NsxPluginV3TestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(NsxPluginV3TestCase, self).setUp(plugin=plugin,
                                               ext_mgr=ext_mgr)
        cfg.CONF.set_override('nsx_controllers', ["1.1.1.1"],
                              group='nsx_v3')
        nsx_v3_lib.create_logical_switch = mock.Mock()
        nsx_v3_lib.create_logical_switch.return_value = {"id": "xxx"}


class TestBasicGet(test_plugin.TestBasicGet, NsxPluginV3TestCase):
    pass
