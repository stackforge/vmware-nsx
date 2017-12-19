# Copyright (c) 2017 OpenStack Foundation.
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

from oslo_utils import uuidutils

from neutron_lib import context
from neutron_lib.plugins import directory

from vmware_nsx.tests.unit.dvs import test_plugin as dvs_tests
from vmware_nsx.tests.unit.nsx_v import test_plugin as v_tests
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as t_tests

PLUGIN_NAME = 'vmware_nsx.plugin.NsxTVDPlugin'
_uuid = uuidutils.generate_uuid


class NsxTVDPluginTestCase(v_tests.NsxVPluginV2TestCase,
                           t_tests.NsxV3PluginTestCaseMixin,
                           dvs_tests.NeutronSimpleDvsTestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(NsxTVDPluginTestCase, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr)

        self.core_plugin = directory.get_plugin()

        # create a context with this tenant
        self.context = context.get_admin_context()
        self.context.tenant_id = self.project_id

        # create a default user for this plugin
        self.core_plugin.create_project_plugin_map(self.context,
                {'project_plugin_map': {'plugin': self.plugin_type,
                                        'project': self.project_id}})
        self.sub_plugin = self.core_plugin.get_plugin_by_type(self.plugin_type)

    @property
    def project_id(self):
        pass

    @property
    def plugin_type(self):
        pass

    def _test_plugin_initialized(self):
        self.assertTrue(self.core_plugin.is_tvd_plugin())
        self.assertIsNotNone(self.sub_plugin)

    def _test_call_create(self, obj_name, calls_count=1):
        method_name = 'create_%s' % obj_name
        func_to_call = getattr(self.core_plugin, method_name)

        with mock.patch.object(self.sub_plugin, method_name) as sub_func:
            func_to_call(self.context,
                         {obj_name: {'tenant_id': self.project_id}})
            self.assertEqual(calls_count, sub_func.call_count)

    def _test_call_create_with_net_id(self, obj_name, field_name='network_id',
                                      calls_count=1):
        method_name = 'create_%s' % obj_name
        func_to_call = getattr(self.core_plugin, method_name)
        net_id = _uuid()

        with mock.patch.object(self.sub_plugin, method_name) as sub_func,\
            mock.patch.object(self.core_plugin, '_get_network',
                              return_value={'tenant_id': self.project_id}):
            func_to_call(self.context,
                         {obj_name: {'tenant_id': self.project_id,
                                     field_name: net_id}})
            self.assertEqual(calls_count, sub_func.call_count)


class TestPluginWithNsxv(NsxTVDPluginTestCase):

    @property
    def project_id(self):
        return 'project_v'

    @property
    def plugin_type(self):
        return 'nsx-v'

    def test_plugin_initialized(self):
        self._test_plugin_initialized()

        # no unsupported extensions for the nsx_v plugin
        self.assertEqual(
            [],
            self.core_plugin._unsupported_fields[self.plugin_type]['router'])
        self.assertEqual(
            [],
            self.core_plugin._unsupported_fields[self.plugin_type]['port'])

    def test_create_network(self):
        self._test_call_create('network')

    def test_create_subnet(self):
        self._test_call_create_with_net_id('subnet')

    def test_create_port(self):
        self._test_call_create_with_net_id('port')

    def test_create_router(self):
        self._test_call_create('router')

    def test_create_floatingip(self):
        self._test_call_create_with_net_id(
            'floatingip', field_name='floating_network_id')

    def test_create_security_group(self):
        # plugin will be called twice because of the default sg
        self._test_call_create('security_group', calls_count=2)


class TestPluginWithNsxt(NsxTVDPluginTestCase):

    @property
    def project_id(self):
        return 'project_t'

    @property
    def plugin_type(self):
        return 'nsx-t'

    def test_plugin_initialized(self):
        self._test_plugin_initialized()

        # no unsupported extensions for the nsx_t plugin
        self.assertItemsEqual(
            ['router_type', 'router_size'],
            self.core_plugin._unsupported_fields[self.plugin_type]['router'])
        self.assertEqual(
            [],
            self.core_plugin._unsupported_fields[self.plugin_type]['port'])

    def test_create_network(self):
        self._test_call_create('network')

    def test_create_subnet(self):
        self._test_call_create_with_net_id('subnet')

    def test_create_port(self):
        self._test_call_create_with_net_id('port')

    def test_create_router(self):
        self._test_call_create('router')

    def test_create_floatingip(self):
        self._test_call_create_with_net_id(
            'floatingip', field_name='floating_network_id')

    def test_create_security_group(self):
        # plugin will be called twice because of the default sg
        self._test_call_create('security_group', calls_count=2)


class TestPluginWithDvs(NsxTVDPluginTestCase):

    @property
    def project_id(self):
        return 'project_dvs'

    @property
    def plugin_type(self):
        return 'dvs'

    def test_plugin_initialized(self):
        self._test_plugin_initialized()

        # no unsupported extensions for the dvs plugin
        self.assertEqual(
            ['mac_learning_enabled'],
            self.core_plugin._unsupported_fields[self.plugin_type]['port'])

    def test_create_network(self):
        self._test_call_create('network')

    def test_create_subnet(self):
        self._test_call_create_with_net_id('subnet')

    def test_create_port(self):
        self._test_call_create_with_net_id('port')

    def test_create_router(self):
        self._test_call_create('router')

    def test_create_floatingip(self):
        self._test_call_create_with_net_id(
            'floatingip', field_name='floating_network_id')

    def test_create_security_group(self):
        # plugin will be called twice because of the default sg
        self._test_call_create('security_group', calls_count=2)

    #TODO(asarfaty): router is not supported by the dvs plugin
