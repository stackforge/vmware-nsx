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
import six

from neutron.api.v2 import attributes
from neutron import context
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import l3_ext_gw_mode
from neutron.extensions import extraroute
from neutron.extensions import providernet as pnet
from neutron import manager
import neutron.tests.unit.db.test_db_base_plugin_v2 as test_plugin
import neutron.tests.unit.extensions.test_extraroute as test_ext_route
import neutron.tests.unit.extensions.test_l3 as test_l3_plugin
import neutron.tests.unit.extensions.test_l3_ext_gw_mode as test_ext_gw_mode
import neutron.tests.unit.extensions.test_securitygroup as ext_sg
from vmware_nsx.neutron.plugins.vmware.common import utils
from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib
from vmware_nsx.neutron.tests.unit import vmware
from vmware_nsx.neutron.tests.unit.vmware import nsx_v3_mocks

PLUGIN_NAME = ('vmware_nsx.neutron.plugins.vmware.'
               'plugins.nsx_v3_plugin.NsxV3Plugin')


class NsxPluginV3TestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(NsxPluginV3TestCase, self).setUp(plugin=plugin,
                                               ext_mgr=ext_mgr)
        cfg.CONF.set_override('nsx_manager', '1.2.3.4', 'nsx_v3')
        cfg.CONF.set_override('default_tier0_router_uuid',
                              nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID, 'nsx_v3')
        # Mock entire nsxlib methods as this is the best approach to perform
        # white-box testing on the plugin class
        # TODO(salv-orlando): supply unit tests for nsxlib.v3
        nsxlib.create_logical_switch = nsx_v3_mocks.create_logical_switch
        nsxlib.create_logical_port = nsx_v3_mocks.create_logical_port
        nsxlib.delete_logical_port = mock.Mock()
        nsxlib.delete_logical_switch = mock.Mock()
        self.v3_mock = nsx_v3_mocks.NsxV3Mock()
        nsxlib.get_edge_cluster = self.v3_mock.get_edge_cluster
        nsxlib.get_logical_router = self.v3_mock.get_logical_router

    def _create_network(self, fmt, name, admin_state_up,
                        arg_list=None, providernet_args=None, **kwargs):
        data = {'network': {'name': name,
                            'admin_state_up': admin_state_up,
                            'tenant_id': self._tenant_id}}
        # Fix to allow the router:external attribute and any other
        # attributes containing a colon to be passed with
        # a double underscore instead
        kwargs = dict((k.replace('__', ':'), v) for k, v in kwargs.items())
        if external_net.EXTERNAL in kwargs:
            arg_list = (external_net.EXTERNAL, ) + (arg_list or ())

        attrs = kwargs
        if providernet_args:
            attrs.update(providernet_args)
        for arg in (('admin_state_up', 'tenant_id', 'shared') +
                    (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['network'][arg] = kwargs[arg]
        network_req = self.new_create_request('networks', data, fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            network_req.environ['neutron.context'] = context.Context(
                '', kwargs['tenant_id'])
        return network_req.get_response(self.api)


class TestNetworksV2(test_plugin.TestNetworksV2, NsxPluginV3TestCase):
    pass


class TestPortsV2(test_plugin.TestPortsV2, NsxPluginV3TestCase):
    pass


class SecurityGroupsTestCase(ext_sg.SecurityGroupDBTestCase):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None):
        nsxlib.create_logical_switch = nsx_v3_mocks.create_logical_switch
        nsxlib.create_logical_port = nsx_v3_mocks.create_logical_port
        nsxlib.delete_logical_port = mock.Mock()
        nsxlib.delete_logical_switch = mock.Mock()
        cfg.CONF.set_override('default_tier0_router_uuid',
                              nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID, 'nsx_v3')

        super(SecurityGroupsTestCase, self).setUp(plugin=PLUGIN_NAME,
                                                  ext_mgr=ext_mgr)


class TestSecurityGroups(ext_sg.TestSecurityGroups, SecurityGroupsTestCase):
    pass


class TestL3ExtensionManager(object):

    def get_resources(self):
        # Simulate extension of L3 attribute map
        # First apply attribute extensions
        for key in l3.RESOURCE_ATTRIBUTE_MAP.keys():
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                l3_ext_gw_mode.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                extraroute.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
        # Finally add l3 resources to the global attribute map
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            l3.RESOURCE_ATTRIBUTE_MAP)
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


def backup_l3_attribute_map():
    """Return a backup of the original l3 attribute map."""
    return dict((res, attrs.copy()) for
                (res, attrs) in six.iteritems(l3.RESOURCE_ATTRIBUTE_MAP))


def restore_l3_attribute_map(map_to_restore):
    """Ensure changes made by fake ext mgrs are reverted."""
    l3.RESOURCE_ATTRIBUTE_MAP = map_to_restore


class L3NatTest(test_l3_plugin.L3BaseForIntTests, NsxPluginV3TestCase):

    def _restore_l3_attribute_map(self):
        l3.RESOURCE_ATTRIBUTE_MAP = self._l3_attribute_map_bk

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None,
              service_plugins=None):
        self._l3_attribute_map_bk = {}
        for item in l3.RESOURCE_ATTRIBUTE_MAP:
            self._l3_attribute_map_bk[item] = (
                l3.RESOURCE_ATTRIBUTE_MAP[item].copy())
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        l3_attribute_map_bk = backup_l3_attribute_map()
        self.addCleanup(restore_l3_attribute_map, l3_attribute_map_bk)
        ext_mgr = ext_mgr or TestL3ExtensionManager()
        super(L3NatTest, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        plugin_instance = manager.NeutronManager.get_plugin()
        self._plugin_name = "%s.%s" % (
            plugin_instance.__module__,
            plugin_instance.__class__.__name__)
        self._plugin_class = plugin_instance.__class__
        nsxlib.create_logical_port = self.v3_mock.create_logical_port
        nsxlib.create_logical_router = self.v3_mock.create_logical_router
        nsxlib.update_logical_router = self.v3_mock.update_logical_router
        nsxlib.delete_logical_router = self.v3_mock.delete_logical_router
        nsxlib.get_logical_router_port_by_ls_id = (
            self.v3_mock.get_logical_router_port_by_ls_id)
        nsxlib.create_logical_router_port = (
            self.v3_mock.create_logical_router_port)
        nsxlib.update_logical_router_port = (
            self.v3_mock.update_logical_router_port)
        nsxlib.delete_logical_router_port = (
            self.v3_mock.delete_logical_router_port)

    def _create_l3_ext_network(
        self, physical_network=nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID):
        name = 'l3_ext_net'
        net_type = utils.NetworkTypes.L3_EXT
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: physical_network}
        return self.network(name=name,
                            router__external=True,
                            providernet_args=providernet_args,
                            arg_list=(pnet.NETWORK_TYPE,
                                      pnet.PHYSICAL_NETWORK))


class TestL3NatTestCase(L3NatTest,
                        test_l3_plugin.L3NatDBIntTestCase,
                        NsxPluginV3TestCase):

    def _test_create_l3_ext_network(
        self, physical_network=nsx_v3_mocks.DEFAULT_TIER0_ROUTER_UUID):
        name = 'l3_ext_net'
        net_type = utils.NetworkTypes.L3_EXT
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (external_net.EXTERNAL, True),
                    (pnet.NETWORK_TYPE, net_type),
                    (pnet.PHYSICAL_NETWORK, physical_network)]
        with self._create_l3_ext_network(physical_network) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_l3_ext_network_with_default_tier0(self):
        self._test_create_l3_ext_network()


class ExtGwModeTestCase(L3NatTest,
                        test_ext_gw_mode.ExtGwModeIntTestCase):
    pass
