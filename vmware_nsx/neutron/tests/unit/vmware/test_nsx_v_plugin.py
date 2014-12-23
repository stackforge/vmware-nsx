# Copyright (c) 2012 OpenStack Foundation.
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

import contextlib
from eventlet import greenthread
import mock
from oslo.config import cfg
import webob.exc

from neutron.api.v2 import attributes
from neutron.common import constants
import neutron.common.test_lib as test_lib
from neutron import context
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import l3_ext_gw_mode
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as secgrp
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.tests.unit import _test_extension_portbindings as test_bindings
import neutron.tests.unit.test_db_plugin as test_plugin
import neutron.tests.unit.test_extension_allowedaddresspairs as test_addr_pair
import neutron.tests.unit.test_extension_ext_gw_mode as test_ext_gw_mode
import neutron.tests.unit.test_extension_security_group as ext_sg
import neutron.tests.unit.test_l3_plugin as test_l3_plugin
from neutron.tests.unit import testlib_api
from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_db
from vmware_nsx.neutron.plugins.vmware.extensions import (
    distributedrouter as dist_router)
from vmware_nsx.neutron.plugins.vmware.extensions import (
    vnic_index as ext_vnic_idx)
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    constants as vcns_const)
from vmware_nsx.neutron.plugins.vmware.vshield import edge_utils
from vmware_nsx.neutron.tests.unit import vmware
from vmware_nsx.neutron.tests.unit.vmware.extensions import test_vnic_index
from vmware_nsx.neutron.tests.unit.vmware.vshield import fake_vcns

PLUGIN_NAME = 'vmware_nsx.neutron.plugins.vmware.plugin.NsxVPlugin'

_uuid = uuidutils.generate_uuid


class NsxVPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

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

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        test_lib.test_config['config_files'] = [
            vmware.get_fake_conf('nsx.ini.test')]
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc2 = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc2
        edge_utils.query_dhcp_service_config = mock.Mock(return_value=[])
        self.mock_create_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'create_dhcp_edge_service'))
        self.mock_create_dhcp_service.start()
        mock_update_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'update_dhcp_edge_service'))
        mock_update_dhcp_service.start()
        mock_delete_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'delete_dhcp_edge_service'))
        mock_delete_dhcp_service.start()
        super(NsxVPluginV2TestCase, self).setUp(plugin=plugin,
                                                ext_mgr=ext_mgr)
        self.addCleanup(self.fc2.reset_all)

    def test_get_vlan_network_name(self):
        p = manager.NeutronManager.get_plugin()
        id = uuidutils.generate_uuid()
        net = {'name': '',
               'id': id}
        expected = id
        self.assertEqual(expected,
                         p._get_vlan_network_name(net))
        net = {'name': 'pele',
               'id': id}
        expected = '%s-%s' % ('pele', id)
        self.assertEqual(expected,
                         p._get_vlan_network_name(net))
        name = 'X' * 500
        net = {'name': name,
               'id': id}
        expected = '%s-%s' % (name[:43], id)
        self.assertEqual(expected,
                         p._get_vlan_network_name(net))


class TestNetworksV2(test_plugin.TestNetworksV2, NsxVPluginV2TestCase):

    def _test_create_bridge_network(self, vlan_id=0):
        net_type = vlan_id and 'vlan' or 'flat'
        name = 'bridge_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, net_type),
                    (pnet.PHYSICAL_NETWORK, 'tzuuid'),
                    (pnet.SEGMENTATION_ID, vlan_id)]
        providernet_args = {pnet.NETWORK_TYPE: net_type,
                            pnet.PHYSICAL_NETWORK: 'tzuuid'}
        if vlan_id:
            providernet_args[pnet.SEGMENTATION_ID] = vlan_id
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    pnet.SEGMENTATION_ID)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_bridge_network(self):
        self._test_create_bridge_network()

    def test_create_bridge_vlan_network(self):
        self._test_create_bridge_network(vlan_id=123)

    def test_create_bridge_vlan_network_outofrange_returns_400(self):
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_bridge_network(vlan_id=5000)
        self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_external_portgroup_network(self):
        name = 'ext_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (external_net.EXTERNAL, True),
                    (pnet.NETWORK_TYPE, 'portgroup'),
                    (pnet.PHYSICAL_NETWORK, 'tzuuid')]
        providernet_args = {pnet.NETWORK_TYPE: 'portgroup',
                            pnet.PHYSICAL_NETWORK: 'tzuuid',
                            external_net.EXTERNAL: True}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK,
                                    external_net.EXTERNAL)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_delete_network_after_removing_subnet(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        fmt = 'json'
        # Create new network
        res = self._create_network(fmt=fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(fmt, res)
        subnet = self._make_subnet(fmt, network, gateway_ip,
                                   cidr, ip_version=4)
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        sub_del_res = req.get_response(self.api)
        self.assertEqual(sub_del_res.status_int, 204)
        req = self.new_delete_request('networks', network['network']['id'])
        net_del_res = req.get_response(self.api)
        self.assertEqual(net_del_res.status_int, 204)

    def test_list_networks_with_shared(self):
        with self.network(name='net1'):
            with self.network(name='net2', shared=True):
                req = self.new_list_request('networks')
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(len(res['networks']), 2)
                req_2 = self.new_list_request('networks')
                req_2.environ['neutron.context'] = context.Context('',
                                                                   'somebody')
                res = self.deserialize('json', req_2.get_response(self.api))
                # tenant must see a single network
                self.assertEqual(len(res['networks']), 1)

    def test_create_network_name_exceeds_40_chars(self):
        name = 'this_is_a_network_whose_name_is_longer_than_40_chars'
        with self.network(name=name) as net:
            # Assert neutron name is not truncated
            self.assertEqual(net['network']['name'], name)

    def test_update_network_with_admin_false(self):
        data = {'network': {'admin_state_up': False}}
        with self.network() as net:
            plugin = manager.NeutronManager.get_plugin()
            self.assertRaises(NotImplementedError,
                              plugin.update_network,
                              context.get_admin_context(),
                              net['network']['id'], data)

    def test_create_extend_dvs_provider_network(self):
        name = 'provider_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, 'flat'),
                    (pnet.PHYSICAL_NETWORK, 'dvs-uuid')]
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_same_vlan_network_with_different_dvs(self):
        name = 'dvs-provider-net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (pnet.NETWORK_TYPE, 'vlan'),
                    (pnet.SEGMENTATION_ID, 43),
                    (pnet.PHYSICAL_NETWORK, 'dvs-uuid-1')]
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 43,
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid-1'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.SEGMENTATION_ID,
                                    pnet.PHYSICAL_NETWORK)) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

            expected_same_vlan = [(pnet.NETWORK_TYPE, 'vlan'),
                                  (pnet.SEGMENTATION_ID, 43),
                                  (pnet.PHYSICAL_NETWORK, 'dvs-uuid-2')]
            providernet_args_1 = {pnet.NETWORK_TYPE: 'vlan',
                                  pnet.SEGMENTATION_ID: 43,
                                  pnet.PHYSICAL_NETWORK: 'dvs-uuid-2'}
            with self.network(name=name,
                              providernet_args=providernet_args_1,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.SEGMENTATION_ID,
                                        pnet.PHYSICAL_NETWORK)) as net1:
                for k, v in expected_same_vlan:
                    self.assertEqual(net1['network'][k], v)


class TestVnicIndex(NsxVPluginV2TestCase,
                    test_vnic_index.VnicIndexDbTestCase):
    def test_update_port_twice_with_the_same_index(self):
        """Tests that updates which does not modify the port vnic
        index association do not produce any errors
        """
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                res = self._port_index_update(port['port']['id'], 2)
                self.assertEqual(2, res['port'][ext_vnic_idx.VNIC_INDEX])
                res = self._port_index_update(port['port']['id'], 2)
                self.assertEqual(2, res['port'][ext_vnic_idx.VNIC_INDEX])


class TestPortsV2(NsxVPluginV2TestCase,
                  test_plugin.TestPortsV2,
                  test_bindings.PortBindingsTestCase,
                  test_bindings.PortBindingsHostTestCaseMixin,
                  test_bindings.PortBindingsVnicTestCaseMixin):

    VIF_TYPE = portbindings.VIF_TYPE_DVS
    HAS_PORT_FILTER = True

    def test_update_port_delete_ip(self):
        # This test case overrides the default because the nsx plugin
        # implements port_security/security groups and it is not allowed
        # to remove an ip address from a port unless the security group
        # is first removed.
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'admin_state_up': False,
                                 'fixed_ips': [],
                                 secgrp.SECURITYGROUPS: []}}
                req = self.new_update_request('ports',
                                              data, port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(res['port']['admin_state_up'],
                                 data['port']['admin_state_up'])
                self.assertEqual(res['port']['fixed_ips'],
                                 data['port']['fixed_ips'])

    def test_update_port_index(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                self.assertIsNone(port['port']['vnic_index'])
                data = {'port': {'vnic_index': 1}}
                req = self.new_update_request('ports',
                                              data, port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(1, res['port']['vnic_index'])

    def test_update_port_with_compute_device_owner(self):
        """
        Test that DHCP binding is created when ports 'device_owner'
        is updated to compute, for example when attaching an interface to a
        instance with existing port.
        """
        with self.port() as port:
            with mock.patch(PLUGIN_NAME + '._create_dhcp_static_binding') as (
                    _create_dhcp_static_binding_mock):
                update = {'port': {'device_owner'}}
                self.new_update_request('ports',
                                        update, port['port']['id'])
                _create_dhcp_static_binding_mock.assert_called_once()


class TestSubnetsV2(NsxVPluginV2TestCase,
                    test_plugin.TestSubnetsV2):

    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        super(TestSubnetsV2, self).setUp()
        self.context = context.get_admin_context()

    def test_create_subnet_ipv6_attributes(self):
        # Expected to fail for now as we dont't support IPv6 for NSXv
        cidr = "fe80::/80"
        with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
            self._test_create_subnet(cidr=cidr)
            self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_subnet_with_different_dhcp_server(self):
        self.mock_create_dhcp_service.stop()
        name = 'dvs-provider-net'
        providernet_args = {pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 43,
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.SEGMENTATION_ID,
                                    pnet.PHYSICAL_NETWORK)) as net:
            self._test_create_subnet(network=net, cidr='10.0.0.0/24')
            dhcp_router_id = (vcns_const.DHCP_EDGE_PREFIX +
                              net['network']['id'])[:36]
            dhcp_server_id = nsxv_db.get_vcns_router_binding(
                self.context.session, dhcp_router_id)['edge_id']
            providernet_args_1 = {pnet.NETWORK_TYPE: 'vlan',
                                  pnet.SEGMENTATION_ID: 43,
                                  pnet.PHYSICAL_NETWORK: 'dvs-uuid-1'}
            with self.network(name=name,
                              providernet_args=providernet_args_1,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.SEGMENTATION_ID,
                                        pnet.PHYSICAL_NETWORK)) as net1:
                self._test_create_subnet(network=net1, cidr='10.0.1.0/24')
                router_id = (vcns_const.DHCP_EDGE_PREFIX +
                             net1['network']['id'])[:36]
                dhcp_server_id_1 = nsxv_db.get_vcns_router_binding(
                    self.context.session, router_id)['edge_id']
                self.assertNotEqual(dhcp_server_id, dhcp_server_id_1)

    def test_create_subnet_with_different_dhcp_by_flat_net(self):
        self.mock_create_dhcp_service.stop()
        name = 'flat-net'
        providernet_args = {pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
        with self.network(name=name,
                          providernet_args=providernet_args,
                          arg_list=(pnet.NETWORK_TYPE,
                                    pnet.PHYSICAL_NETWORK)) as net:
            self._test_create_subnet(network=net, cidr='10.0.0.0/24')
            dhcp_router_id = (vcns_const.DHCP_EDGE_PREFIX +
                              net['network']['id'])[:36]
            dhcp_server_id = nsxv_db.get_vcns_router_binding(
                self.context.session, dhcp_router_id)['edge_id']
            providernet_args_1 = {pnet.NETWORK_TYPE: 'flat',
                                  pnet.PHYSICAL_NETWORK: 'dvs-uuid'}
            with self.network(name=name,
                              providernet_args=providernet_args_1,
                              arg_list=(pnet.NETWORK_TYPE,
                                        pnet.PHYSICAL_NETWORK)) as net1:
                self._test_create_subnet(network=net1, cidr='10.0.1.0/24')
                router_id = (vcns_const.DHCP_EDGE_PREFIX +
                             net1['network']['id'])[:36]
                dhcp_server_id_1 = nsxv_db.get_vcns_router_binding(
                    self.context.session, router_id)['edge_id']
                self.assertNotEqual(dhcp_server_id, dhcp_server_id_1)


class TestBasicGet(test_plugin.TestBasicGet, NsxVPluginV2TestCase):
    pass


class TestV2HTTPResponse(test_plugin.TestV2HTTPResponse, NsxVPluginV2TestCase):
    pass


class TestL3ExtensionManager(object):

    def get_resources(self):
        # Simulate extension of L3 attribute map
        # First apply attribute extensions
        for key in l3.RESOURCE_ATTRIBUTE_MAP.keys():
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                l3_ext_gw_mode.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                dist_router.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
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
                (res, attrs) in l3.RESOURCE_ATTRIBUTE_MAP.iteritems())


def restore_l3_attribute_map(map_to_restore):
    """Ensure changes made by fake ext mgrs are reverted."""
    l3.RESOURCE_ATTRIBUTE_MAP = map_to_restore


class L3NatTest(test_l3_plugin.L3BaseForIntTests, NsxVPluginV2TestCase):

    def _restore_l3_attribute_map(self):
        l3.RESOURCE_ATTRIBUTE_MAP = self._l3_attribute_map_bk

    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None, service_plugins=None):
        self._l3_attribute_map_bk = {}
        for item in l3.RESOURCE_ATTRIBUTE_MAP:
            self._l3_attribute_map_bk[item] = (
                l3.RESOURCE_ATTRIBUTE_MAP[item].copy())
        cfg.CONF.set_override('task_status_check_interval', 200, group="nsxv")

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

    def tearDown(self):
        plugin = manager.NeutronManager.get_plugin()
        _manager = plugin.nsx_v.task_manager
        # wait max ~10 seconds for all tasks to be finished
        for i in range(100):
            if not _manager.has_pending_task():
                break
            greenthread.sleep(0.1)
        if _manager.has_pending_task():
            _manager.show_pending_tasks()
            raise Exception(_("Tasks not completed"))
        _manager.stop()
        # Ensure the manager thread has been stopped
        self.assertIsNone(_manager._thread)
        super(L3NatTest, self).tearDown()

    def _create_l3_ext_network(self, vlan_id=None):
        name = 'l3_ext_net'
        return self.network(name=name,
                            router__external=True)

    @contextlib.contextmanager
    def router(self, name=None, admin_state_up=True,
               fmt=None, tenant_id=_uuid(),
               external_gateway_info=None, set_context=False,
               **kwargs):
        # avoid name duplication of edge
        if not name:
            name = _uuid()
        router = self._make_router(fmt or self.fmt, tenant_id, name,
                                   admin_state_up, external_gateway_info,
                                   set_context, **kwargs)
        yield router
        self._delete('routers', router['router']['id'])


class TestL3NatTestCase(L3NatTest,
                        test_l3_plugin.L3NatDBIntTestCase,
                        NsxVPluginV2TestCase):

    def _test_create_l3_ext_network(self, vlan_id=0):
        name = 'l3_ext_net'
        expected = [('subnets', []), ('name', name), ('admin_state_up', True),
                    ('status', 'ACTIVE'), ('shared', False),
                    (external_net.EXTERNAL, True)]
        with self._create_l3_ext_network(vlan_id) as net:
            for k, v in expected:
                self.assertEqual(net['network'][k], v)

    def test_create_l3_ext_network_with_dhcp(self):
        with self._create_l3_ext_network() as net:
            with testlib_api.ExpectedException(
                webob.exc.HTTPClientError) as ctx_manager:
                with self.subnet(network=net):
                    self.assertEqual(ctx_manager.exception.code, 400)

    def test_create_l3_ext_network_without_vlan(self):
        self._test_create_l3_ext_network()

    def _test_router_create_with_gwinfo_and_l3_ext_net(self, vlan_id=None,
                                                       validate_ext_gw=False):
        with self._create_l3_ext_network(vlan_id) as net:
            with self.subnet(network=net, enable_dhcp=False) as s:
                data = {'router': {'tenant_id': 'whatever'}}
                data['router']['name'] = 'router1'
                data['router']['external_gateway_info'] = {
                    'network_id': s['subnet']['network_id']}
                router_req = self.new_create_request('routers', data,
                                                     self.fmt)
                try:
                    res = router_req.get_response(self.ext_api)
                    router = self.deserialize(self.fmt, res)
                    self.assertEqual(
                        s['subnet']['network_id'],
                        (router['router']['external_gateway_info']
                         ['network_id']))
                    if validate_ext_gw:
                        pass
                finally:
                    self._delete('routers', router['router']['id'])

    def test_router_create_with_gwinfo_and_l3_ext_net(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net()

    def test_router_create_with_gwinfo_and_l3_ext_net_with_vlan(self):
        self._test_router_create_with_gwinfo_and_l3_ext_net(444)

    def test_router_add_gateway_invalid_network_returns_404(self):
        # NOTE(salv-orlando): This unit test has been overriden
        # as the nsx plugin support the ext_gw_mode extension
        # which mandates a uuid for the external network identifier
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                uuidutils.generate_uuid(),
                expected_code=webob.exc.HTTPNotFound.code)

    def _test_router_update_gateway_on_l3_ext_net(self, vlan_id=None,
                                                  validate_ext_gw=False,
                                                  distributed=False):
        with self.router(
            arg_list=('distributed',), distributed=distributed) as r:
            with self.subnet() as s1:
                with self._create_l3_ext_network(vlan_id) as net:
                    with self.subnet(network=net, enable_dhcp=False) as s2:
                        self._set_net_external(s1['subnet']['network_id'])
                        try:
                            self._add_external_gateway_to_router(
                                r['router']['id'],
                                s1['subnet']['network_id'])
                            body = self._show('routers', r['router']['id'])
                            net_id = (body['router']
                                      ['external_gateway_info']['network_id'])
                            self.assertEqual(net_id,
                                             s1['subnet']['network_id'])
                            # Plug network with external mapping
                            self._set_net_external(s2['subnet']['network_id'])
                            self._add_external_gateway_to_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])
                            body = self._show('routers', r['router']['id'])
                            net_id = (body['router']
                                      ['external_gateway_info']['network_id'])
                            self.assertEqual(net_id,
                                             s2['subnet']['network_id'])
                            if validate_ext_gw:
                                pass
                        finally:
                            # Cleanup
                            self._remove_external_gateway_from_router(
                                r['router']['id'],
                                s2['subnet']['network_id'])

    def test_router_update_gateway_on_l3_ext_net(self):
        self._test_router_update_gateway_on_l3_ext_net()

    def test_router_update_gateway_on_l3_ext_net_with_vlan(self):
        self._test_router_update_gateway_on_l3_ext_net(444)

    def test_router_update_gateway_with_existing_floatingip(self):
        with self._create_l3_ext_network() as net:
            with self.subnet(network=net, enable_dhcp=False) as subnet:
                with self.floatingip_with_assoc() as fip:
                    self._add_external_gateway_to_router(
                        fip['floatingip']['router_id'],
                        subnet['subnet']['network_id'],
                        expected_code=webob.exc.HTTPConflict.code)

    def test_router_list_by_tenant_id(self):
        with contextlib.nested(self.router(tenant_id='custom'),
                               self.router(),
                               self.router()
                               ) as routers:
            self._test_list_resources('router', [routers[0]],
                                      query_params="tenant_id=custom")

    def test_create_l3_ext_network_with_vlan(self):
        self._test_create_l3_ext_network(666)

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(self._plugin_name)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_floatingip_update(self):
        super(TestL3NatTestCase, self).test_floatingip_update(
            constants.FLOATINGIP_STATUS_DOWN)

    def test_floatingip_disassociate(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                self.assertEqual(fip['floatingip']['status'],
                                 constants.FLOATINGIP_STATUS_DOWN)
                port_id = p['port']['id']
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                self.assertEqual(body['floatingip']['port_id'], port_id)
                self.assertEqual(body['floatingip']['status'],
                                 constants.FLOATINGIP_STATUS_ACTIVE)
                # Disassociate
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': None}})
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertIsNone(body['floatingip']['port_id'])
                self.assertIsNone(body['floatingip']['fixed_ip_address'])
                self.assertEqual(body['floatingip']['status'],
                                 constants.FLOATINGIP_STATUS_DOWN)

    def test_update_floatingip_with_edge_router_update_failure(self):
        p = manager.NeutronManager.get_plugin()
        with self.subnet() as subnet:
            with contextlib.nested(self.port(subnet=subnet),
                                   self.port(subnet=subnet)) as (p1, p2):
                p1_id = p1['port']['id']
                p2_id = p2['port']['id']
                with self.floatingip_with_assoc(port_id=p1_id) as fip:
                    with self._mock_edge_router_update_with_exception() as (
                            update_edge):
                        self.assertRaises(object,
                                          p.update_floatingip,
                                          context.get_admin_context(),
                                          fip['floatingip']['id'],
                                          floatingip={'floatingip':
                                                      {'port_id': p2_id}})
                        update_edge.assert_called_once()
                    res = self._list(
                        'floatingips', query_params="port_id=%s" % p1_id)
                    self.assertEqual(len(res['floatingips']), 1)
                    res = self._list(
                        'floatingips', query_params="port_id=%s" % p2_id)
                    self.assertEqual(len(res['floatingips']), 0)

    def test_create_floatingip_with_edge_router_update_failure(self):
        p = manager.NeutronManager.get_plugin()
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            public_network_id = public_sub['subnet']['network_id']
            self._set_net_external(public_network_id)
            with self.port() as private_port:
                port_id = private_port['port']['id']
                tenant_id = private_port['port']['tenant_id']
                subnet_id = private_port['port']['fixed_ips'][0]['subnet_id']
                with self.router() as r:
                    self._add_external_gateway_to_router(
                        r['router']['id'],
                        public_sub['subnet']['network_id'])
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  subnet_id,
                                                  None)
                    floatingip = {'floatingip': {
                                  'tenant_id': tenant_id,
                                  'floating_network_id': public_network_id,
                                  'port_id': port_id}}

                    with self._mock_edge_router_update_with_exception() as (
                            update_edge):
                        self.assertRaises(object,
                                          p.create_floatingip,
                                          context.get_admin_context(),
                                          floatingip=floatingip)
                        update_edge.assert_called_once()
                        res = self._list(
                            'floatingips', query_params="port_id=%s" % port_id)
                        self.assertEqual(len(res['floatingips']), 0)
                    # Cleanup
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  subnet_id,
                                                  None)
                    self._remove_external_gateway_from_router(
                        r['router']['id'], public_network_id)

    @contextlib.contextmanager
    def _mock_edge_router_update_with_exception(self):
        nsx_router_update = PLUGIN_NAME + '._update_edge_router'
        with mock.patch(nsx_router_update) as update_edge:
            update_edge.side_effect = object()
            yield update_edge

    def test_router_interfaces_with_update_firewall(self):
        with mock.patch.object(edge_utils, "update_firewall") as firewall:
            with self.router() as r:
                s1_cidr = '10.0.0.0/24'
                s2_cidr = '11.0.0.0/24'
                with contextlib.nested(
                    self.subnet(cidr=s1_cidr),
                    self.subnet(cidr=s2_cidr)) as (s1, s2):
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)
                    firewall.reset_mock()
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    expected_fw = {
                        'firewall_rule_list': [
                            {'action': 'allow',
                             'enabled': True,
                             'source_ip_address': [s1_cidr, s2_cidr],
                             'destination_ip_address': [s1_cidr, s2_cidr]}]}
                    firewall.assert_called_once_with(
                        mock.ANY, mock.ANY, mock.ANY,
                        expected_fw, allow_external=True)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)

    def test_router_interfaces_different_tenants_update_firewall(self):
        tenant_id = _uuid()
        other_tenant_id = _uuid()
        with mock.patch.object(edge_utils, "update_firewall") as firewall:
            with contextlib.nested(
                self.router(tenant_id=tenant_id),
                self.network(tenant_id=tenant_id),
                self.network(tenant_id=other_tenant_id)
            ) as (r, n1, n2):
                s1_cidr = '10.0.0.0/24'
                s2_cidr = '11.0.0.0/24'
                with contextlib.nested(
                    self.subnet(network=n1, cidr=s1_cidr),
                    self.subnet(network=n2, cidr=s2_cidr)
                ) as (s1, s2):
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    firewall.reset_mock()
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s1['subnet']['id'],
                                                  None,
                                                  tenant_id=tenant_id)
                    expected_fw = {
                        'firewall_rule_list': [
                            {'action': 'allow',
                             'enabled': True,
                             'source_ip_address': [s2_cidr, s1_cidr],
                             'destination_ip_address': [s2_cidr, s1_cidr]}]}
                    firewall.assert_called_once_with(
                        mock.ANY, mock.ANY, mock.ANY,
                        expected_fw, allow_external=True)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s1['subnet']['id'],
                                                  None,
                                                  tenant_id=tenant_id)
                    firewall.reset_mock()
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None)
                    expected_fw = {'firewall_rule_list': []}
                    firewall.assert_called_once_with(
                        mock.ANY, mock.ANY, mock.ANY,
                        expected_fw, allow_external=True)


class ExtGwModeTestCase(NsxVPluginV2TestCase,
                        test_ext_gw_mode.ExtGwModeIntTestCase):
    pass


class NsxVSecurityGroupsTestCase(ext_sg.SecurityGroupDBTestCase):
    def setUp(self,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        test_lib.test_config['config_files'] = [
            vmware.get_fake_conf('nsx.ini.test')]
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc2 = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc2
        edge_utils.query_dhcp_service_config = mock.Mock(return_value=[])
        mock_create_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'create_dhcp_edge_service'))
        mock_create_dhcp_service.start()
        mock_update_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'update_dhcp_edge_service'))
        mock_update_dhcp_service.start()
        mock_delete_dhcp_service = mock.patch("%s.%s" % (
            vmware.EDGE_MANAGE_NAME, 'delete_dhcp_edge_service'))
        mock_delete_dhcp_service.start()
        super(NsxVSecurityGroupsTestCase, self).setUp(plugin=plugin,
                                                      ext_mgr=ext_mgr)
        self.addCleanup(self.fc2.reset_all)


class NsxVTestSecurityGroup(ext_sg.TestSecurityGroups,
                            NsxVSecurityGroupsTestCase):
    def test_vnic_security_group_membership(self):
        self.fc2.add_member_to_security_group = (
            mock.Mock().add_member_to_security_group)
        self.fc2.remove_member_from_security_group = (
            mock.Mock().remove_member_from_security_group)
        nsx_sg_id = str(self.fc2._securitygroups['ids'])
        device_id = _uuid()
        port_index = 0
        # The expected vnic-id format by NsxV
        vnic_id = '%s.%03d' % (device_id, port_index)
        with self.port(device_id=device_id,
                       device_owner='compute:None') as port:
            data = {'port': {'vnic_index': port_index}}
            self.new_update_request('ports', data,
                                    port['port']['id']).get_response(self.api)
            # The vnic should be added as a member to the nsx-security-groups
            # which match the port security-groups
            (self.fc2.add_member_to_security_group
             .assert_called_once_with(nsx_sg_id, vnic_id))

        # The vnic should be removed from the nsx-security-groups which match
        # the deleted port security-groups
        #TODO(kobis): Port is not removed automatically
        # (self.fc2.remove_member_from_security_group
        #  .assert_called_once_with(nsx_sg_id, vnic_id))

    def test_delete_ext_net_with_disassociated_floating_ips(self):
        #TODO(kobis): unskip
        self.skipTest('external network with dhcp not supported')


class TestVdrTestCase(L3NatTest,
                      test_l3_plugin.L3NatDBIntTestCase,
                      NsxVPluginV2TestCase):

    def _create_router(self, fmt, tenant_id, name=None,
                       admin_state_up=None, set_context=False,
                       arg_list=None, **kwargs):
        data = {'router': {'tenant_id': tenant_id}}
        if name:
            data['router']['name'] = name
        if admin_state_up:
            data['router']['admin_state_up'] = admin_state_up
        for arg in (('admin_state_up', 'tenant_id') + (arg_list or ())):
            # Arg must be present and not empty
            if arg in kwargs and kwargs[arg]:
                data['router'][arg] = kwargs[arg]

        if 'distributed' in kwargs:
                data['router']['distributed'] = kwargs[arg]
        else:
                data['router']['distributed'] = True

        router_req = self.new_create_request('routers', data, fmt)
        if set_context and tenant_id:
            # create a specific auth context for this request
            router_req.environ['neutron.context'] = context.Context(
                '', tenant_id)

        return router_req.get_response(self.ext_api)

    def _test_router_create_with_distributed(self, dist_input, dist_expected,
                                             return_code=201):
        data = {'tenant_id': 'whatever'}
        data['name'] = 'router1'
        data['distributed'] = dist_input
        router_req = self.new_create_request(
            'routers', {'router': data}, self.fmt)
        try:
            res = router_req.get_response(self.ext_api)
            self.assertEqual(return_code, res.status_int)
            if res.status_int == 201:
                router = self.deserialize(self.fmt, res)
                self.assertIn('distributed', router['router'])
                self.assertEqual(dist_expected,
                                 router['router']['distributed'])
        finally:
            if res.status_int == 201:
                self._delete('routers', router['router']['id'])

    def test_router_create_distributed(self):
        self._test_router_create_with_distributed(True, True)

    def test_router_create_not_distributed(self):
        self._test_router_create_with_distributed(False, False)

    def test_router_create_distributed_unspecified(self):
        self._test_router_create_with_distributed(None, False)

    def test_floatingip_with_assoc_fails(self):
        self._test_floatingip_with_assoc_fails(self._plugin_name)

    def test_floatingip_update(self):
        super(TestVdrTestCase, self).test_floatingip_update(
            constants.FLOATINGIP_STATUS_DOWN)

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)

    def test_router_add_gateway_invalid_network_returns_404(self):
        with self.router() as r:
            self._add_external_gateway_to_router(
                r['router']['id'],
                uuidutils.generate_uuid(),
                expected_code=webob.exc.HTTPNotFound.code)

    def test_router_add_interfaces_with_multiple_subnets_on_same_network(self):
        with self.router() as r:
            with self.network() as n:
                with contextlib.nested(
                    self.subnet(network=n),
                    self.subnet(network=n,
                                cidr='11.0.0.0/24')) as (s1, s2):
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)
                    err_code = webob.exc.HTTPBadRequest.code
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  s2['subnet']['id'],
                                                  None,
                                                  err_code)
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  s1['subnet']['id'],
                                                  None)

    def test_delete_ext_net_with_disassociated_floating_ips(self):
        #TODO(kobis): unskip
        self.skipTest('external network with dhcp not supported')


class TestNSXvAllowedAddressPairs(test_addr_pair.TestAllowedAddressPairs,
                                  NsxVPluginV2TestCase):
    def test_get_vlan_network_name(self):
        pass
