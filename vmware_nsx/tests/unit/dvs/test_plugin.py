# Copyright (c) 2014 VMware.
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
from oslo_utils import uuidutils

from neutron.common import exceptions as exp
from neutron import context
from neutron.extensions import portbindings
from neutron import manager
from neutron.tests import base
import neutron.tests.unit.db.test_db_base_plugin_v2 as test_plugin
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.dvs import dvs
from vmware_nsx.dvs import dvs_utils

PLUGIN_NAME = 'vmware_nsx.plugin.NsxDvsPlugin'


class fake_session(object):
    def __init__(self, *ret):
        self._vim = mock.Mock()

    def invoke_api(self, *args, **kwargs):
        pass

    def wait_for_task(self, task):
        pass

    def vim(self):
        return self._vim


class DvsTestCase(base.BaseTestCase):

    @mock.patch.object(dvs_utils, 'dvs_create_session',
                       return_value=fake_session())
    @mock.patch.object(dvs.DvsManager, '_get_dvs_moref',
                       return_value='dvs-moref')
    def setUp(self, mock_moref, mock_session):
        super(DvsTestCase, self).setUp()
        cfg.CONF.set_override('dvs_name', 'fake_dvs', group='dvs')
        self._dvs = dvs.DvsManager()
        self.assertEqual('dvs-moref', self._dvs._dvs_moref)
        mock_moref.assert_called_once_with(mock_session.return_value,
                                           'fake_dvs')

    @mock.patch.object(dvs_utils, 'dvs_create_session',
                       return_value=fake_session())
    def test_dvs_not_found(self, mock_session):
        self.assertRaises(nsx_exc.DvsNotFound,
                          dvs.DvsManager)

    @mock.patch.object(dvs.DvsManager, '_get_port_group_spec',
                       return_value='fake-spec')
    def test_add_port_group(self, fake_get_spec):
        self._dvs.add_port_group('fake-uuid', 7)
        fake_get_spec.assert_called_once_with('fake-uuid', 7)

    @mock.patch.object(dvs.DvsManager, '_get_port_group_spec',
                       return_value='fake-spec')
    def test_add_port_group_with_exception(self, fake_get_spec):
        with (
            mock.patch.object(self._dvs._session, 'wait_for_task',
                              side_effect=exp.NeutronException())
        ):
            self.assertRaises(exp.NeutronException,
                              self._dvs.add_port_group,
                              'fake-uuid', 7)
            fake_get_spec.assert_called_once_with('fake-uuid', 7)

    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref',
                       return_value='fake-moref')
    def test_delete_port_group(self, fake_get_moref):
        self._dvs.delete_port_group('fake-uuid')
        fake_get_moref.assert_called_once_with('fake-uuid')

    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref',
                       return_value='fake-moref')
    def test_delete_port_group_with_exception(self, fake_get_moref):
        with (
            mock.patch.object(self._dvs._session, 'wait_for_task',
                              side_effect=exp.NeutronException())
        ):
            self.assertRaises(exp.NeutronException,
                              self._dvs.delete_port_group,
                              'fake-uuid')
            fake_get_moref.assert_called_once_with('fake-uuid')


class NeutronSimpleDvsTest(test_plugin.NeutronDbPluginV2TestCase):

    @mock.patch.object(dvs_utils, 'dvs_create_session',
                       return_value=fake_session())
    @mock.patch.object(dvs.DvsManager, '_get_dvs_moref',
                       return_value='dvs-moref')
    def setUp(self, mock_moref, mock_session,
              plugin=PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        # Ensure that DVS is enabled
        cfg.CONF.set_override('host_ip', 'fake_ip', group='dvs')
        cfg.CONF.set_override('host_username', 'fake_user', group='dvs')
        cfg.CONF.set_override('host_password', 'fake_password', group='dvs')
        cfg.CONF.set_override('dvs_name', 'fake_dvs', group='dvs')
        super(NeutronSimpleDvsTest, self).setUp(plugin=PLUGIN_NAME)
        self._plugin = manager.NeutronManager.get_plugin()

    def _create_and_delete_dvs_network(self, network_type='flat', vlan_tag=0):
        params = {'provider:network_type': network_type}
        if network_type == 'vlan':
            params['provider:segmentation_id'] = vlan_tag
        params['arg_list'] = tuple(params.keys())
        with mock.patch.object(self._plugin._dvs,
                               'add_port_group') as mock_add,\
                mock.patch.object(self._plugin._dvs, 'delete_port_group'):
            with self.network(**params) as network:
                ctx = context.get_admin_context()
                id = network['network']['id']
                dvs_id = '%s-%s' % (network['network']['name'], id)
                binding = nsx_db.get_network_bindings(ctx.session, id)
                self.assertIsNotNone(binding)
                self.assertEqual('dvs', binding[0].phy_uuid)
                if network_type == 'flat':
                    self.assertEqual('flat', binding[0].binding_type)
                    self.assertEqual(0, binding[0].vlan_id)
                elif network_type == 'vlan':
                    self.assertEqual('vlan', binding[0].binding_type)
                    self.assertEqual(vlan_tag, binding[0].vlan_id)
                else:
                    self.fail()
            mock_add.assert_called_once_with(dvs_id, vlan_tag)

    def test_create_and_delete_dvs_network_tag(self):
        self._create_and_delete_dvs_network(network_type='vlan', vlan_tag=7)

    def test_create_and_delete_dvs_network_flat(self):
        self._create_and_delete_dvs_network()

    def test_create_and_delete_dvs_port(self):
        params = {'provider:network_type': 'vlan',
                  'provider:physical_network': 'dvs',
                  'provider:segmentation_id': 7}
        params['arg_list'] = tuple(params.keys())
        with mock.patch.object(self._plugin._dvs, 'add_port_group'),\
                mock.patch.object(self._plugin._dvs, 'delete_port_group'):
            with self.network(**params) as network,\
                    self.subnet(network) as subnet,\
                    self.port(subnet) as port:
                self.assertEqual('dvs',
                                 port['port'][portbindings.VIF_TYPE])
                port_status = port['port']['status']
                self.assertEqual(port_status, 'ACTIVE')

    def test_create_router_only_dvs_backend(self):
        data = {'router': {'tenant_id': 'whatever'}}
        data['router']['name'] = 'router1'
        data['router']['external_gateway_info'] = {'network_id': 'whatever'}
        self.assertRaises(exp.BadRequest,
                          self._plugin.create_router,
                          context.get_admin_context(),
                          data)

    def test_dvs_get_id(self):
        id = uuidutils.generate_uuid()
        net = {'name': '',
               'id': id}
        expected = id
        self.assertEqual(expected, self._plugin._dvs_get_id(net))
        net = {'name': 'pele',
               'id': id}
        expected = '%s-%s' % ('pele', id)
        self.assertEqual(expected, self._plugin._dvs_get_id(net))
        name = 'X' * 500
        net = {'name': name,
               'id': id}
        expected = '%s-%s' % (name[:43], id)
        self.assertEqual(expected, self._plugin._dvs_get_id(net))
