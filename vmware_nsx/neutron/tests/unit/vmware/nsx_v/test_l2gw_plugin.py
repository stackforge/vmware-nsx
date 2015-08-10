# Copyright 2015 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import contextlib
import mock

from neutron.common import exceptions as n_exc
from neutron import context
from neutron.tests import base

from networking_l2gw.db.l2gateway import l2gateway_db
from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_db
from vmware_nsx.neutron.services.l2gateway import nsx_v_driver


class TestL2gatewayDriver(base.BaseTestCase):

    def setUp(self):
        super(TestL2gatewayDriver, self).setUp()
        self.context = context.get_admin_context()
        self.plugin = nsx_v_driver.NsxvL2GatewayDriver()
        self.plugin._vcns = mock.Mock()
        self.plugin._edge_manager = mock.Mock()

    def test_validate_device_with_multi_devices(self):
        fake_l2gw_dict = {"l2_gateway":
                          {"tenant_id": "fake__tenant_id",
                           "name": "fake_l2gw",
                           "devices": [{"interfaces":
                                        [{"name": "fake_inter"}],
                                        "device_name": "fake_dev"},
                                       {"interfaces":
                                        [{"name": "fake_inter_1"}],
                                        "device_name": "fake_dev_1"}]}}
        with mock.patch.object(l2gateway_db.L2GatewayMixin, '_admin_check'):
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_l2_gateway,
                              self.context, fake_l2gw_dict)

    def test_validate_interface_with_multi_interfaces(self):
        fake_l2gw_dict = {"l2_gateway":
                          {"tenant_id": "fake_tenant_id",
                           "name": "fake_l2gw",
                           "devices": [{"interfaces":
                                        [{"name": "fake_inter_1"},
                                         {"name": "fake_inter_2"}],
                                        "device_name": "fake_dev"}]}}
        with mock.patch.object(l2gateway_db.L2GatewayMixin, '_admin_check'):
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_l2_gateway,
                              self.context, fake_l2gw_dict)

    def test_validate_interface_with_invalid_interfaces(self):
        fake_l2gw_dict = {"l2_gateway":
                          {"tenant_id": "fake_tenant_id",
                           "name": "fake_l2gw",
                           "devices": [{"interfaces":
                                        [{"name": "fake_inter_1"}],
                                        "device_name": "fake_dev"}]}}
        with mock.patch.object(l2gateway_db.L2GatewayMixin, '_admin_check'):
            self.plugin._vcns.validate_network.return_value = False
            self.assertRaises(n_exc.InvalidInput,
                              self.plugin.create_l2_gateway,
                              self.context, fake_l2gw_dict)

    def test_create_l2_gateway(self):
        fake_l2gw_dict = {"l2_gateway":
                          {"tenant_id": "fake_teannt_id",
                           "name": "fake_l2gw",
                           "devices": [{"interfaces":
                                        [{"name": "fake_inter"}],
                                        "device_name": "fake_dev"}]}}
        fake_devices = [{"interfaces": [{"name": "fake_inter"}],
                         "device_name": "fake_dev"}]
        fake_interfaces = [{"name": "fake_inter"}]
        with contextlib.nested(
            mock.patch.object(l2gateway_db.L2GatewayMixin, '_admin_check'),
            mock.patch.object(self.plugin, '_validate_device_list'),
            mock.patch.object(self.plugin, '_validate_interface_list'),
            mock.patch.object(self.plugin, '_create_l2_gateway_edge',
                              return_value="fake_dev"),
            mock.patch.object(l2gateway_db.L2GatewayMixin,
                              'create_l2_gateway')
            ) as (_admin_check, val_dev, val_inter,
                  _create_l2gw_edge, create_l2gw):
            self.plugin.create_l2_gateway(self.context, fake_l2gw_dict)
            _admin_check.assert_called_with(self.context, 'CREATE')
            val_dev.assert_called_with(fake_devices)
            val_inter.assert_called_with(fake_interfaces)
            create_l2gw.assert_called_with(self.context, fake_l2gw_dict)

    def test_delete_l2_gateway_connection(self):
        fake_conn_dict = {'l2_gateway_id': 'fake_l2gw_id'}
        fake_device_dict = {'id': 'fake_dev_id',
                            'device_name': 'fake_dev_name'}

        with contextlib.nested(
            mock.patch.object(l2gateway_db.L2GatewayMixin,
                              '_admin_check',
                              return_value=True),
            mock.patch.object(l2gateway_db.L2GatewayMixin,
                              'get_l2_gateway_connection',
                              return_value=fake_conn_dict),
            mock.patch.object(l2gateway_db.L2GatewayMixin,
                              'delete_l2_gateway_connection'),
            mock.patch.object(self.plugin, '_get_device',
                              return_value=fake_device_dict)
            ) as (admin_check, get_con, del_conn,
                  get_devices):
            self.plugin.delete_l2_gateway_connection(self.context,
                                                     fake_conn_dict)
            admin_check.assert_called_with(self.context, 'DELETE')
            get_con.assert_called_with(self.context, fake_conn_dict)
            get_devices.assert_called_with(self.context, 'fake_l2gw_id')
            self.plugin._vcns.del_bridge.asert_called_with('fake_dev_name')
            del_conn.assert_called_with(self.context, fake_conn_dict)

    def test_delete_l2_gateway(self):
        fake_device_dict = {"id": "fake_dev_id",
                            "device_name": "fake_edge_name",
                            "l2_gateway_id": "fake_l2gw_id"}
        fake_rtr_binding = {"router_id": 'fake_router_id'}

        with contextlib.nested(
            mock.patch.object(self.plugin, '_get_device',
                              return_value=fake_device_dict),
            mock.patch.object(l2gateway_db.L2GatewayMixin,
                              '_admin_check',
                              return_value=True),
            mock.patch.object(nsxv_db,
                              'get_nsxv_router_binding_by_edge',
                              return_value=fake_rtr_binding),
            mock.patch.object(l2gateway_db.L2GatewayMixin,
                              'delete_l2_gateway')
            ) as (get_devices, admin_check, get_nsxv_router,
                  del_l2gw):
            self.plugin.delete_l2_gateway(self.context, 'fake_l2gw_id')
            admin_check.assert_called_with(self.context, 'DELETE')
            get_devices.assert_called_with(self.context, 'fake_l2gw_id')
            del_l2gw.assert_called_with(self.context, 'fake_l2gw_id')
            get_nsxv_router.assert_called_with(self.context.session,
                                               "fake_edge_name")
