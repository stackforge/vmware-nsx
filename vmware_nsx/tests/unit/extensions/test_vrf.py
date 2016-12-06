# Copyright (c) 2016 VMware, Inc.
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

import mock
from oslo_utils import uuidutils
from webob import exc

from neutron.api.v2 import attributes
from neutron import context
from neutron.extensions import l3
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin

from vmware_nsx.db import db as nsx_db
from vmware_nsx.extensions import vrf
from vmware_nsx.tests.unit.nsx_v3 import test_plugin


class TestVrfExtensionManager(object):

    def get_resources(self):
        for key in l3.RESOURCE_ATTRIBUTE_MAP.keys():
            l3.RESOURCE_ATTRIBUTE_MAP[key].update(
                vrf.EXTENDED_ATTRIBUTES_2_0.get(key, {}))
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            l3.RESOURCE_ATTRIBUTE_MAP)
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class NsxV3VrfTestCase(test_plugin.NsxV3PluginTestCaseMixin,
                       test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self, plugin=test_plugin.PLUGIN_NAME,
              ext_mgr=None,
              service_plugins=None):
        if not ext_mgr:
            ext_mgr = TestVrfExtensionManager()
        super(NsxV3VrfTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr,
                                           service_plugins=service_plugins)

    def _validate_update_router_with_vrf_id(self, router_id, router_data,
                                            vrf_id):
        with mock.patch(
            'vmware_nsxlib.v3.router.RouterLib.update_vrf') as update_vrf:
            self._update('routers', router_id, router_data,
                         expected_code=exc.HTTPOk.code, neutron_context=None)
            update_vrf.assert_called_once_with(mock.ANY, vrf_id)
            body = self._show('routers', router_id)
            self.assertEqual(vrf_id, body['router'].get(vrf.VRF_ID))
            vrf_id_in_db = nsx_db.get_neutron_vrf_id(
                context.get_admin_context().session, router_id)
            self.assertEqual(vrf_id, vrf_id_in_db)

    def test_update_router_with_vrf_id(self):
        with mock.patch(
            'vmware_nsx.plugins.nsx_v3.plugin.NsxV3Plugin._get_edge_cluster',
            return_value=uuidutils.generate_uuid()):
            with self.router() as router:
                with self._create_l3_ext_network() as network:
                    # Configure vrf_id when setting external network.
                    vrf_id = uuidutils.generate_uuid()
                    data = {'router': {
                        'external_gateway_info': {
                            'network_id': network['network']['id']},
                        vrf.VRF_ID: vrf_id}}
                    self._validate_update_router_with_vrf_id(
                        router['router']['id'], data, vrf_id)
                    # Remove vrf_id.
                    vrf_id = None
                    data = {'router': {vrf.NO_VRF: True}}
                    self._validate_update_router_with_vrf_id(
                        router['router']['id'], data, vrf_id)
