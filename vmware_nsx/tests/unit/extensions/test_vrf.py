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
from neutron.extensions import l3
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin

from vmware_nsx.extensions import vrf
from vmware_nsx.tests.unit.nsx_v3 import test_plugin


_uuid = uuidutils.generate_uuid


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

    def _add_external_gateway_to_router(self, router_id, network_id,
                                        expected_code=exc.HTTPOk.code,
                                        neutron_context=None, ext_ips=None,
                                        vrf_id=None):
        ext_ips = ext_ips or []
        body = {'router':
                {'external_gateway_info': {'network_id': network_id}}}
        if ext_ips:
            body['router']['external_gateway_info'][
                'external_fixed_ips'] = ext_ips
        if vrf_id:
            body['router']['external_gateway_info']['vrf_id'] = vrf_id
        return self._update('routers', router_id, body,
                            expected_code=expected_code,
                            neutron_context=neutron_context)

    def test_router_add_gateway_with_vrf(self):
        with mock.patch(
            'vmware_nsx.plugins.nsx_v3.plugin.NsxV3Plugin._get_edge_cluster',
            return_value=_uuid()):
            with self.router() as router:
                with self._create_l3_ext_network() as network:
                    with self.subnet(network=network) as subnet:
                        vrf_id = _uuid()
                        self._add_external_gateway_to_router(
                            router['router']['id'],
                            subnet['subnet']['network_id'],
                            vrf_id=vrf_id)
                        body = self._show('routers', router['router']['id'])
                        self.assertEqual(vrf_id, body['router'][
                            'external_gateway_info']['vrf_id'])
