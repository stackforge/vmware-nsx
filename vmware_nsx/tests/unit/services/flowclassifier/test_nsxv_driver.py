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
import mock
from oslo_config import cfg
from oslo_utils import importutils

from vmware_nsx.services.flowclassifier.nsx_v import driver as nsx_v_driver
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.nsx_v.vshield import fake_vcns

from neutron.api import extensions as api_ext
from neutron.common import config
from neutron import context
from neutron.extensions import portbindings

from networking_sfc.db import flowclassifier_db as fdb
from networking_sfc.extensions import flowclassifier
from networking_sfc.services.flowclassifier.common import context as fc_ctx
from networking_sfc.services.flowclassifier.common import exceptions as fc_exc
from networking_sfc.tests import base
from networking_sfc.tests.unit.db import test_flowclassifier_db


class TestNsxvFlowClassifierDriver(
    test_flowclassifier_db.FlowClassifierDbPluginTestCaseBase,
    base.NeutronDbPluginV2TestCase):

    resource_prefix_map = dict([
        (k, flowclassifier.FLOW_CLASSIFIER_PREFIX)
        for k in flowclassifier.RESOURCE_ATTRIBUTE_MAP.keys()
    ])

    def setUp(self):
        # init the flow classifier plugin
        flowclassifier_plugin = (
            test_flowclassifier_db.DB_FLOWCLASSIFIER_PLUGIN_CLASS)

        service_plugins = {
            flowclassifier.FLOW_CLASSIFIER_EXT: flowclassifier_plugin
        }
        fdb.FlowClassifierDbPlugin.supported_extension_aliases = [
            flowclassifier.FLOW_CLASSIFIER_EXT]
        fdb.FlowClassifierDbPlugin.path_prefix = (
            flowclassifier.FLOW_CLASSIFIER_PREFIX
        )

        super(TestNsxvFlowClassifierDriver, self).setUp(
            ext_mgr=None,
            plugin=None,
            service_plugins=service_plugins
        )

        self.flowclassifier_plugin = importutils.import_object(
            flowclassifier_plugin)
        ext_mgr = api_ext.PluginAwareExtensionManager(
            test_flowclassifier_db.extensions_path,
            {
                flowclassifier.FLOW_CLASSIFIER_EXT: self.flowclassifier_plugin
            }
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.ctx = context.get_admin_context()

        # use the fake vcns
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc2 = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc2

        # use the nsxv flow classifier driver
        self._profile_id = 'serviceprofile-1'
        cfg.CONF.set_override('service_insertion_profile_id',
                              self._profile_id, 'nsxv')
        self.driver = nsx_v_driver.NsxvFlowClassifierDriver()
        self.driver.initialize()

        self._fc = {'name': 'test1',
                    'description': 'test',
                    'logical_source_port': None,
                    'logical_destination_port': None,
                    'source_ip_prefix': '10.10.0.0/24',
                    'destination_ip_prefix': '20.10.0.0/24',
                    'protocol': 'tcp',
                    'source_port_range_min': 100,
                    'source_port_range_max': 114,
                    'destination_port_range_min': 80,
                    'destination_port_range_max': 80}

    def tearDown(self):
        super(TestNsxvFlowClassifierDriver, self).tearDown()

    def test_driver_init(self):
        self.assertEqual(self.driver._profile_id, self._profile_id)
        self.assertEqual(self.driver._security_group_id, '0')

    def test_create_flow_classifier_precommit(self):
        with self.flow_classifier(flow_classifier=self._fc) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            self.driver.create_flow_classifier_precommit(fc_context)

    def test_create_flow_classifier_precommit_logical_source_port(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port:
            with self.flow_classifier(flow_classifier={
                'name': 'test1',
                'logical_source_port': src_port['port']['id']
            }) as fc:
                fc_context = fc_ctx.FlowClassifierContext(
                    self.flowclassifier_plugin, self.ctx,
                    fc['flow_classifier']
                )
                self.assertRaises(
                    fc_exc.FlowClassifierBadRequest,
                    self.driver.create_flow_classifier_precommit,
                    fc_context)

    def test_create_flow_classifier_precommit_logical_dest_port(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as dst_port:
            with self.flow_classifier(flow_classifier={
                'name': 'test1',
                'logical_destination_port': dst_port['port']['id']
            }) as fc:
                fc_context = fc_ctx.FlowClassifierContext(
                    self.flowclassifier_plugin, self.ctx,
                    fc['flow_classifier']
                )
                self.assertRaises(
                    fc_exc.FlowClassifierBadRequest,
                    self.driver.create_flow_classifier_precommit,
                    fc_context)

    def _test_create_flow_classifier_precommit_src_port_range(self):
        with self.flow_classifier(flow_classifier={
            'name': 'test1',
            'protocol': 'tcp',
            'source_port_range_min': 100,
            'source_port_range_max': 116,
        }) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            self.assertRaises(
                fc_exc.FlowClassifierBadRequest,
                self.driver.create_flow_classifier_precommit,
                fc_context)

    def _test_create_flow_classifier_precommit_dst_port_range(self):
        with self.flow_classifier(flow_classifier={
            'name': 'test1',
            'protocol': 'tcp',
            'destination_port_range_min': 100,
            'destination_port_range_max': 116,
        }) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            self.assertRaises(
                fc_exc.FlowClassifierBadRequest,
                self.driver.create_flow_classifier_precommit,
                fc_context)

    def test_create_flow_classifier(self):
        with self.flow_classifier(flow_classifier=self._fc) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            with mock.patch.object(self.fc2,
                                   'update_section') as mock_update_section:
                self.driver.create_flow_classifier(fc_context)
                self.assertTrue(mock_update_section.called)

    def test_update_flow_classifier(self):
        with self.flow_classifier(flow_classifier=self._fc) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            self.driver.create_flow_classifier(fc_context)
            with mock.patch.object(self.fc2,
                                   'update_section') as mock_update_section:
                self.driver.update_flow_classifier(fc_context)
                self.assertTrue(mock_update_section.called)

    def test_delete_flow_classifier(self):
        with self.flow_classifier(flow_classifier=self._fc) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            self.driver.create_flow_classifier(fc_context)
            with mock.patch.object(self.fc2,
                                   'update_section') as mock_update_section:
                self.driver.delete_flow_classifier(fc_context)
                self.assertTrue(mock_update_section.called)
