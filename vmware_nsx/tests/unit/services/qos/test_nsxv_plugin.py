# Copyright 2016 VMware, Inc.
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

from neutron import manager
from neutron.objects.qos import policy as policy_object
from neutron.tests.unit.services.qos import test_qos_plugin as qos_tests

from vmware_nsx.dvs import dvs
from vmware_nsx.dvs import dvs_utils
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.services.qos.nsx_v import utils as qos_utils
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.nsx_v.vshield import fake_vcns
from vmware_nsx.tests.unit import test_utils

from oslo_config import cfg

CORE_PLUGIN = "vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2"
QOS_PLUGIN = "vmware_nsx.services.qos.nsx_v.plugin.NsxVQosPlugin"


class TestQosNsxVPlugin(qos_tests.TestQosPlugin):
    @mock.patch.object(edge_utils.EdgeManager, '_deploy_edge')
    @mock.patch.object(dvs_utils, 'dvs_create_session')
    @mock.patch.object(dvs.DvsManager, '_get_dvs_moref')
    def setUp(self, *mocks):
        # Ensure that DVS is enabled
        # and enable the DVS features for nsxv qos support
        cfg.CONF.set_override('host_ip', 'fake_ip', group='dvs')
        cfg.CONF.set_override('host_username', 'fake_user', group='dvs')
        cfg.CONF.set_override('host_password', 'fake_password', group='dvs')
        cfg.CONF.set_override('dvs_name', 'fake_dvs', group='dvs')
        cfg.CONF.set_default('use_dvs_features', True, 'nsxv')

        # Allow the nsxv core plugin to be enabled
        test_utils.override_nsx_ini_test()
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc2 = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc2

        self.CORE_PLUGIN_NAME = CORE_PLUGIN
        self.SERVICE_PLUGIN_NAME = QOS_PLUGIN

        super(TestQosNsxVPlugin, self).setUp()

        self._core_plugin = manager.NeutronManager.get_plugin()
        self._core_plugin._dvs = dvs.DvsManager()

        self._net_data = {'network': {
            'name': 'test-qos',
            'tenant_id': 'fake_tenant',
            'qos_policy_id': self.policy.id,
            'port_security_enabled': False,
            'admin_state_up': False,
            'shared': False
        }}
        self._rules = [self.rule_data['bandwidth_limit_rule']]

    @mock.patch.object(qos_utils, 'update_network_policy_binding')
    @mock.patch('vmware_nsx.dvs.dvs.DvsManager.update_port_groups_config')
    def test_create_network_with_policy_rule(self, dvs_update_mock,
        update_bindings_mock):
        with mock.patch.object(policy_object.QosPolicy, 'get_object',
            return_value=self.policy):
            # create qos policy & rule
            self.qos_plugin.create_policy_bandwidth_limit_rule(
                self.ctxt, self.policy.id, self.rule_data)

            with mock.patch('neutron.services.qos.qos_plugin.QoSPlugin.'
                            'get_policy_bandwidth_limit_rules',
                            return_value=self._rules) as get_rules_mock:
                # create the network to use this policy
                net = self._core_plugin.create_network(
                    self.ctxt, self._net_data)
                # make sure the dvs was updated
                update_bindings_mock.assert_called_once_with(
                    self.ctxt, net['id'], self.policy.id)
                # make sure the qos rule was found
                get_rules_mock.assert_called_with(self.ctxt, self.policy.id)

    @mock.patch('neutron.db.qos.api.'
        'get_network_ids_by_policy_network_binding',
        return_value=['fake_net_id'])
    @mock.patch('vmware_nsx.db.db.get_nsx_switch_ids', return_value=[])
    def test_update_policy_network(self, get_nsx_ids_mock, get_binding_mock):
        # create a qos policy
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch.object(policy_object.QosPolicy, 'get_object',
            return_value=_policy):
            # update the rule of the policy, and try to update policies
            setattr(_policy, "rules", [self.rule])
            with mock.patch('neutron.services.qos.qos_plugin.QoSPlugin.'
                        'get_policy_bandwidth_limit_rules',
                        return_value=self._rules) as fake_get_rules:
                self.qos_plugin.update_policy_bandwidth_limit_rule(
                    self.ctxt, self.rule.id, self.policy.id, self.rule_data)
                fake_get_rules.assert_called_once_with(
                    self.ctxt, self.policy.id)
                get_nsx_ids_mock.assert_called_once_with(
                    self.ctxt.session, 'fake_net_id')
