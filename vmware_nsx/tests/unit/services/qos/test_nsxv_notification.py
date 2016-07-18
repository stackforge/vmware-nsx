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

from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.common import constants as n_const
from neutron import context
from neutron import manager
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.services.qos import qos_consts
from neutron.services.qos import qos_plugin
from neutron.tests.unit.services.qos import base

from vmware_nsx.dvs import dvs
from vmware_nsx.dvs import dvs_utils
from vmware_nsx.services.qos.common import utils as qos_com_utils
from vmware_nsx.services.qos.nsx_v import utils as qos_utils
from vmware_nsx.tests.unit.nsx_v import test_plugin

CORE_PLUGIN = "vmware_nsx.plugins.nsx_v.plugin.NsxVPluginV2"


class TestQosNsxVNotification(test_plugin.NsxVPluginV2TestCase,
                              base.BaseQosTestCase):

    @mock.patch.object(dvs_utils, 'dvs_create_session')
    @mock.patch.object(dvs.DvsManager, '_get_dvs_moref')
    def setUp(self, *mocks):
        # init the nsx-v plugin for testing with DVS
        self._init_dvs_config()
        super(TestQosNsxVNotification, self).setUp(plugin=CORE_PLUGIN,
                                                   ext_mgr=None)
        plugin_instance = manager.NeutronManager.get_plugin()
        self._core_plugin = plugin_instance
        self._core_plugin.init_is_complete = True

        # Setup the QoS plugin:
        # Add a dummy notification driver that calls our handler directly
        # (to skip the message queue)
        cfg.CONF.set_override(
            "notification_drivers",
            ['vmware_nsx.tests.unit.services.qos.fake_nsxv_notifier.'
             'DummyNsxVNotificationDriver'],
            "qos")
        self.qos_plugin = qos_plugin.QoSPlugin()
        mock.patch.object(qos_utils.NsxVQosRule,
                          '_get_qos_plugin',
                          return_value=self.qos_plugin).start()

        # Pre defined QoS data for the tests
        self.ctxt = context.Context('fake_user', 'fake_tenant')
        self.policy_data = {
            'policy': {'id': uuidutils.generate_uuid(),
                       'tenant_id': uuidutils.generate_uuid(),
                       'name': 'test-policy',
                       'description': 'Test policy description',
                       'shared': True}}

        self.egress_max = 100
        self.egress_burst = 150
        self.egress_rule_data = {
            'bandwidth_limit_rule': {
                'id': uuidutils.generate_uuid(),
                'max_kbps': self.egress_max,
                'max_burst_kbps': self.egress_burst,
                'direction': n_const.EGRESS_DIRECTION,
                'type': qos_consts.RULE_TYPE_BANDWIDTH_LIMIT}}
        self.ingress_max = 200
        self.ingress_burst = 250
        self.ingress_rule_data = {
            'bandwidth_limit_rule': {
                'id': uuidutils.generate_uuid(),
                'max_kbps': self.ingress_max,
                'max_burst_kbps': self.ingress_burst,
                'direction': n_const.INGRESS_DIRECTION,
                'type': qos_consts.RULE_TYPE_BANDWIDTH_LIMIT}}
        self.dscp_mark_val = 22
        self.dscp_rule_data = {
            'dscp_marking_rule': {
                'id': uuidutils.generate_uuid(),
                'dscp_mark': self.dscp_mark_val,
                'type': qos_consts.RULE_TYPE_DSCP_MARKING}}

        self.policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])

        self.egress_rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **self.egress_rule_data['bandwidth_limit_rule'])
        self.ingress_rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **self.ingress_rule_data['bandwidth_limit_rule'])
        self.dscp_rule = rule_object.QosDscpMarkingRule(
            self.ctxt, **self.dscp_rule_data['dscp_marking_rule'])

        self._net_data = {'network': {
            'name': 'test-qos',
            'tenant_id': 'fake_tenant',
            'qos_policy_id': self.policy.id,
            'port_security_enabled': False,
            'admin_state_up': False,
            'shared': False
        }}
        self._dscp_rules = [self.dscp_rule_data['dscp_marking_rule']]

        mock.patch('neutron.objects.db.api.create_object',
            return_value=self.egress_rule_data).start()
        mock.patch('neutron.objects.db.api.update_object',
            return_value=self.egress_rule_data).start()
        mock.patch('neutron.objects.db.api.delete_object').start()
        mock.patch('neutron.objects.db.api.get_object').start()
        mock.patch(
            'neutron.objects.qos.policy.QosPolicy.obj_load_attr').start()

    def _init_dvs_config(self):
        # Ensure that DVS is enabled
        # and enable the DVS features for nsxv qos support
        cfg.CONF.set_override('host_ip', 'fake_ip', group='dvs')
        cfg.CONF.set_override('host_username', 'fake_user', group='dvs')
        cfg.CONF.set_override('host_password', 'fake_password', group='dvs')
        cfg.CONF.set_override('dvs_name', 'fake_dvs', group='dvs')
        cfg.CONF.set_default('use_dvs_features', True, 'nsxv')

    def _create_net(self):
        with mock.patch('vmware_nsx.services.qos.common.utils.'
                        'get_network_policy_id',
                        return_value=self.policy.id):
            return self._core_plugin.create_network(self.ctxt, self._net_data)

    def _compare_qos_data(self, qos_data, with_dscp=False,
                          with_egress=False, with_ingress=False):
        if with_dscp:
            self.assertEqual(True, qos_data.dscpMarkEnabled)
            self.assertEqual(self.dscp_mark_val, qos_data.dscpMarkValue)
        else:
            self.assertEqual(False, qos_data.dscpMarkEnabled)

        if with_egress:
            self.assertEqual(True, qos_data.egressBW.bandwidthEnabled)
            self.assertEqual(self.egress_max * 1024,
                             qos_data.egressBW.averageBandwidth)
            self.assertEqual(self.egress_max * 1024,
                             qos_data.egressBW.peakBandwidth)
            self.assertEqual(self.egress_burst * 128,
                             qos_data.egressBW.burstSize)
        else:
            self.assertEqual(False, qos_data.egressBW.bandwidthEnabled)

        if with_ingress:
            self.assertEqual(True, qos_data.ingressBW.bandwidthEnabled)
            self.assertEqual(self.ingress_max * 1024,
                             qos_data.ingressBW.averageBandwidth)
            self.assertEqual(self.ingress_max * 1024,
                             qos_data.ingressBW.peakBandwidth)
            self.assertEqual(self.ingress_burst * 128,
                             qos_data.ingressBW.burstSize)
        else:
            self.assertEqual(False, qos_data.ingressBW.bandwidthEnabled)

    @mock.patch.object(qos_com_utils, 'update_network_policy_binding')
    @mock.patch.object(dvs.DvsManager, 'update_port_groups_config')
    def test_create_network_with_policy_rule(self,
                                             dvs_update_mock,
                                             update_bindings_mock):
        """Test the DVS update when a QoS rule is attached to a network"""
        # Create a policy with a rule
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        setattr(_policy, "rules", [self.egress_rule, self.ingress_rule,
                                   self.dscp_rule])

        with mock.patch('neutron.services.qos.qos_plugin.QoSPlugin.'
                        'get_policy',
                        return_value=_policy) as get_rules_mock:
            # create the network to use this policy
            net = self._create_net()

            # make sure the network-policy binding was updated
            update_bindings_mock.assert_called_once_with(
                self.ctxt, net['id'], self.policy.id)
            # make sure the qos rule was found
            get_rules_mock.assert_called_with(self.ctxt, self.policy.id)
            # make sure the dvs was updated, with the correct values
            self.assertTrue(dvs_update_mock.called)
            self._compare_qos_data(dvs_update_mock.call_args[0][3],
                with_dscp=True, with_egress=True, with_ingress=True)

    def _test_rule_action_notification(self, action, rule_direction):
        with mock.patch.object(qos_com_utils, 'update_network_policy_binding'):
            with mock.patch.object(dvs.DvsManager,
                                   'update_port_groups_config') as dvs_mock:

                # Create a policy with a rule
                _policy = policy_object.QosPolicy(
                    self.ctxt, **self.policy_data['policy'])

                if rule_direction == n_const.INGRESS_DIRECTION:
                    rule = self.ingress_rule
                    rule_data = self.ingress_rule_data
                else:
                    rule = self.egress_rule
                    rule_data = self.egress_rule_data

                # set the rule in the policy data
                if action != 'create':
                    setattr(_policy, "rules", [rule])

                with mock.patch('neutron.services.qos.qos_plugin.QoSPlugin.'
                                'get_policy',
                                return_value=_policy) as get_rules_mock:
                    with mock.patch('neutron.objects.qos.policy.'
                                    'QosPolicy.get_object',
                                    return_value=_policy):
                        # create the network to use this policy
                        self._create_net()

                        # create/update/delete the rule
                        if action == 'create':
                            self.qos_plugin.create_policy_bandwidth_limit_rule(
                                self.ctxt, self.policy.id, rule_data)
                        elif action == 'update':
                            self.qos_plugin.update_policy_bandwidth_limit_rule(
                                self.ctxt, rule.id,
                                self.policy.id, rule_data)
                        else:
                            self.qos_plugin.delete_policy_bandwidth_limit_rule(
                                self.ctxt, rule.id, self.policy.id)

                        # make sure the qos rule was found
                        self.assertTrue(get_rules_mock.called)
                        # make sure the dvs was updated
                        self.assertTrue(dvs_mock.called)

    def test_create_egress_rule_notification(self):
        """Test the DVS update when a QoS rule, attached to a network,
        is created
        """
        self._test_rule_action_notification('create', n_const.EGRESS_DIRECTION)

    def test_update_egress_rule_notification(self):
        """Test the DVS update when a QoS rule, attached to a network,
        is modified
        """
        self._test_rule_action_notification('update', n_const.EGRESS_DIRECTION)

    def test_delete_egress_rule_notification(self):
        """Test the DVS update when a QoS rule, attached to a network,
        is deleted
        """
        self._test_rule_action_notification('delete', n_const.EGRESS_DIRECTION)

    def test_create_ingress_rule_notification(self):
        """Test the DVS update when a QoS rule, attached to a network,
        is created
        """
        self._test_rule_action_notification('create',
                                            n_const.INGRESS_DIRECTION)

    def test_update_ingress_rule_notification(self):
        """Test the DVS update when a QoS rule, attached to a network,
        is modified
        """
        self._test_rule_action_notification('update',
                                            n_const.INGRESS_DIRECTION)

    def test_delete_ingress_rule_notification(self):
        """Test the DVS update when a QoS rule, attached to a network,
        is deleted
        """
        self._test_rule_action_notification('delete',
                                            n_const.INGRESS_DIRECTION)

    def _test_dscp_rule_action_notification(self, action):
        with mock.patch.object(qos_com_utils, 'update_network_policy_binding'):
            with mock.patch.object(dvs.DvsManager,
                                   'update_port_groups_config') as dvs_mock:

                # Create a policy with a rule
                _policy = policy_object.QosPolicy(
                    self.ctxt, **self.policy_data['policy'])

                # set the rule in the policy data
                if action != 'create':
                    setattr(_policy, "rules", [self.dscp_rule])
                plugin = self.qos_plugin
                with mock.patch('neutron.services.qos.qos_plugin.QoSPlugin.'
                                'get_policy',
                                return_value=_policy) as rules_mock:
                    with mock.patch('neutron.objects.qos.policy.'
                                    'QosPolicy.get_object',
                                    return_value=_policy):
                        # create the network to use this policy
                        self._create_net()
                        # create/update/delete the rule
                        if action == 'create':
                            with mock.patch('neutron.objects.db.api.'
                                            'create_object',
                                            return_value=self.dscp_rule_data):
                                plugin.create_policy_dscp_marking_rule(
                                    self.ctxt,
                                    self.policy.id,
                                    self.dscp_rule_data)
                        elif action == 'update':
                            with mock.patch('neutron.objects.db.api.'
                                            'update_object',
                                            return_value=self.dscp_rule_data):
                                plugin.update_policy_dscp_marking_rule(
                                    self.ctxt,
                                    self.dscp_rule.id,
                                    self.policy.id,
                                    self.dscp_rule_data)
                        else:
                            plugin.delete_policy_dscp_marking_rule(
                                self.ctxt,
                                self.dscp_rule.id,
                                self.policy.id)

                        # make sure the qos rule was found
                        self.assertTrue(rules_mock.called)

                        # make sure the dvs was updated
                        self.assertTrue(dvs_mock.called)

    def test_create_dscp_rule_notification(self):
        """Test the DVS update when a QoS DSCP rule, attached to a network,
        is created
        """
        self._test_dscp_rule_action_notification('create')

    def test_update_dscp_rule_notification(self):
        """Test the DVS update when a QoS DSCP rule, attached to a network,
        is modified
        """
        self._test_dscp_rule_action_notification('update')

    def test_delete_dscp_rule_notification(self):
        """Test the DVS update when a QoS DSCP rule, attached to a network,
        is deleted
        """
        self._test_dscp_rule_action_notification('delete')

    def _test_nsxv_rule_init(self, with_dscp=False,
                             with_egress=False, with_ingress=False):
        # init the qos policy with the relevant rules
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        rules = []

        if with_dscp:
            rules.append(self.dscp_rule)
        if with_egress:
            rules.append(self.egress_rule)
        if with_ingress:
            rules.append(self.ingress_rule)
        setattr(_policy, "rules", rules)

        # translate the policy to the nsxv object
        with mock.patch('neutron.services.qos.qos_plugin.QoSPlugin.get_policy',
                        return_value=_policy):
            with mock.patch('neutron.objects.qos.policy.'
                            'QosPolicy.get_object',
                            return_value=_policy):
                nsxv_rule = qos_utils.NsxVQosRule(context=self.ctxt,
                                                  qos_policy_id=_policy.id)
                self._compare_qos_data(
                    nsxv_rule,
                    with_dscp=with_dscp,
                    with_ingress=with_ingress,
                    with_egress=with_egress)

    def test_nsxv_rule_with_dhcp(self):
        self._test_nsxv_rule_init(with_dscp=True)

    def test_nsxv_rule_with_ingress_bw(self):
        self._test_nsxv_rule_init(with_ingress=True)

    def test_nsxv_rule_with_egress_bw(self):
        self._test_nsxv_rule_init(with_egress=True)

    def test_nsxv_rule_empty(self):
        self._test_nsxv_rule_init()

    def test_nsxv_rule_all(self):
        self._test_nsxv_rule_init(
            with_dscp=True, with_ingress=True, with_egress=True)
