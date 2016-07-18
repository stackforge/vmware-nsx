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
from neutron.objects import base as base_object
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.services.qos import qos_plugin
from neutron.tests.unit.services.qos import base

from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.nsxlib import v3 as nsxlib
from vmware_nsx.services.qos.nsx_v3 import utils as qos_utils
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase

PLUGIN_NAME = 'vmware_nsx.plugins.nsx_v3.plugin.NsxV3Plugin'


class TestQosNsxV3Notification(nsxlib_testcase.NsxClientTestCase,
                               base.BaseQosTestCase):

    def setUp(self):
        super(TestQosNsxV3Notification, self).setUp()
        self.setup_coreplugin(PLUGIN_NAME)

        # Add a dummy notification driver that calls our handler directly
        # (to skip the message queue)
        cfg.CONF.set_override(
            "notification_drivers",
            ['vmware_nsx.tests.unit.services.qos.fake_notifier.'
             'DummyNotificationDriver'],
            "qos")

        self.qos_plugin = qos_plugin.QoSPlugin()
        self.ctxt = context.Context('fake_user', 'fake_tenant')
        self.policy_data = {
            'policy': {'id': uuidutils.generate_uuid(),
                       'tenant_id': uuidutils.generate_uuid(),
                       'name': 'test-policy',
                       'description': 'Test policy description',
                       'shared': True}}
        self.egress_rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': 2000,
                                     'max_burst_kbps': 150,
                                     'direction': n_const.EGRESS_DIRECTION}}
        self.ingress_rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': 2000,
                                     'max_burst_kbps': 150,
                                     'direction': n_const.INGRESS_DIRECTION}}
        self.dscp_rule_data = {
            'dscp_marking_rule': {'id': uuidutils.generate_uuid(),
                                  'dscp_mark': 22}}

        self.policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])

        self.egress_rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **self.egress_rule_data['bandwidth_limit_rule'])
        self.ingress_rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **self.ingress_rule_data['bandwidth_limit_rule'])
        self.dscp_rule = rule_object.QosDscpMarkingRule(
            self.ctxt, **self.dscp_rule_data['dscp_marking_rule'])

        self.fake_profile_id = 'fake_profile'
        self.fake_profile = {'id': self.fake_profile_id}

        mock.patch('neutron.objects.db.api.create_object').start()
        mock.patch('neutron.objects.db.api.update_object').start()
        mock.patch('neutron.objects.db.api.delete_object').start()
        mock.patch(
            'neutron.objects.qos.policy.QosPolicy.obj_load_attr').start()
        mock.patch.object(nsx_db, 'get_switch_profile_by_qos_policy',
            return_value=self.fake_profile_id).start()

        self.peak_bw_multiplier = cfg.CONF.NSX.qos_peak_bw_multiplier

    @mock.patch(
        'neutron.objects.rbac_db.RbacNeutronDbObjectMixin'
        '.create_rbac_policy')
    @mock.patch.object(nsx_db, 'add_qos_policy_profile_mapping')
    def test_policy_create_profile(self, fake_db_add, fake_rbac_create):
        # test the switch profile creation when a QoS policy is created
        with mock.patch.object(nsxlib, 'create_qos_switching_profile',
            return_value=self.fake_profile) as create_profile:
            with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                return_value=self.policy):
                with mock.patch('neutron.objects.qos.policy.QosPolicy.create'):
                    policy = self.qos_plugin.create_policy(self.ctxt,
                                                           self.policy_data)
                    expected_tags = utils.build_v3_tags_payload(
                        policy,
                        resource_type='os-neutron-qos-id',
                        project_name=self.ctxt.tenant_name)

                    create_profile.assert_called_once_with(
                        description=self.policy_data["policy"]["description"],
                        name=self.policy_data["policy"]["name"],
                        tags=expected_tags)
                    # verify that the policy->profile mapping entry was added
                    self.assertTrue(fake_db_add.called)

    @mock.patch(
        'neutron.objects.rbac_db.RbacNeutronDbObjectMixin'
        '.create_rbac_policy')
    def test_policy_update_profile(self, *mocks):
        # test the switch profile update when a QoS policy is updated
        fields = base_object.get_updatable_fields(
            policy_object.QosPolicy, self.policy_data['policy'])
        with mock.patch.object(nsxlib,
            'update_qos_switching_profile') as update_profile:
            with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                return_value=self.policy):
                with mock.patch('neutron.objects.qos.policy.QosPolicy.update'):
                    self.qos_plugin.update_policy(
                        self.ctxt, self.policy.id, {'policy': fields})
                    # verify that the profile was updated with the correct data
                    self.policy_data["policy"]["id"] = self.policy.id
                    expected_tags = utils.build_v3_tags_payload(
                        self.policy_data["policy"],
                        resource_type='os-neutron-qos-id',
                        project_name=self.ctxt.tenant_name)

                    update_profile.assert_called_once_with(
                        self.fake_profile_id,
                        description=self.policy_data["policy"]["description"],
                        name=self.policy_data["policy"]["name"],
                        tags=expected_tags
                    )

    def _compare_bw_values_for_profile(self, actual_rule, expected_rule):
        if expected_rule:
            expected_bw = int(expected_rule['max_kbps'] / 1024)
            expected_peak = int(expected_bw * self.peak_bw_multiplier)
            expected_burst = int(expected_rule['max_burst_kbps'] * 128)
            self.assertEqual(True, actual_rule.shaping_enabled)
            self.assertEqual(expected_peak, actual_rule.peak_bandwidth)
            self.assertEqual(expected_bw, actual_rule.average_bandwidth)
            self.assertEqual(expected_burst, actual_rule.burst_size)
        else:
            self.assertEqual(False, actual_rule.shaping_enabled)

    @mock.patch.object(policy_object.QosPolicy, 'reload_rules')
    def test_bw_rule_create_profile(self, *mocks):
        # test the switch profile update when a QoS BW rule is created
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [self.egress_rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            with mock.patch.object(nsxlib,
                'update_qos_switching_profile_shaping') as update_profile:
                with mock.patch('neutron.objects.db.api.update_object',
                    return_value=self.egress_rule_data):
                    self.qos_plugin.update_policy_bandwidth_limit_rule(
                        self.ctxt, self.egress_rule.id, _policy.id,
                        self.egress_rule_data)

                    self.assertTrue(update_profile.called)
                    # validate egress data on the profile
                    actual_rule = update_profile.call_args[1]['egress']
                    expected_rule_dict = self.egress_rule_data[
                        'bandwidth_limit_rule']
                    self._compare_bw_values_for_profile(
                        actual_rule, expected_rule_dict)

                    # validate empty ingress data on the profile
                    actual_rule = update_profile.call_args[1]['ingress']
                    self._compare_bw_values_for_profile(actual_rule, None)

                    # validate the dscp arguments
                    self.assertEqual(
                        'trusted', update_profile.call_args[1]['qos_marking'])
                    self.assertEqual(0, update_profile.call_args[1]['dscp'])

    @mock.patch.object(policy_object.QosPolicy, 'reload_rules')
    def test_bw_rules_create_profile(self, *mocks):
        # test the switch profile update when a QoS BW rules for both
        # directions are created
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [self.egress_rule, self.ingress_rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            with mock.patch.object(nsxlib,
                'update_qos_switching_profile_shaping') as update_profile:
                with mock.patch('neutron.objects.db.api.update_object',
                    return_value=self.egress_rule_data):
                    self.qos_plugin.update_policy_bandwidth_limit_rule(
                        self.ctxt, self.egress_rule.id, _policy.id,
                        self.egress_rule_data)

                    self.qos_plugin.update_policy_bandwidth_limit_rule(
                        self.ctxt, self.ingress_rule.id, _policy.id,
                        self.egress_rule_data)

                    self.assertTrue(update_profile.called)
                    # validate egress data on the profile
                    actual_rule = update_profile.call_args[1]['egress']
                    expected_rule_dict = self.egress_rule_data[
                        'bandwidth_limit_rule']
                    self._compare_bw_values_for_profile(
                        actual_rule, expected_rule_dict)

                    # validate ingress data on the profile
                    actual_rule = update_profile.call_args[1]['ingress']
                    expected_rule_dict = self.ingress_rule_data[
                        'bandwidth_limit_rule']
                    self._compare_bw_values_for_profile(
                        actual_rule, expected_rule_dict)

                    # validate the dscp arguments
                    self.assertEqual(
                        'trusted',
                        update_profile.call_args[1]['qos_marking'])
                    self.assertEqual(0, update_profile.call_args[1]['dscp'])

    @mock.patch.object(policy_object.QosPolicy, 'reload_rules')
    def test_bw_rule_create_profile_minimal_val(self, *mocks):
        # test the switch profile update when a QoS rule is created
        # with an invalid limit value
        bad_limit = qos_utils.MAX_KBPS_MIN_VALUE - 1
        rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': bad_limit,
                                     'max_burst_kbps': 150,
                                     'direction': n_const.INGRESS_DIRECTION}}

        rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **rule_data['bandwidth_limit_rule'])

        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            with mock.patch.object(nsxlib,
                'update_qos_switching_profile_shaping') as update_profile:
                with mock.patch('neutron.objects.db.api.update_object',
                    return_value=rule_data):
                    self.qos_plugin.update_policy_bandwidth_limit_rule(
                        self.ctxt, rule.id, _policy.id, rule_data)

                    self.assertTrue(update_profile.called)
                    actual_rule = update_profile.call_args[1]['ingress']
                    expected_rule_dict = rule_data['bandwidth_limit_rule']
                    # Fix the expected, since the minimal value will be used
                    expected_rule_dict['max_kbps'] = (
                        qos_utils.MAX_KBPS_MIN_VALUE)
                    self._compare_bw_values_for_profile(
                        actual_rule, expected_rule_dict)

                    # validate empty egress
                    actual_rule = update_profile.call_args[1]['egress']
                    self._compare_bw_values_for_profile(actual_rule, None)

                    # validate the dscp arguments
                    self.assertEqual(
                        'trusted',
                        update_profile.call_args[1]['qos_marking'])
                    self.assertEqual(0, update_profile.call_args[1]['dscp'])

    @mock.patch.object(policy_object.QosPolicy, 'reload_rules')
    def test_dscp_rule_create_profile(self, *mocks):
        # test the switch profile update when a QoS DSCP rule is created
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # add a rule to the policy
        setattr(_policy, "rules", [self.dscp_rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            with mock.patch.object(nsxlib,
                'update_qos_switching_profile_shaping') as update_profile:
                with mock.patch('neutron.objects.db.api.'
                    'update_object', return_value=self.dscp_rule_data):
                    self.qos_plugin.update_policy_dscp_marking_rule(
                        self.ctxt, self.dscp_rule.id,
                        _policy.id, self.dscp_rule_data)

                    # validate the data on the profile
                    self.assertTrue(update_profile.called)
                    # validate empty ingress
                    actual_rule = update_profile.call_args[1]['ingress']
                    self._compare_bw_values_for_profile(actual_rule, None)

                    # validate empty egress
                    actual_rule = update_profile.call_args[1]['egress']
                    self._compare_bw_values_for_profile(actual_rule, None)

                    # validate the dscp arguments
                    rule_dict = self.dscp_rule_data['dscp_marking_rule']
                    self.assertEqual(
                        'untrusted',
                        update_profile.call_args[1]['qos_marking'])
                    self.assertEqual(
                        rule_dict['dscp_mark'],
                        update_profile.call_args[1]['dscp'])

    @mock.patch('neutron.objects.db.api.get_objects',
                return_value=[])
    def test_rule_delete_profile(self, mock_objects):
        # test the switch profile update when a QoS rule is deleted
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        # The mock will return the policy without the rule,
        # as if it was deleted
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            with mock.patch.object(nsxlib,
                'update_qos_switching_profile_shaping') as update_profile:
                setattr(_policy, "rules", [self.egress_rule])
                self.qos_plugin.delete_policy_bandwidth_limit_rule(
                    self.ctxt, self.egress_rule.id, self.policy.id)
                # validate the data on the profile
                self.assertTrue(update_profile.called)
                # validate empty ingress
                actual_rule = update_profile.call_args[1]['ingress']
                self._compare_bw_values_for_profile(actual_rule, None)

                # validate empty egress
                actual_rule = update_profile.call_args[1]['egress']
                self._compare_bw_values_for_profile(actual_rule, None)

                # validate the dscp arguments
                self.assertEqual('trusted',
                                 update_profile.call_args[1]['qos_marking'])
                self.assertEqual(0, update_profile.call_args[1]['dscp'])

    @mock.patch('neutron.objects.db.api.get_object', return_value=None)
    def test_policy_delete_profile(self, *mocks):
        # test the switch profile deletion when a QoS policy is deleted
        with mock.patch.object(nsxlib, 'delete_qos_switching_profile',
            return_value=self.fake_profile) as delete_profile:
            self.qos_plugin.delete_policy(self.ctxt, self.policy.id)
            delete_profile.assert_called_once_with(self.fake_profile_id)
