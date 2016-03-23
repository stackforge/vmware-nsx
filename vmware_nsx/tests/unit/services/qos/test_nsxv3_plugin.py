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

from neutron.objects import base as base_object
from neutron.objects.qos import policy as policy_object
from neutron.tests.unit.services.qos import test_qos_plugin as qos_tests

from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.nsxlib import v3 as nsxlib

QOS_PLUGIN = "vmware_nsx.services.qos.nsx_v3.plugin.NsxV3QosPlugin"


class TestQosNsxV3Plugin(qos_tests.TestQosPlugin):
    def setUp(self):

        self.SERVICE_PLUGIN_NAME = QOS_PLUGIN

        super(TestQosNsxV3Plugin, self).setUp()

        # Set a different default max_kbps because nsx-v3 does not
        # support values under 1Mbps
        self.rule_data['bandwidth_limit_rule']['max_kbps'] = 2000

        self.fake_profile_id = 'fake_profile'
        self.fake_profile = {'id': self.fake_profile_id}

        self._patchers = []

        def _patch_object(*args, **kwargs):
            patcher = mock.patch.object(*args, **kwargs)
            patcher.start()
            self._patchers.append(patcher)

        # add all mocks for the nsx-db and nsx-backend api
        _patch_object(nsx_db, 'add_qos_policy_profile_mapping')
        _patch_object(nsx_db, 'get_switch_profile_by_qos_policy',
            return_value=self.fake_profile_id)
        _patch_object(nsxlib, 'create_qos_switching_profile',
            return_value=self.fake_profile)
        _patch_object(nsxlib, 'update_qos_switching_profile')
        _patch_object(nsxlib, 'update_qos_switching_profile_shaping')
        _patch_object(nsxlib, 'delete_qos_switching_profile')

    def tearDown(self):
        for patcher in self._patchers:
            patcher.stop()
        super(TestQosNsxV3Plugin, self).tearDown()

    @mock.patch(
        'neutron.objects.rbac_db.RbacNeutronDbObjectMixin'
        '.create_rbac_policy')
    def test_policy_create_profile(self, *mocks):
        # test the switch profile creation when a QoS policy is created
        with mock.patch.object(nsxlib, 'create_qos_switching_profile',
            return_value=self.fake_profile) as create_profile:
            with mock.patch.object(nsx_db,
                'add_qos_policy_profile_mapping') as add_db_map:
                policy = self.qos_plugin.create_policy(self.ctxt,
                                                       self.policy_data)
                # verify that the profile was created with the correct data
                expected_tags = utils.build_v3_tags_payload(
                    policy,
                    resource_type='os-neutron-qos-id',
                    project_name=self.ctxt.tenant_name)

                create_profile.assert_called_once_with(
                    description=self.policy_data["policy"]["description"],
                    name=self.policy_data["policy"]["name"],
                    tags=expected_tags)
                # verify that the policy->profile mapping entry was added
                add_db_map.assert_called_once_with(self.ctxt.session,
                                                   policy["id"],
                                                   self.fake_profile_id)

    @mock.patch(
        'neutron.objects.rbac_db.RbacNeutronDbObjectMixin'
        '.create_rbac_policy')
    def test_policy_update_profile(self, *mocks):
        # test the switch profile update when a QoS policy is updated
        fields = base_object.get_updatable_fields(
            policy_object.QosPolicy, self.policy_data['policy'])
        with mock.patch.object(nsxlib,
            'update_qos_switching_profile') as update_profile:
            self.qos_plugin.update_policy(
                self.ctxt, self.policy.id, {'policy': fields})

            # verify that the profile was updated with the correct data
            self.policy_data["policy"]["id"] = self.policy.id
            expected_tags = utils.build_v3_tags_payload(
                self.policy_data,
                resource_type='os-neutron-qos-id',
                project_name=self.ctxt.tenant_name)

            update_profile.assert_called_once_with(
                self.fake_profile_id,
                description=self.policy_data["policy"]["description"],
                name=self.policy_data["policy"]["name"],
                tags=expected_tags
            )

    def test_rule_create_profile(self):
        # test the switch profile update when a QoS rule is created
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            with mock.patch.object(nsxlib,
                'update_qos_switching_profile_shaping') as update_profile:
                # add a rule to the policy
                setattr(_policy, "rules", [self.rule])
                self.qos_plugin.update_policy_bandwidth_limit_rule(
                    self.ctxt, self.rule.id, self.policy.id, self.rule_data)

                # validate the data on the profile
                rule_dict = self.rule_data['bandwidth_limit_rule']
                expected_bw = rule_dict['max_kbps'] / 1024
                expected_burst = rule_dict['max_burst_kbps'] * 128
                update_profile.assert_called_once_with(
                    self.fake_profile_id,
                    average_bandwidth=expected_bw,
                    burst_size=expected_burst,
                    peak_bandwidth=expected_bw,
                    shaping_enabled=True
                )

    @mock.patch('neutron.objects.db.api.get_object', return_value=None)
    def test_policy_delete_profile(self, *mocks):
        # test the switch profile deletion when a QoS policy is deleted
        with mock.patch.object(nsxlib, 'delete_qos_switching_profile',
            return_value=self.fake_profile) as delete_profile:
            self.qos_plugin.delete_policy(self.ctxt, self.policy.id)
            delete_profile.assert_called_once_with(self.fake_profile_id)
