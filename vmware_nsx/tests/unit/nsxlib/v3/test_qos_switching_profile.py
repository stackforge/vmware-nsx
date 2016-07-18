# Copyright (c) 2015 VMware, Inc.
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
#
import mock

from oslo_log import log
from oslo_serialization import jsonutils

from vmware_nsx.nsxlib import v3 as nsxlib
from vmware_nsx.services.qos.nsx_v3 import utils
from vmware_nsx.tests.unit.nsx_v3 import test_constants as test_constants_v3
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase
from vmware_nsx.tests.unit.nsxlib.v3 import test_client

LOG = log.getLogger(__name__)


class NsxLibQosTestCase(nsxlib_testcase.NsxClientTestCase):

    def _body(self, qos_marking=None, dscp=None,
              description=test_constants_v3.FAKE_NAME):
        body = {
            "resource_type": "QosSwitchingProfile",
            "tags": []
        }
        if qos_marking:
            body = nsxlib._update_dscp_in_args(body, qos_marking, dscp)

        body["display_name"] = test_constants_v3.FAKE_NAME
        body["description"] = description

        return body

    def _body_with_shaping(self,
                           egress=None,
                           ingress=None,
                           description=test_constants_v3.FAKE_NAME,
                           qos_marking=None,
                           dscp=0):
        body = test_constants_v3.FAKE_QOS_PROFILE
        body["display_name"] = test_constants_v3.FAKE_NAME
        body["description"] = description

        for shaper in body["shaper_configuration"]:
            if egress and shaper["resource_type"] == "EgressRateShaper":
                shaper["enabled"] = egress.get('shaping_enabled')
                if egress.get('burst_size'):
                    shaper["burst_size_bytes"] = egress['burst_size']
                if egress.get('peak_bandwidth'):
                    shaper["peak_bandwidth_mbps"] = egress['peak_bandwidth']
                if egress.get('average_bandwidth'):
                    shaper["average_bandwidth_mbps"] = egress[
                        'average_bandwidth']
            elif ingress and shaper["resource_type"] == "IngressRateShaper":
                shaper["enabled"] = ingress.get('shaping_enabled')
                if ingress.get('burst_size'):
                    shaper["burst_size_bytes"] = ingress['burst_size']
                if ingress.get('peak_bandwidth'):
                    shaper["peak_bandwidth_mbps"] = ingress['peak_bandwidth']
                if ingress.get('average_bandwidth'):
                    shaper["average_bandwidth_mbps"] = ingress[
                        'average_bandwidth']

        if qos_marking:
            body = nsxlib._update_dscp_in_args(body, qos_marking, dscp)

        return body

    def test_create_qos_switching_profile(self):
        """
        Test creating a qos-switching profile returns the correct response
        """
        api = self.mocked_rest_fns(nsxlib, 'client')

        nsxlib.create_qos_switching_profile(
            tags=[],
            name=test_constants_v3.FAKE_NAME,
            description=test_constants_v3.FAKE_NAME)

        test_client.assert_json_call(
            'post', api,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps(self._body(),
                                 sort_keys=True))

    def test_update_qos_switching_profile(self):
        """
        Test updating a qos-switching profile returns the correct response
        """
        api = self.mocked_rest_fns(nsxlib, 'client')

        original_profile = self._body()
        new_description = "Test"
        with mock.patch.object(nsxlib.client, 'get_resource',
                        return_value=original_profile):
            # update the description of the profile
            nsxlib.update_qos_switching_profile(
                test_constants_v3.FAKE_QOS_PROFILE['id'],
                tags=[],
                description=new_description)

            test_client.assert_json_call(
                'put', api,
                'https://1.2.3.4/api/v1/switching-profiles/%s'
                % test_constants_v3.FAKE_QOS_PROFILE['id'],
                data=jsonutils.dumps(self._body(description=new_description),
                                     sort_keys=True))

    def test_enable_qos_switching_profile_shaping(self):
        """
        Test updating a qos-switching profile returns the correct response
        """
        api = self.mocked_rest_fns(nsxlib, 'client')

        original_profile = self._body_with_shaping()
        egress = utils.NsxV3BWLimitRule()
        egress.shaping_enabled = True
        egress.burst_size = 100
        egress.peak_bandwidth = 200
        egress.average_bandwidth = 300
        ingress = utils.NsxV3BWLimitRule()
        ingress.shaping_enabled = True
        ingress.burst_size = 101
        ingress.peak_bandwidth = 201
        egress.average_bandwidth = 301
        qos_marking = "untrusted"
        dscp = 10
        with mock.patch.object(nsxlib.client, 'get_resource',
                        return_value=original_profile):
            # update the bw shaping of the profile
            nsxlib.update_qos_switching_profile_shaping(
                test_constants_v3.FAKE_QOS_PROFILE['id'],
                egress=egress,
                ingress=ingress,
                qos_marking=qos_marking,
                dscp=dscp)

            test_client.assert_json_call(
                'put', api,
                'https://1.2.3.4/api/v1/switching-profiles/%s'
                % test_constants_v3.FAKE_QOS_PROFILE['id'],
                data=jsonutils.dumps(
                    self._body_with_shaping(
                        egress=egress.__dict__,
                        ingress=ingress.__dict__,
                        qos_marking="untrusted", dscp=10),
                    sort_keys=True))

    def test_disable_qos_switching_profile_shaping(self):
        """
        Test updating a qos-switching profile returns the correct response
        """
        api = self.mocked_rest_fns(nsxlib, 'client')

        original_profile = self._body_with_shaping(
            egress={'shaping_enabled': True,
                    'burst_size': 100,
                    'peak_bandwidth': 200,
                    'average_bandwidth': 300},
            ingress={'shaping_enabled': True,
                    'burst_size': 101,
                    'peak_bandwidth': 201,
                    'average_bandwidth': 301},
            qos_marking="untrusted",
            dscp=10)
        with mock.patch.object(nsxlib.client, 'get_resource',
                        return_value=original_profile):
            # update the bw shaping of the profile
            nsxlib.update_qos_switching_profile_shaping(
                test_constants_v3.FAKE_QOS_PROFILE['id'],
                qos_marking="trusted")

            test_client.assert_json_call(
                'put', api,
                'https://1.2.3.4/api/v1/switching-profiles/%s'
                % test_constants_v3.FAKE_QOS_PROFILE['id'],
                data=jsonutils.dumps(
                    self._body_with_shaping(qos_marking="trusted"),
                    sort_keys=True))

    def test_delete_qos_switching_profile(self):
        """
        Test deleting qos-switching-profile
        """
        api = self.mocked_rest_fns(nsxlib, 'client')

        nsxlib.delete_qos_switching_profile(
            test_constants_v3.FAKE_QOS_PROFILE['id'])

        test_client.assert_json_call(
            'delete', api,
            'https://1.2.3.4/api/v1/switching-profiles/%s'
            % test_constants_v3.FAKE_QOS_PROFILE['id'])
