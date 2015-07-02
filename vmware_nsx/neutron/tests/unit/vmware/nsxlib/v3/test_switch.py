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
import requests

from oslo_log import log

from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib
from vmware_nsx.neutron.tests.unit.vmware.nsxlib.v3 import nsxlib_testcase
from vmware_nsx.neutron.tests.unit.vmware import test_constants_v3

LOG = log.getLogger(__name__)


class NsxLibSwitchTestCase(nsxlib_testcase.NsxLibTestCase):

    def _create_mock_object(self, fake_object):
        """Construct mock response object"""
        mock_response = mock.Mock()
        mock_response.json.return_value = fake_object
        return mock_response

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3.requests.post")
    def test_create_logical_switch(self, mock_post):
        """
        Test creating a switch returns the correct response and 200 status
        """
        mock_post.return_value = self._create_mock_object(
                                     test_constants_v3.FAKE_SWITCH)
        mock_post.return_value.status_code = requests.codes.created

        result = nsxlib.create_logical_switch(
                    test_constants_v3.FAKE_NAME,
                    test_constants_v3.FAKE_TZ_UUID, tags={})
        self.assertEqual(test_constants_v3.FAKE_SWITCH, result)

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3.requests.post")
    def test_create_logical_switch_admin_down(self, mock_post):
        """
        Test creating switch with admin_state down
        """
        fake_switch = test_constants_v3.FAKE_SWITCH
        fake_switch['admin_state'] = "DOWN"
        mock_post.return_value = self._create_mock_object(fake_switch)
        mock_post.return_value.status_code = requests.codes.created

        result = nsxlib.create_logical_switch(
                    test_constants_v3.FAKE_NAME,
                    test_constants_v3.FAKE_TZ_UUID, tags={}, admin_state=False)
        self.assertEqual(fake_switch, result)

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3.requests.post")
    def test_create_logical_switch_vlan(self, mock_post):
        """
        Test creating switch with provider:network_type VLAN
        """
        fake_switch = test_constants_v3.FAKE_SWITCH
        fake_switch['vlan_id'] = '123'
        mock_post.return_value = self._create_mock_object(fake_switch)
        mock_post.return_value.status_code = requests.codes.created

        result = nsxlib.create_logical_switch(
                    test_constants_v3.FAKE_NAME,
                    test_constants_v3.FAKE_BRIDGED_TZ_UUID, tags={})
        self.assertEqual(fake_switch, result)

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3.requests.delete")
    def test_delete_logical_switch(self, mock_delete):
        """
        Test deleting switch
        """
        mock_delete.return_value = self._create_mock_object(None)
        mock_delete.return_value.status_code = requests.codes.ok

        result = nsxlib.delete_logical_switch(
                     test_constants_v3.FAKE_SWITCH['id'])
        self.assertIsNone(result)
