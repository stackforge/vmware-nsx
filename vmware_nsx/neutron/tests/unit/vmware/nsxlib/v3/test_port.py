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


class NsxLibPortTestCase(nsxlib_testcase.NsxLibTestCase):

    def _create_mock_object(self, fake_object):
        """Construct mock response object"""
        mock_response = mock.Mock()
        if fake_object is not None:
            mock_response.json.return_value = fake_object
        return mock_response

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3.requests.post")
    def test_create_logical_port(self, mock_post):
        """
        Test creating a port returns the correct response and 200 status
        """
        mock_post.return_value = self._create_mock_object(
                                     test_constants_v3.FAKE_PORT)
        mock_post.return_value.status_code = requests.codes.created

        result = nsxlib.create_logical_port(
                     test_constants_v3.FAKE_PORT['logical_switch_id'],
                     test_constants_v3.FAKE_PORT['attachment']['id'],
                     tags={})

        self.assertEqual(test_constants_v3.FAKE_PORT, result)

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3.requests.post")
    def test_create_logical_port_admin_down(self, mock_post):
        """
        Test creating port with admin_state down
        """
        fake_port = test_constants_v3.FAKE_PORT
        fake_port['admin_state'] = "DOWN"
        mock_post.return_value = self._create_mock_object(fake_port)
        mock_post.return_value.status_code = requests.codes.created

        result = nsxlib.create_logical_port(
                     test_constants_v3.FAKE_PORT['logical_switch_id'],
                     test_constants_v3.FAKE_PORT['attachment']['id'],
                     tags={}, admin_state=False)

        self.assertEqual(fake_port, result)

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3.requests.delete")
    def test_delete_logical_port(self, mock_delete):
        """
        Test deleting port
        """
        mock_delete.return_value = self._create_mock_object(None)
        mock_delete.return_value.status_code = requests.codes.ok

        result = nsxlib.delete_logical_port(
                     test_constants_v3.FAKE_PORT['id'])
        self.assertIsNone(result)
