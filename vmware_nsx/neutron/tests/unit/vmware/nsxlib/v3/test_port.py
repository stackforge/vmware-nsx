# Copyright (c) 2014 VMware, Inc.
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

import copy
import mock
from oslo_log import log
import requests

from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib
from vmware_nsx.neutron.tests.unit.vmware.nsxlib.v3 import nsxlib_testcase
from vmware_nsx.neutron.tests.unit.vmware import test_constants_v3

LOG = log.getLogger(__name__)


class NsxLibPortTestCase(nsxlib_testcase.NsxLibTestCase):

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3.requests.post")
    def test_create_logical_port(self, mock_post):
        """
        Test creating a port returns the correct response and 200 status
        """
        # Construct mock response object
        mock_response = mock.Mock()
        mock_response.json.return_value = copy.deepcopy(
            test_constants_v3.FAKE_PORT)
        mock_response.status_code = requests.codes.created
        mock_post.return_value = mock_response

        result = nsxlib.create_logical_port(
                     test_constants_v3.FAKE_PORT['logical_switch_id'],
                     test_constants_v3.FAKE_PORT['attachment']['id'])

        self.assertEqual(result, test_constants_v3.FAKE_PORT)

    @mock.patch("vmware_nsx.neutron.plugins.vmware.nsxlib.v3.requests.post")
    def test_create_logical_port_admin_down(self, mock_post):
        """
        Test creating port with admin_state down
        """
        # Construct mock response object
        mock_response = mock.Mock()
        fake_port = copy.deepcopy(test_constants_v3.FAKE_PORT)
        fake_port['admin_state'] = "DOWN"
        mock_response.json.return_value = fake_port
        mock_response.status_code = requests.codes.created
        mock_post.return_value = mock_response

        result = nsxlib.create_logical_port(
                     test_constants_v3.FAKE_PORT['logical_switch_id'],
                     test_constants_v3.FAKE_PORT['attachment']['id'],
                     admin_state=False)

        self.assertEqual(result, fake_port)


if __name__ == "__main__":
    import unittest
    unittest.main(verbosity=2)
