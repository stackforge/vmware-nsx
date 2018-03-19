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

# dummy change to test neutron/master access in the gate

from neutron.extensions import securitygroup
from neutron.tests import base


class TestNeutronMaster(base.BaseTestCase):

    def test_sec_group_exception(self):
        # SecurityGroupInvalidProtocolForPortRange recently
        # added to neutron/master
        self.assertIsNotNone(
            securitygroup.SecurityGroupInvalidProtocolForPortRange)
