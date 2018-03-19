# dummy change to test neutron/master access in the gate

from neutron.extensions import securitygroup
from neutron.tests import base


class TestNeutronMaster(base.BaseTestCase):

    def test_sec_group_exception(self):
        # SecurityGroupInvalidProtocolForPortRange recently
        # added to neutron/master
        self.assertIsNotNone(
            securitygroup.SecurityGroupInvalidProtocolForPortRange)
