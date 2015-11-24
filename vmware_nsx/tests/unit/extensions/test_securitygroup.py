# Copyright (c) 2015 VMware, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
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
import sys

from neutron.tests.unit.extensions import test_securitygroup as ext_sg

from vmware_nsx.nsxlib.v3 import dfw_api as firewall
from vmware_nsx.nsxlib.v3 import security
from vmware_nsx.plugins.nsx_v3 import plugin as nsx_plugin
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsxv3
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase


# Pool of fake ns-groups uuids
NSG_IDS = ['11111111-1111-1111-1111-111111111111',
           '22222222-2222-2222-2222-222222222222',
           '33333333-3333-3333-3333-333333333333',
           '44444444-4444-4444-4444-444444444444',
           '55555555-5555-5555-5555-555555555555']


def _mock_create_and_list_nsgroups(test_method):
    nsgroups = []

    def _create_nsgroup_mock(name, desc, tags):
        nsgroup = {'id': NSG_IDS[len(nsgroups)],
                   'display_name': name,
                   'desc': desc,
                   'tags': tags}
        nsgroups.append(nsgroup)
        return nsgroup

    def wrap(*args, **kwargs):
        with mock.patch.object(nsx_plugin.security.firewall,
                               'create_nsgroup') as create_nsgroup_mock:
            create_nsgroup_mock.side_effect = _create_nsgroup_mock
            with mock.patch.object(nsx_plugin.security.firewall,
                                   'list_nsgroups') as list_nsgroups_mock:
                list_nsgroups_mock.side_effect = lambda: nsgroups

                test_method(*args, **kwargs)
    return wrap


class TestSecurityGroups(test_nsxv3.NsxV3PluginTestCaseMixin,
                         ext_sg.TestSecurityGroups):

    @_mock_create_and_list_nsgroups
    @mock.patch.object(firewall, 'remove_nsgroup_member')
    @mock.patch.object(firewall, 'add_nsgroup_member')
    def test_create_port_with_multiple_security_groups(self,
                                                       add_member_mock,
                                                       remove_member_mock):
        super(TestSecurityGroups,
              self).test_create_port_with_multiple_security_groups()

        # The first nsgroup is associated with the default secgroup, which is
        # not added to this port.
        calls = [mock.call(NSG_IDS[1], mock.ANY, mock.ANY),
                 mock.call(NSG_IDS[2], mock.ANY, mock.ANY)]
        add_member_mock.assert_has_calls(calls, any_order=True)

    @_mock_create_and_list_nsgroups
    @mock.patch.object(firewall, 'remove_nsgroup_member')
    @mock.patch.object(firewall, 'add_nsgroup_member')
    def test_update_port_with_multiple_security_groups(self,
                                                       add_member_mock,
                                                       remove_member_mock):
        super(TestSecurityGroups,
              self).test_update_port_with_multiple_security_groups()

        calls = [mock.call(NSG_IDS[0], mock.ANY, mock.ANY),
                 mock.call(NSG_IDS[1], mock.ANY, mock.ANY),
                 mock.call(NSG_IDS[2], mock.ANY, mock.ANY)]
        add_member_mock.assert_has_calls(calls, any_order=True)

        remove_member_mock.assert_called_with(NSG_IDS[0], mock.ANY)

    @_mock_create_and_list_nsgroups
    @mock.patch.object(firewall, 'remove_nsgroup_member')
    @mock.patch.object(firewall, 'add_nsgroup_member')
    def test_update_port_remove_security_group_empty_list(self,
                                                          add_member_mock,
                                                          remove_member_mock):
        super(TestSecurityGroups,
              self).test_update_port_remove_security_group_empty_list()

        add_member_mock.assert_called_with(NSG_IDS[1], mock.ANY, mock.ANY)
        remove_member_mock.assert_called_with(NSG_IDS[1], mock.ANY)


class TestNSGroupContainerManager(nsxlib_testcase.NsxLibTestCase):
    """
    This test suite is responsible for unittesting of class
    vmware_nsx.nsxlib.v3.security.NSGroupContainerManager.
    """

    def _mock_builtin_hash(self):
        # We use the builtin hash function to determine the placement of
        # nsgroup, since `hash` implementation we want to mock
        # that builtin function, however it's a bit tricky since it's located
        # on a different modules in depending on the python version (2.x/3.x).
        if sys.version_info.major == 2:
            import __builtin__ as builtins
        else:
            import builtins
        # the mocked hash function will simply return 7
        return mock.patch.object(builtins, 'hash',
                                 new_callable=lambda: lambda obj: 7)

    @_mock_create_and_list_nsgroups
    def test_first_initialization(self):
        size = 5
        cont_manager = security.NSGroupContainerManager(size)
        containers = cont_manager._containers
        self.assertEqual(size, len(containers))
        for i in range(size):
            self.assertEqual(NSG_IDS[i], containers[i])

    @_mock_create_and_list_nsgroups
    def test_num_containers_reconfigure(self):
        # We need to test that when changing the number of containers then the
        # NSGroupContainerManager picks the ones which were previously created
        # and create the ones which are missing, which also verifies that it
        # also recognizes existing containers.

        size = 2
        # Creates 2 nsgroup containers.
        security.NSGroupContainerManager(size)

        size = 5
        # Creates another 3 nsgroup containers.
        containers = security.NSGroupContainerManager(size)._containers
        self.assertEqual(size, len(containers))
        for i in range(size):
            self.assertEqual(NSG_IDS[i], containers[i])

    @_mock_create_and_list_nsgroups
    @mock.patch.object(firewall, 'remove_nsgroup_member')
    @mock.patch.object(firewall, 'add_nsgroup_member')
    def test_add_and_remove_nsgroups(self,
                                     add_member_mock,
                                     remove_member_mock):
        # We verify that when adding a new nsgroup the properly placed
        # according to its id and the number of nsgroup containers.

        size = 5
        cont_manager = security.NSGroupContainerManager(size)
        nsgroup_id = 'nsgroup_id'

        with self._mock_builtin_hash():
            cont_manager.add_nsgroup(nsgroup_id)
            cont_manager.remove_nsgroup(nsgroup_id)

        # There are 5 containers, the hash function will return 7, therefore we
        # expect that the nsgroup will be placed in the 3rd container.
        add_member_mock.assert_called_once_with(
            NSG_IDS[2], firewall.NSGROUP, nsgroup_id)
        remove_member_mock.assert_called_once_with(
            NSG_IDS[2], nsgroup_id, verify=True)

    def test_container_is_out_of_space(self):
        pass
