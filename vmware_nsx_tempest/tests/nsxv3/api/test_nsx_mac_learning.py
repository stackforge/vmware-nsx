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

from tempest.api.network import base
from tempest.common import custom_matchers
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test

from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF


class NSXv3MacLearningTest(base.BaseNetworkTest):
    """Test MAC Learning operations in the Neutron API.

       Create port with options required for enabling MAC Learning.
       List ports including created port with MAC Learning enabled.
       Show port details with options required for enabling MAC Learning.
       Update port with options required for enabling MAC Learning.
       Delete port.

       CRUD operation tests
       Workflow 1
       Workflow 2
       Workflow 3

       After the neutron API call, we also need to make sure the
       corresponding resource has been handled in the NSX backend.

    """

    @classmethod
    def resource_setup(cls):
        super(NSXv3MacLearningTest, cls).resource_setup()
        cls.network = cls.create_network()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                           CONF.nsxv3.nsx_user,
                                           CONF.nsxv3.nsx_password)

    def _get_nsx_mac_learning_enabled(self, port):
        mac_learn_set_bool = False
        # Get nsxv3 port(expects 'name' set)
        nsx_port = self.nsx.get_logical_port(port['name'])
        # Get list of logical port's switch profiles
        port_swtch_profs = self.nsx.get_lport_switching_profiles(nsx_port)
        # Convert switch profiles list to dict, key:UUID
        port_sw_prof_dict = self._conv_switch_prof_to_dict(port_swtch_profs)
        # Get MAC learning switch profile ID
        mac_sw_prof_id = port_sw_prof_dict[constants.MAC_SW_PROFILE]
        # Get MAC learning switch profile json
        mac_sw_profile_json = self.nsx.get_switching_profile(
            mac_sw_prof_id)
        # Get mac-learning state for port
        if ('mac_learning' in mac_sw_profile_json):
            nsxport_mac_learning = mac_sw_profile_json[
                'mac_learning']['enabled']
            if nsxport_mac_learning:
                mac_learn_set_bool = True
        return mac_learn_set_bool

    def _create_mac_learn_enabled_port(self, network):
        # Create Port with required port security/sec groups config
        test_port = data_utils.rand_name('port-')
        port = self.create_port(self.network, name=test_port,
                                mac_learning_enabled=True,
                                port_security_enabled=False,
                                security_groups=[])
        return port

    def _update_port_enable_mac_learning(self, port):
        updated_port = self.update_port(port,
                                        mac_learning_enabled=True,
                                        port_security_enabled=False,
                                        security_groups=[])
        return updated_port

    def _update_port_disable_mac_learning(self, port, sec_groups=None):
        if sec_groups is None:
            sec_groups = []
        updated_sec_grp = port['security_groups'] + sec_groups
        updated_port = self.update_port(port,
                                        mac_learning_enabled=False,
                                        port_security_enabled=True,
                                        security_groups=updated_sec_grp)
        return updated_port

    def _delete_port(self, port):
        port_id = port['id']
        self.ports_client.delete_port(port_id)
        body = self.ports_client.list_ports()
        ports_list = body['ports']
        if len(ports_list) > 0:
            self.assertFalse(port_id in [n['id'] for n in ports_list])

    def _conv_switch_prof_to_dict(self, switch_profiles):
        switch_prof_dict = {}
        for i in range(len(switch_profiles)):
            switch_prof_dict.update(
                {switch_profiles[i]['key']: switch_profiles[i]['value']})
        return switch_prof_dict

    def _check_mac_learning(self, port, mac_learn_state=True):
        # Enabling MAC Learning requires port security=False and no sec grps
        nsxport_mac_learning = self._get_nsx_mac_learning_enabled(port)
        if mac_learn_state:
            self.assertEmpty(port['security_groups'])
            self.assertFalse(port['port_security_enabled'])
            self.assertTrue(port['mac_learning_enabled'])
            self.assertEqual(nsxport_mac_learning,
                             port['mac_learning_enabled'])
        else:
            self.assertTrue(port['port_security_enabled'])
            if 'mac_learning_enabled' in port.keys():
                self.assertFalse(port['mac_learning_enabled'])
                self.assertEqual(nsxport_mac_learning,
                                 port['mac_learning_enabled'])

    @test.attr(type='nsxv3')
    @test.idempotent_id('bb8a0eee-954e-11e6-ae22-56b6b6499611')
    def test_create_mac_learning_port(self):
        """
        Test creation of MAC Learning enabled port
         """
        port = self._create_mac_learn_enabled_port(self.network)
        self._check_mac_learning(port, mac_learn_state=True)

    @test.attr(type='nsxv3')
    @test.idempotent_id('bb8a12c2-954e-11e6-ae22-56b6b6499611')
    def test_list_mac_learning_port(self):
        """
        Create port with MAC learning enabled. Create vanilla port.
        Verify that the created ports are included in list_ports().
        """
        mac_lrn_port = self._create_mac_learn_enabled_port(self.network)
        vanilla_name = data_utils.rand_name('vanilla_port-')
        vanilla_port = self.create_port(self.network, name=vanilla_name)
        self._check_mac_learning(mac_lrn_port, mac_learn_state=True)
        self._check_mac_learning(vanilla_port, mac_learn_state=False)
        body = self.ports_client.list_ports()
        nill_nsx = self.nsx.get_logical_port(vanilla_port['name'])
        ml_port_nsx = self.nsx.get_logical_port(mac_lrn_port['name'])
        test_ports_in_body = []
        # Verify the each port exists in the list of all ports
        for tport in body['ports']:
            if(nill_nsx['display_name'] == tport['name']):
                test_ports_in_body.append(nill_nsx['display_name'])
            if(ml_port_nsx['display_name'] == tport['name']):
                test_ports_in_body.append(ml_port_nsx['display_name'])
        self.assertEqual(len(test_ports_in_body), 2,
                         'Both ports are not listed')

    @test.attr(type='nsxv3')
    @test.idempotent_id('bb8a161e-954e-11e6-ae22-56b6b6499611')
    def test_show_mac_learning_port(self):
        """
        Create port with MAC learning enabled with OS. Test port show api
        on the MAC enabled port.
        """
        port = self._create_mac_learn_enabled_port(self.network)
        nsx_port = self.nsx.get_logical_port(port['name'])
        nsxport_mac_learning = self._get_nsx_mac_learning_enabled(port)
        body = self.ports_client.show_port(port['id'])
        show_port_result = body['port']
        # Check the port ID exists and the  MAC learning state and name match
        self.assertIn('id', show_port_result)
        self.assertEqual(nsxport_mac_learning,
                         show_port_result['mac_learning_enabled'])
        self.assertEqual(nsx_port['display_name'], show_port_result['name'])
        # from upstream tempest test_show_port()
        self.assertThat(port,
                        custom_matchers.MatchesDictExceptForKeys
                        (show_port_result, excluded_keys=['extra_dhcp_opts',
                                                          'created_at',
                                                          'updated_at']))

    @test.attr(type='nsxv3')
    @test.idempotent_id('bb8a186c-954e-11e6-ae22-56b6b6499611')
    def test_update_mac_learning_port(self):
        """
        Create a MAC learning-enabled port on network. Update the port's
        name. Check name and MAC learning configuration.
        """
        test_port = self._create_mac_learn_enabled_port(self.network)
        update_port_name = data_utils.rand_name('updated_port-')
        updated_os_port = self.update_port(test_port,
                                           name=update_port_name)
        updated_nsx_port = self.nsx.get_logical_port(updated_os_port['name'])
        # Assert if NSXT and OS names do not match
        self.assertEqual(updated_nsx_port['display_name'],
                         updated_os_port['name'])
        # Check MAC Learn state between NSXT and OS match.
        nsxport_mac_learning = self._get_nsx_mac_learning_enabled(
            updated_os_port)
        self.assertEqual(nsxport_mac_learning,
                         updated_os_port['mac_learning_enabled'])

    @test.attr(type='nsxv3')
    @test.idempotent_id('bb8a1a24-954e-11e6-ae22-56b6b6499611')
    def test_delete_mac_learning_port(self):
        """
        Create MAC learning-enabled port on network. Verify port on
        NSX and OS. Delete port.
        """
        test_port = self._create_mac_learn_enabled_port(self.network)
        nsx_port = self.nsx.get_logical_port(test_port['name'])
        # Check created port name matches name on NSXT and NSXT id exists
        self.assertIsNotNone(nsx_port['id'])
        self.assertEqual(nsx_port['display_name'], test_port['name'])
        self._delete_port(test_port)
        self.assertIsNone(self.nsx.get_logical_port(test_port['name']))

    @test.attr(type='nsxv3')
    @test.idempotent_id('bb8a1be6-954e-11e6-ae22-56b6b6499611')
    def test_create_enable_mac_learning_port_delete(self):
        """
        CRUD Workflow 1

        Create vanilla network port
        Update port with options required and enable MAC Learning
        Delete port
        """
        test_port_name = data_utils.rand_name('port-')
        test_port = self.create_port(self.network, name=test_port_name)
        self._check_mac_learning(test_port, mac_learn_state=False)
        updated_os_port = self._update_port_enable_mac_learning(test_port)
        self._check_mac_learning(updated_os_port, mac_learn_state=True)
        self._delete_port(updated_os_port)
        self.assertIsNone(self.nsx.get_logical_port(updated_os_port['name']))

    @test.attr(type='nsxv3')
    @test.idempotent_id('bb8a1dda-954e-11e6-ae22-56b6b6499611')
    def test_create_toggle_mac_learning_port_delete(self):
        """
        CRUD Workflow 2

        Create port with MAC Learning enabled
        Update port, disabling MAC Learning
        Update port, re-enabling MAC Learning
        Delete port
        """
        test_port = self._create_mac_learn_enabled_port(self.network)
        self._check_mac_learning(test_port, mac_learn_state=True)
        ml_off_port = self._update_port_disable_mac_learning(test_port)
        self._check_mac_learning(ml_off_port, mac_learn_state=False)
        ml_on_port = self._update_port_enable_mac_learning(ml_off_port)
        self._check_mac_learning(ml_on_port, mac_learn_state=True)
        self._delete_port(ml_on_port)
        self.assertIsNone(self.nsx.get_logical_port(ml_on_port['name']))

    @test.attr(type='nsxv3')
    @test.idempotent_id('bb8a20f0-954e-11e6-ae22-56b6b6499611')
    def test_create_update_delete_mac_learning_port(self):
        """
        CRUD Workflow 3

        Create port with MAC Learning enabled
        Update port(non-MAC Learning settings)
        Delete port
        """
        test_port = self._create_mac_learn_enabled_port(self.network)
        new_port_name = data_utils.rand_name('updated_port-')
        updated_port = self.update_port(test_port,
                                        name=new_port_name)
        updated_nsx_port = self.nsx.get_logical_port(updated_port['name'])
        self.assertEqual(updated_nsx_port['display_name'],
                         updated_port['name'])
        self._delete_port(updated_port)
        self.assertIsNone(self.nsx.get_logical_port(updated_port['name']))
