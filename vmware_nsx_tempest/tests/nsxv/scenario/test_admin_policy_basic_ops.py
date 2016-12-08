# Copyright 2016 VMware Inc
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

import six

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest import test

from vmware_nsx_tempest.tests.nsxv.scenario import (
    manager_topo_deployment as dmgr)
from vmware_nsx_tempest.tests.nsxv.scenario import (
    network_addon_methods as HELO)

CONF = config.CONF


class TestAdminPolicyBasicOps(dmgr.TopoDeployScenarioManager):
    """Test VMs with security-group-policy traffic is managed by NSX

    Test topology:
        TOPO: refer to test plan: https://goo.gl/PiA0KQ

        Test topology setup and traffic forwarding validation:

        1.*1 2 tenants (ames, jpl) each tenant has 2 VMs, and boot with
           security-group with policy==policy-AA which must allow
           ping and ssh services as automation relys on this to make
           sure test environment network connectivity is an OK.
        2. Admin create router (nasa-router) with both tenants' network
           so tenant:ames and tenant:jpl can talk to each other according
           to policy-AA.
        3. under policy-AA, all servers can be ping and ssh from anywhere
        4.*2 Admin change tenant:jpl's policy to policy-BB
        5. Tenant jpl's VMs are not pingable, ssh still OK
           Tenant ames's MVs, both ping and ssh are OK
        6.*3 Admin change tenant:ames's policy to policy-BB
           VMs from ames and jpl are not pingalbe; ssh is OK

    ATTENTION:
        config nsxv.default_policy_id is policy_AA
        config nsxv.alt_policy_is is policy_BB

        The testbed needs to have policy_AA and policy_BB created
        and matched with the default_policy_id & alt_plicy_id under
        session nsxv of tempest.conf or devstack local.conf.
    """

    @classmethod
    def skip_checks(cls):
        super(TestAdminPolicyBasicOps, cls).skip_checks()
        if not test.is_extension_enabled('security-group-policy', 'network'):
            msg = "Extension security-group-policy is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(TestAdminPolicyBasicOps, cls).setup_clients()
        cls.cmgr_adm = cls.get_client_manager('admin')
        cls.cmgr_ames = cls.get_client_manager('primary')
        cls.cmgr_jpl = cls.get_client_manager('alt')

    @classmethod
    def resource_setup(cls):
        super(TestAdminPolicyBasicOps, cls).resource_setup()
        cls.policy_AA = CONF.nsxv.default_policy_id
        cls.policy_BB = CONF.nsxv.alt_policy_id

    @classmethod
    def resource_cleanup(cls):
        super(TestAdminPolicyBasicOps, cls).resource_cleanup()

    def setUp(self):
        super(TestAdminPolicyBasicOps, self).setUp()
        self.server_id_list = []
        self.exc_msg = ("Admin-Policy-Traffic-Forwarding test steps:\n"
                        "Both tenants with policy_AA[%s]:\n"
                        % self.policy_AA)

    def tearDown(self):
        # delete all servers and make sure they are terminated
        servers_client = self.cmgr_adm.servers_client
        server_id_list = getattr(self, 'server_id_list', [])
        for server_id in server_id_list:
            servers_client.delete_server(server_id)
        for server_id in server_id_list:
            waiters.wait_for_server_termination(servers_client, server_id)
        # delete all floating-ips
        if hasattr(self, 'fip_nasa_ames_1'):
            self.delete_floatingip(self.cmgr_ames, self.fip_nasa_ames_1) 
        if hasattr(self, 'fip_nasa_jpl_3'):
            self.delete_floatingip(self.cmgr_jpl, self.fip_nasa_jpl_3) 
        super(TestAdminPolicyBasicOps, self).tearDown()

    def delete_floatingip(self, cmgr, net_floatingip):
        test_utils.call_and_ignore_notfound_exc(
            cmgr.floating_ips_client.delete_floatingip,
            net_floatingip.get('id'))

    def delete_security_group(self, sg_client, sg_id):
        sg_client.delete_security_group(sg_id)

    def create_security_group_policy(self, policy_id, tenant_id,
                                     name_prefix=None):
        sg_name = data_utils.rand_name(name_prefix or 'admin-policy')
        sg_client = self.cmgr_adm.security_groups_client
        sg_dict = dict(name=sg_name, policy=policy_id)
        if tenant_id:
            sg_dict['tenant_id'] = tenant_id
        sg = sg_client.create_security_group(**sg_dict)
        sg = sg.get('security_group', sg)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_security_group,
                        sg_client, sg.get('id'))
        return sg

    def create_networks(self, cmgr,
                        name_prefix=None, cidr_offset=0):
        net_name = data_utils.rand_name(name_prefix or 'admin-policy')
        network = self.create_network(client=cmgr.networks_client,
                                      name=net_name)
        network = network.get('network', network)
        subnet_kwargs = dict(name=net_name, cidr_offset=cidr_offset)
        subnet = self.create_subnet(network,
                                    client=cmgr.subnets_client,
                                    **subnet_kwargs)
        subnet = subnet.get('subnet', subnet)
        return (network, subnet)

    def create_router_by_type(self, router_type, client=None, **kwargs):
        routers_client = client or self.cmgr_adm.routers_client
        create_kwargs = dict(namestart='nasa-router', external_gateway_info={
            "network_id": CONF.network.public_network_id})
        if router_type in ('shared', 'exclusive'):
            create_kwargs['router_type'] = router_type
        elif router_type in ('distributed'):
            create_kwargs['distributed'] = True
        create_kwargs.update(**kwargs)
        router = HELO.router_create(self, client=routers_client,
                                    **create_kwargs)
        return router

    def create_router_and_add_interfaces(self, router_type, subnet_list):
        routers_client = self.cmgr_adm.routers_client
        router = self.create_router_by_type(router_type)
        for subnet in subnet_list:
            HELO.router_interface_add(self, router['id'], subnet['id'],
                                      client=routers_client)
        # check interfaces/subnets are added to router
        router_port_list = self.get_router_port_list(self.cmgr_adm,
                                                     router['id'])
        for subnet in subnet_list:
            added = self.rports_have_subnet_id(router_port_list, subnet['id'])
            self.assertTrue(
                added,
                "subnet_id:%s is not added to router" % subnet['id'])
        return router

    def rports_have_subnet_id(self, router_port_list, subnet_id):
        for rport in router_port_list:
            for fips in rport.get('fixed_ips', []):
                if subnet_id == fips['subnet_id']:
                    return True
        return False

    def get_router_port_list(self, cmgr, router_id):
        device_owner = u'network:router_interface'
        ports_client = cmgr.ports_client
        port_list = ports_client.list_ports(device_id=router_id,
                                            device_owner=device_owner)
        port_list = port_list.get('ports', port_list)
        return port_list

    def create_servers_on_networks(self, cmgr, sv_name, networks_info):
        network = networks_info.get('network')
        security_group = networks_info.get('security_group')
        security_groups = [{'name': security_group['id']}]
        svr = self.create_server_on_network(
            network, security_groups, name=sv_name,
            wait_on_boot=False,
            servers_client=cmgr.servers_client)
        self.server_id_list.append(svr.get('id'))
        return svr

    def get_server_info(self, cmgr, server_id):
        """Get server's ip addresses"""
        svr = cmgr.servers_client.show_server(server_id)
        svr = svr.get('server', svr)
        sinfo = dict(id=svr['id'], name=svr['name'],
                     security_gropus=svr['security_groups'],
                     fixed_ip_address=None, floating_ip_address=None)
        addresses = svr.get('addresses')
        for n_addresses in six.itervalues(addresses):
            for n_addr in n_addresses:
                if n_addr['OS-EXT-IPS:type'] == 'fixed':
                    if not sinfo['fixed_ip_address']:
                        sinfo['fixed_ip_address'] = n_addr['addr']
                elif n_addr['OS-EXT-IPS:type'] == 'floating':
                    if not sinfo['floating_ip_address']:
                        sinfo['floating_ip_address'] = n_addr['addr']
        return sinfo

    def create_floatingip_for_server(self, cmgr, server):
        username, password = self.get_image_userpass()
        floatingip = super(TestAdminPolicyBasicOps,
                           self).create_floatingip_for_server(
            server, client_mgr=cmgr, and_check_assigned=True)
        msg = ("Associate floatingip[%s] to server[%s]"
               % (floatingip, server['name']))
        self._check_floatingip_connectivity(
            floatingip, server, should_connect=True, msg=msg,
            floating_ips_client=cmgr.floating_ips_client)
        return floatingip

    def wait_for_servers_become_active(self):
        servers_client = self.cmgr_adm.servers_client
        for server_id in self.server_id_list:
            waiters.wait_for_server_status(
                servers_client, server_id, 'ACTIVE')

    def find_servers_ips(self):
        self.server_ips = {}
        self.jpl_ips = {}
        self.server_ips['1'] = self.get_server_info(
            self.cmgr_ames, self.vm_nasa_ames_1['id'])
        self.server_ips['2'] = self.get_server_info(
            self.cmgr_ames, self.vm_nasa_ames_2['id'])
        self.server_ips['3'] = self.get_server_info(
            self.cmgr_jpl, self.vm_nasa_jpl_3['id'])
        self.server_ips['4'] = self.get_server_info(
            self.cmgr_jpl, self.vm_nasa_jpl_4['id'])

    def create_nasa_ames_network_and_servers(self, security_group=None):
        sg = security_group or self.sg_ames
        net, subnet = self.create_networks(self.cmgr_ames, 'nasa-ames', 1)
        self.netinfo_ames = dict(network=net, subnet=subnet,
                                 security_group=sg)
        self.vm_nasa_ames_1 = self.create_servers_on_networks(
            self.cmgr_ames, 'vm-nasa-ames-1', self.netinfo_ames)
        self.vm_nasa_ames_2 = self.create_servers_on_networks(
            self.cmgr_ames, 'vm-nasa-ames-2', self.netinfo_ames)

    def create_nasa_jpl_network_and_servers(self, security_group=None):
        sg = security_group or self.sg_jpl
        # jpl and ames attached to the same router, CIDR cannot overlap
        net, subnet = self.create_networks(self.cmgr_jpl, 'nasa-jpl', 3)
        self.netinfo_jpl = dict(network=net, subnet=subnet,
                                security_group=sg)
        self.vm_nasa_jpl_3 = self.create_servers_on_networks(
            self.cmgr_jpl, 'vm-nasa-jpl-3', self.netinfo_jpl)
        self.vm_nasa_jpl_4 = self.create_servers_on_networks(
            self.cmgr_jpl, 'vm-nasa-jpl-4', self.netinfo_jpl)

    def create_nasa_topo(self, router_type=None):
        router_type = router_type or 'shared'
        self.sg_ames = self.create_security_group_policy(
            self.policy_AA,
            self.cmgr_ames.networks_client.tenant_id,
            name_prefix='nasa-ames')
        self.sg_jpl = self.create_security_group_policy(
            self.policy_AA,
            self.cmgr_jpl.networks_client.tenant_id,
            name_prefix='nasa-jpl')
        self.create_nasa_ames_network_and_servers(self.sg_ames)
        self.create_nasa_jpl_network_and_servers(self.sg_jpl)
        subnet_list = [self.netinfo_ames.get('subnet'),
                       self.netinfo_jpl.get('subnet')]
        self.nasa_router = self.create_router_and_add_interfaces(
            router_type, subnet_list)
        self.wait_for_servers_become_active()
        # associate floating-ip to servers and pingable
        self.fip_nasa_ames_1 = self.create_floatingip_for_server(
            self.cmgr_ames, self.vm_nasa_ames_1)
        self.fip_nasa_jpl_3 = self.create_floatingip_for_server(
            self.cmgr_jpl, self.vm_nasa_jpl_3)
        self.find_servers_ips()

    def host_ssh_reachable(self, host_ip):
        username, password = self.get_image_userpass()
        ssh_client = dmgr.get_remote_client_by_password(
            host_ip, username, password)
        return ssh_client

    def host_ssh_not_reachable(self, host_ip):
        """This is-not the best method to check host is-not ssh reachable!"""
        username, password = self.get_image_userpass()
        try:
            dmgr.get_remote_client_by_password(host_ip, username, password)
            return False
        except Exception:
            return True

    def host_can_reach_ips(self, host_id, host_ssh, ip_list):
        for dest_ip in ip_list:
            reachable = dmgr.dest_is_reachable(host_ssh, dest_ip)
            msg = (self.exc_msg +
                   "VM[%s] cannot reach dest[%s]" % (host_id, dest_ip))
            self.assertTrue(reachable, msg)
            self.exc_msg += ("   VM[%s] can reach dest[%s]\n" %
                             (host_id, dest_ip))

    def run_basic_scenario(self, router_type):
        self.create_nasa_topo(router_type)
        ### Both tenants with policy_AA: 
        # at the beginning, can ssh to VM with floating-ip
        self.exc_msg += "Can ssh vm-nasa-ames-1\n"
        ames_1_ssh = self.host_ssh_reachable(
            self.fip_nasa_ames_1['floating_ip_address'])
        self.exc_msg += "Can ssh vm-nasa-jpl-3\n"
        jpl_3_ssh = self.host_ssh_reachable(
            self.fip_nasa_jpl_3['floating_ip_address'])
        # all private-ips are reachable too.
        private_ips = [y['fixed_ip_address']
                       for y in six.itervalues(self.server_ips)]
        # from vm-nasa-ames-1 can ping all other private-ips
        self.exc_msg += ("vm-nasa-ames-1[%s] can reach all private-ips\n"
                         % (self.server_ips['1']['fixed_ip_address']))
        self.host_can_reach_ips('nasa-ames-1', ames_1_ssh, private_ips)
        # from vm-nasa-jpl_3 can ping all other private-ips
        self.exc_msg += ("vm-nasa-jpl-3[%s] can reach all private-ips\n"
                         % (self.server_ips['3']['fixed_ip_address']))
        self.host_can_reach_ips('nasa-jpl-3', jpl_3_ssh, private_ips)
        # within VM can ping both tanants' floating-ips
        self.exc_msg += "vm-nasa-ames-1 can reach vm-nasa-jpl-1 floatingip\n"
        self.host_can_reach_ips(
            'nasa-ames-1', ames_1_ssh,
            [self.fip_nasa_jpl_3['floating_ip_address']])
        self.exc_msg += "vm-nasa-jpl-3 can reach vm-nasa-ames-3 floatingip\n"
        self.host_can_reach_ips(
            'nasa-jpl-3', jpl_3_ssh,
            [self.fip_nasa_ames_1['floating_ip_address']])

        ### tenant jpl:policy_BB, tenant ames:policy_AA
        # admin update jpl to policy-BB
        # cannot ping vm-nasa-jpl-3, can ssh to both tenants' floating-ips

        ### both tenants with policy_BB
        # admin update ames to policy-BB
        # cannot ping all VMs, but can ssh to both tenants' floating-ips
        dmgr.LOG.debug(self.exc_msg)


class TestAdminPolicySharedRouter(TestAdminPolicyBasicOps):
    @test.idempotent_id('78f45717-5f95-4ef5-b2a4-a1b4700ef688')
    def test_admin_policy_ops_with_shared_router(self):
        self.run_basic_scenario('shared')


class TestAdminPolicyExclusiveRouter(TestAdminPolicyBasicOps):
    @test.idempotent_id('68345852-da2e-4f46-816b-0afc59470a45')
    def test_admin_policy_ops_with_exclusive_router(self):
        self.run_basic_scenario('exclusive')


class TestAdminPolicyDistributedRouter(TestAdminPolicyBasicOps):
    @test.idempotent_id('76adbfbb-a2e5-40fa-8930-84e7ece87bd5')
    def test_admin_policy_ops_with_distributed_router(self):
        self.run_basic_scenario('distributed')
