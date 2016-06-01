# Copyright 2016 OpenStack Foundation
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

import paramiko
import re
import sys
import time

from tempest import config
from tempest.lib.common.utils import data_utils

from vmware_nsx_tempest.services import nsxv_client
from vmware_nsx_tempest.tests.nsxv.scenario import (
    manager_topo_deployment as dmgr)

DHCP_121_DEPLOY_TOPO = "Testcase DHCP-121 option [%s] deploying"
CONF = config.CONF
DHCP_121_DEPLOY_COMPLETED = "Testcase [%s] deploy test-completed."
FLAT_ALLOC_DICT = CONF.scenario.flat_alloc_pool_dict
LOG = dmgr.manager.log.getLogger(__name__)
Metadataserver_ip = '169.254.169.254'


class TestDHCP121BasicOps(dmgr.TopoDeployScenarioManager):

    """Base class provides DHCP 121 options operations:

    """
    @classmethod
    def skip_checks(cls):
        super(TestDHCP121BasicOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        # Raise skip testcase exception if nsx-v version is less than 6.2.3
        if (CONF.nsxv.nsxv_version and CONF.nsxv.nsxv_version < '6.2.3'):
            msg = ('NSX-v version should be greater than equal to 6.2.3')
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestDHCP121BasicOps, cls).resource_setup()
        manager_ip = re.search(r"(\d{1,3}\.){3}\d{1,3}",
                               CONF.nsxv.manager_uri).group(0)
        cls.vsm = nsxv_client.VSMClient(
            manager_ip, CONF.nsxv.user, CONF.nsxv.password)
        cls.admin_networks_client = cls.admin_manager.networks_client
        cls.admin_subnets_client = cls.admin_manager.subnets_client
        cls.admin_routers_client = cls.admin_manager.routers_client

    @classmethod
    def resource_cleanup(cls):
        super(TestDHCP121BasicOps, cls).resource_cleanup()

    def setUp(self):
        super(TestDHCP121BasicOps, self).setUp()

    def tearDown(self):
        try:
            self.remove_project_network(False)
        except Exception:
            pass
        super(TestDHCP121BasicOps, self).tearDown()

    def remove_project_network(self, from_test=True):
        project_name = 'green'
        tenant = getattr(self, project_name, None)
        servers_client = tenant['client_mgr'].servers_client
        dmgr.delete_all_servers(servers_client)
        self.disassociate_floatingip(tenant['fip1'])
        if from_test:
            time.sleep(dmgr.WAITTIME_AFTER_DISASSOC_FLOATINGIP)
        fip_client = tenant['client_mgr'].floating_ips_client
        fip_client.delete_floatingip(tenant['fip1'].id)
        tenant.pop('fip1')
        tenant['router'].delete_subnet(tenant['subnet'])
        tenant['subnet'].delete()
        tenant['network'].delete()

    def check_server_connected(self, serv):
        # Fetch tenant-network from where vm deployed
        serv_net = list(serv['addresses'].keys())[0]
        serv_addr = serv['addresses'][serv_net][0]
        host_ip = serv_addr['addr']
        self.waitfor_host_connected(host_ip)

    def create_project_network_subnet(self,
                                      name_prefix='dhcp-project'):
        network_name = data_utils.rand_name(name_prefix)
        network, subnet = self.create_network_subnet(
            name=network_name)
        return (network.id, network, subnet)

    def test_dhcp_121_metadata_check_on_vm_nsxv(self):
        LOG.debug(DHCP_121_DEPLOY_TOPO, "metadata check on vm and on nsx")
        self.vm_env = self.setup_vm_enviornment(self.manager, 'green', True)
        self.green = self.dhcp_121_metadata_hostroutes_check_on_vm_nsxv(
            self.vm_env)
        self.remove_project_network()
        self.green['router'].unset_gateway()
        self.green['router'].delete()
        LOG.debug(DHCP_121_DEPLOY_COMPLETED, "DHCP 121 metadata, \
            host-routes check on vm and nsxv")

    def dhcp_121_metadata_hostroutes_check_on_vm_nsxv(self, vm_env):
        self.serv_fip = vm_env['fip1'].floating_ip_address
        username, password = self.get_image_userpass()
        # connect to instance launched using paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.serv_fip, username=username, password=password)
        cmd = ('route -n')
        # Executes route over instance launched
        stdin, stdout, stderr = client.exec_command(cmd)
        self.assertIn(Metadataserver_ip, stdout.read())
        LOG.debug('Metadata routes available on vm')
        cmd = ('wget  http://169.254.169.254 -O sample.txt')
        stdin, stdout, stderr = client.exec_command(cmd)
        cmd = ('cat sample.txt')
        stdin, stdout, stderr = client.exec_command(cmd)
        metadata_exists = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')
        if (metadata_exists.match(stdout.read())):
            LOG.debug('metadata server is acessible')
        client.close()
        exc_edge = self.vsm.get_dhcp_edge_info()
        self.assertIsNotNone(exc_edge)
        # Fetch host-route and metadata info from nsx-v
        dhcp_options_info = {}
        dhcp_options_info = \
            exc_edge['staticBindings']['staticBindings'][0]['dhcpOptions']
        # Check Host Route information avaialable at beckend
        self.assertIn(
            Metadataserver_ip,
            dhcp_options_info['option121'][
                'staticRoutes'][0]['destinationSubnet'])
        # Storing sec-group, network, subnet, router, server info in dict
        project_dict = dict(security_group=vm_env['security_group'],
                            network=vm_env['network'], subnet=vm_env['subnet'],
                            router=vm_env['router'],
                            client_mgr=vm_env['client_mgr'],
                            serv1=vm_env['serv1'], fip1=vm_env['fip1'])
        return project_dict

    def test_dhcp_121_hostroutes_clear(self):
        LOG.debug(DHCP_121_DEPLOY_TOPO, "host routes clear")
        self.vm_env = self.setup_vm_enviornment(self.manager, 'green', True)
        self.green = self.dhcp_121_hostroutes_clear(self.vm_env)
        self.remove_project_network()
        self.green['router'].unset_gateway()
        self.green['router'].delete()
        LOG.debug(DHCP_121_DEPLOY_COMPLETED, "dhcp 121 host routes clear")

    def dhcp_121_hostroutes_clear(self, vm_env):
        # Fetch next hop information from tempest.conf
        next_hop = CONF.network.project_network_cidr
        self.nexthop_host_route = next_hop.rsplit('.', 1)[0]
        self.nexthop1 = self.nexthop_host_route + ".2"
        # Floating-ip of VM
        self.serv_fip = vm_env['fip1'].floating_ip_address
        username, password = self.get_image_userpass()
        # Update subnet with host routes
        _subnet_data = {'host_routes': [{'destination': '10.20.0.0/32',
                                         'nexthop': '10.100.1.1'}],
                        'new_host_routes': [{'destination': '10.20.0.0/32',
                                             'nexthop': self.nexthop1}]}
        new_host_routes = _subnet_data['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "New_subnet"
        subnet_id = vm_env['subnet']['id']
        # Update subnet with host-route info
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Connect to instance using paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.serv_fip, username=username, password=password)
        # Check route info is avialable  on VM
        cmd = ('route -n')
        stdin, stdout, stderr = client.exec_command(cmd)
        self.assertIn(
            _subnet_data['new_host_routes'][0]['nexthop'], stdout.read())
        stdin, stdout, stderr = client.exec_command(cmd)
        self.assertIn(self.nexthop_host_route, stdout.read())
        LOG.debug('Host routes available on vm')
        client.close()
        # Check Host route info at beckend
        exc_edge = self.vsm.get_dhcp_edge_info()
        self.assertIsNotNone(exc_edge)
        # Fetch host-route and metadata info from nsx-v
        dhcp_options_info = {}
        dhcp_options_info = exc_edge['staticBindings']['staticBindings'][0][
            'dhcpOptions']['option121']['staticRoutes']
        # Check Host Route information avaialable at beckend
        for destination_net in dhcp_options_info:
            if _subnet_data['new_host_routes'][0]['destination']\
                in destination_net['destinationSubnet'] and\
                    self.nexthop1 in destination_net['router']:
                LOG.debug('Host routes available on nsxv')
        # Update subnet with no host-routes
        _subnet_data1 = {'new_host_routes': []}
        new_host_routes = _subnet_data1['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "New_subnet"
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Connect to instance using paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.serv_fip, username=username, password=password)
        cmd = ('dhclient eth0')
        stdin, stdout, stderr = client.exec_command(cmd)
        cmd = ('route -n')
        stdin, stdout, stderr = client.exec_command(cmd)
        self.assertIsNotNone(stdout.read())
        stdin, stdout, stderr = client.exec_command(cmd)
        # Check Host routes on VM shouldn't be avialable
        self.assertNotIn(
            _subnet_data['new_host_routes'][0]['destination'], stdout.read())
        # Check Host-routes at beckend after deletion
        exc_edge = self.vsm.get_dhcp_edge_info()
        self.assertIsNotNone(exc_edge)
        dhcp_options_info = []
        dhcp_options_info = exc_edge['staticBindings']['staticBindings'][0][
            'dhcpOptions']['option121']['staticRoutes']
        # Check Host Route information avaialable at beckend
        for destination_net in dhcp_options_info:
            if (_subnet_data['new_host_routes'][0]['destination']
                    not in destination_net['destinationSubnet']):
                LOG.debug('Host routes not available on nsxv')
        project_dict = dict(security_group=vm_env['security_group'],
                            network=vm_env['network'], subnet=vm_env['subnet'],
                            router=vm_env['router'],
                            client_mgr=vm_env['client_mgr'],
                            serv1=vm_env['serv1'], fip1=vm_env['fip1'])
        return project_dict

    def setup_vm_enviornment(self, client_mgr, t_id,
                             check_outside_world=True,
                             cidr_offset=0):
        t_network, t_subnet, t_router = self.setup_project_network(
            self.public_network_id, namestart=("deploy-%s-tenant" % t_id))
        t_security_group = self._create_security_group(
            security_groups_client=self.security_groups_client,
            security_group_rules_client=self.security_group_rules_client,
            namestart='adm')
        username, password = self.get_image_userpass()
        security_groups = [{'name': t_security_group['name']}]
        t_serv1 = self.create_server_on_network(
            t_network, security_groups,
            image=self.get_server_image(),
            flavor=self.get_server_flavor(),
            name=t_network['name'])
        self.check_server_connected(t_serv1)
        t_floatingip = self.create_floatingip_for_server(
            t_serv1, client_mgr=self.admin_manager)
        msg = ("Associate t_floatingip[%s] to server[%s]"
               % (t_floatingip, t_serv1['name']))
        self._check_floatingip_connectivity(
            t_floatingip, t_serv1, should_connect=True, msg=msg)
        vm_enviornment = dict(security_group=t_security_group,
                              network=t_network, subnet=t_subnet,
                              router=t_router, client_mgr=client_mgr,
                              serv1=t_serv1, fip1=t_floatingip)
        return vm_enviornment

    def test_dhcp121_negative_test(self):
        t_net_id, t_network, t_subnet =\
            self.create_project_network_subnet('admin')
        subnet_id = t_subnet['id']
        kwargs = {'enable_dhcp': 'false'}
        new_name = "New_subnet"
        # Update subnet with disable dhcp subnet
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Fetch next hop information from tempest.conf
        next_hop = CONF.network.project_network_cidr
        self.nexthop_host_route = next_hop.rsplit('.', 1)[0]
        self.nexthop1 = self.nexthop_host_route + ".2"
        username, password = self.get_image_userpass()
        # Update subnet with host routes
        _subnet_data = {'host_routes': [{'destination': '10.20.0.0/32',
                                         'nexthop': '10.100.1.1'}],
                        'new_host_routes': [{'destination': '10.20.0.0/32',
                                             'nexthop': self.nexthop1}]}
        new_host_routes = _subnet_data['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "New_subnet"
        # Update subnet with host-route info
        try:
            self.subnets_client.update_subnet(
                subnet_id, name=new_name, **kwargs)
        except Exception:
            e = sys.exc_info()[0].__dict__['message']
            if (e == "Bad request"):
                LOG.debug("Invalid input for operation:\
                          Host routes can only be supported when\
                          DHCP is enabled")
            pass
        subnet_id = t_subnet['id']
        kwargs = {'enable_dhcp': 'true'}
        new_name = "New_subnet"
        # Update subnet with disable dhcp subnet
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Update subnet with host routes
        _subnet_data = {'host_routes': [{'destination': '10.20.0.0/32',
                                         'nexthop': '10.100.1.1'}],
                        'new_host_routes': [{'destination': '10.20.0.0/32',
                                             'nexthop': self.nexthop1}]}
        new_host_routes = _subnet_data['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "Subnet_host_routes"
        # Update subnet with host-route info
        self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        # Disable dhcp subnet
        kwargs = {'enable_dhcp': 'false'}
        # Update subnet with disable dhcp subnet
        try:
            self.subnets_client.update_subnet(
                subnet_id, name=new_name, **kwargs)
        except Exception:
            e = sys.exc_info()[0].__dict__['message']
            if (e == "Bad request"):
                LOG.debug("Can't disable DHCP while using host routes")
            pass

        LOG.debug("test_dhcp121_negative_test Completed")

    def test_dhcp121_multi_host_route(self):
        t_net_id, t_network, t_subnet =\
            self.create_project_network_subnet('admin')
        # Fetch next hop information from tempest.conf
        next_hop = CONF.network.project_network_cidr
        self.nexthop_host_route = next_hop.rsplit('.', 1)[0]
        self.nexthop1 = self.nexthop_host_route + ".2"
        # Update subnet with host routes
        _subnet_data = {'host_routes': [{'destination': '10.20.0.0/32',
                                         'nexthop': '10.100.1.1'}],
                        'new_host_routes': [{'destination': '10.20.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.21.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.22.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.23.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.24.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.25.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.26.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.27.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.28.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.29.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.30.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.31.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.32.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.33.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.34.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.35.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.36.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.37.0.0/32',
                                             'nexthop': self.nexthop1},
                                            {'destination': '10.38.0.0/32',
                                             'nexthop': self.nexthop1}]}
        new_host_routes = _subnet_data['new_host_routes']
        kwargs = {'host_routes': new_host_routes}
        new_name = "New_subnet"
        subnet_id = t_subnet['id']
        # Update subnet with host-route info
        subnet = self.subnets_client.update_subnet(
            subnet_id, name=new_name, **kwargs)
        '''
        Above No of host-routes added are 19 so checking len of
        subnet host_routes equal to 19 or not
        '''
        if (len(subnet['subnet']['host_routes']) == 19):
            LOG.debug("Multiple entries for host routes available")
        LOG.debug("test_dhcp121_negative_test1 Completed")
