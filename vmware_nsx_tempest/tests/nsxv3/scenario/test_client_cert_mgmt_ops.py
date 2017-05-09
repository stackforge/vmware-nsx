# Copyright 2017 VMware, Inc.
# All Rights Reserved
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


from oslo_log import log as logging

import requests

from tempest import config
from tempest import test

from tempest.lib import decorators

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

from tempest.scenario import manager


from vmware_nsx_tempest.services import nsxv3_client
from vmware_nsx_tempest.services.qos import base_qos

authorizationField = ''
CONF = config.CONF
LOG = logging.getLogger(__name__)


class TestCertificateMgmt(manager.NetworkScenarioTest):

    error_message = ("Principal 'admin' from group 'superusers' attempts\
 to delete or modify an object it doesn't own")

    @classmethod
    def skip_checks(cls):
        super(TestCertificateMgmt, cls).skip_checks()
        if not (CONF.network.project_networks_reachable
                or CONF.network.public_network_id):
            msg = ('Either project_networks_reachable must be true, or\
                public_network_id must be defined.')
            raise cls.skipException(msg)
        if not test.is_extension_enabled('qos', 'network'):
            msg = "q-qos extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(TestCertificateMgmt, cls).setup_credentials()
        cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
            CONF.nsxv3.nsx_user, CONF.nsxv3.nsx_password)

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(TestCertificateMgmt, cls).resource_setup()
        cls.admin_mgr = cls.get_client_manager('admin')
        cls.adm_qos_client = base_qos.BaseQosClient(cls.admin_mgr)
        cls.policies_created = []

    def _create_subnet(self, network, cidr, subnets_client=None, **kwargs):
        client = subnets_client or self.subnets_client
        body = client.create_subnet(
            name=data_utils.rand_name('subnet-default1'),
            network_id=network['id'], tenant_id=network['tenant_id'],
            cidr=cidr, ip_version=4, **kwargs)
        subnet = body.get('subnet', body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_subnet, subnet['id'])
        return subnet

    def _create_router(self, router_name=None, admin_state_up=True,
                       external_network_id=None, enable_snat=None,
                       **kwargs):
        ext_gw_info = {}
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat is not None:
            ext_gw_info['enable_snat'] = enable_snat
        body = self.routers_client.create_router(
            name=router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body.get('router', body)
        self.addCleanup(self._delete_router, router)
        return router

    def _delete_router(self, router):
        body = self.ports_client.list_ports(device_id=router['id'])
        interfaces = body['ports']
        for i in interfaces:
            test_utils.call_and_ignore_notfound_exc(
                self.routers_client.remove_router_interface, router['id'],
                subnet_id=i['fixed_ips'][0]['subnet_id'])
        self.routers_client.delete_router(router['id'])

    @classmethod
    def create_qos_policy(cls, name='test-policy',
                          description='test policy desc',
                          shared=False,
                          qos_client=None, **kwargs):
        """create qos policy."""
        qos_client = qos_client if qos_client else cls.adm_qos_client
        policy = qos_client.create_policy(
            name=name, description=description,
            shared=shared, **kwargs)
        cls.policies_created.append(policy)
        return policy

    def get_request(self, component=None):
        """
        NSX-T API Get request
        """
        http_request = ('https://%s/api/v1/%s' %
            (CONF.nsxv3.nsx_manager, component))
        r = requests.get(http_request, verify=False,
            auth=('admin', 'Admin!23Admin'))
        self.assertEqual(r.status_code, 200, 'Bad request')
        return r.json()

    def put_request(self, component=None, comp_id=None, **kwargs):
        """
        NSX-T API Put request
        """
        http_request = ('https://%s/api/v1/%s/%s' %
            (CONF.nsxv3.nsx_manager, component, comp_id))
        r = requests.put(http_request, verify=False,
            headers={"content-type": "application/json"},
            json=kwargs, auth=('admin', 'Admin!23Admin'))
        self.assertIn(self.error_message, r.json()['error_message'])
        LOG.info('NSX admin is unable to modify the openstack object')

    def delete_request(self, component=None, comp_id=None):
        """
        NSX-T API delete request
        """
        http_request = ('https://%s/api/v1/%s/%s' %
            (CONF.nsxv3.nsx_manager, component, comp_id))
        r = requests.delete(http_request, verify=False,
            auth=('admin', 'Admin!23Admin'))
        self.assertIn(self.error_message, r.json()['error_message'])
        LOG.info('NSX admin is unable to delete openstack object')


class TestCertificateMgmtOps(TestCertificateMgmt):
    openstack_tag = 'com.vmware.nsx.openstack'

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('25bb1af7-6190-42d5-a590-4df9fb5592f0')
    def test_network(self):
        """
        Create a network
        Verify if backend shows network is created by openstack
        Verify if backend prevents NSX from modifying this network
        """
        self.network = self._create_network()
        self.subnet = self._create_subnet(self.network,
                                          cidr='197.168.1.0/24')
        """
        Corresponding Logical switch name created at the backend is
        Name of openstack network + First 5 characters of openstack network ID
        + '...' + Last 5 characters of openstack network ID
        """
        network_id = self.network['id']
        network_name = self.network['name']
        ls_name = network_name + '_' + network_id[:5] + '...' + network_id[-5:]
        #send http request to NSX Manager to grep all logical switches
        data = self.get_request(component='logical-switches')
        for item in data['results']:
            if item['display_name'] == ls_name:
                ls_id = item['id']
                #Obtain all logical switch info required for http put request
                ls_info = {"id": item['id'], "_revision": item['_revision'],
                    "transport_zone_id": item['transport_zone_id'],
                     "replication_mode": item['replication_mode'],
                    "admin_state": item['admin_state']}
                """
                Check if backend show openstack
                as the create user for the object
                """
                self.assertEqual(item['_create_user'], self.openstack_tag,
                    'Incorrect tag for the create user')
        #send http put request to modify the logical switch object
        ls_info.update({"display_name": "nsx_modified_switch"})
        self.put_request(component='logical-switches',
            comp_id=ls_id, **ls_info)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('3e9a4d5b-5a14-44a5-bf9f-8999148b9329')
    def test_router(self):
        """
        Create a router
        Verify if backend shows router is created by openstack
        Verify if backend prevents NSX from modifying this router
        Verify if backend prevents NSX from deleting this router
        """
        self.network = self._create_network()
        self.subnet = self._create_subnet(self.network,
                                          cidr='197.168.1.0/24')
        #create router and add an interface
        self.router = self._create_router(
            router_name=data_utils.rand_name('router-cert-mgmt'),
            external_network_id=CONF.network.public_network_id)
        router_id = self.router['id']
        self.routers_client.add_router_interface(
            self.router['id'], subnet_id=self.subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=self.subnet['id'])
        """
        Corresponding Logical router name created at the backend is
        Name of openstack router + First 5 characters of openstack router ID
        + '...' + Last 5 characters of openstack router ID
        """
        router_name = self.router['name']
        rtr_name = router_name + '_' + router_id[:5] + '...' + router_id[-5:]
        #send http request to NSX Manager to grep all logical switches
        data = self.get_request(component='logical-routers')
        for item in data['results']:
            if item['display_name'] == rtr_name:
                rtr_id = item['id']
                #Obtain all logical switch info required for http put request
                rtr_info = {"id": item['id'],
                    "resource_type": item['resource_type'],
                    "router_type": item['router_type'],
                    "high_availability_mode": item['high_availability_mode'],
                    "edge_cluster_id": item['edge_cluster_id'],
                    "_revision": item['_revision']}
                """
                Check if backend shows openstack
                as the create user for the object
                """
                self.assertEqual(item['_create_user'], self.openstack_tag,
                    'Incorrect tag for the create user')
                #checking if it was created by openstack
            else:
                continue
        #send http put request to modify the logical router object
        rtr_info.update({"display_name": "nsx_modified_router"})
        self.put_request(component='logical-routers', comp_id=rtr_id,
            **rtr_info)
        #Obtain any router port corresponding to the logical router
        data = self.get_request(component='logical-router-ports')
        for item in data['results']:
            if item['logical_router_id'] == rtr_id:
                rtr_port_id = item['id']
                break
        #Send http delete request to delete the logical router port
        self.delete_request(component='logical-router-ports',
            comp_id=rtr_port_id)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('141af4cb-52f0-4764-b817-5b0529dbbc73')
    def test_qos_policy(self):
        """
        Create a qos policy
        Verify if backend shows switching profile is created by openstack
        Verify if backend prevents NSX from modifying this profile
        Verify if backend prevents NSX from deleting this profile
        """
        policy = self.create_qos_policy(name='test-qos-policy-cert-mgmt',
                                        description='dscp_rule and bw_rule',
                                        shared=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.adm_qos_client.delete_policy, policy['id'])
        #send http request to NSX Manager to grep all logical switches
        data = self.get_request(component='switching-profiles')
        for item in data['results']:
            if item['display_name'] == 'test-qos-policy-cert-mgmt':
                qos_id = item['id']
                qos_info = {"id": item['id'],
                    "resource_type": item['resource_type'],
                    "_revision": item['_revision']}
                self.assertEqual(item['_create_user'], self.openstack_tag,
                    'Incorrect tag for the create user')
        #send http put request to modify the qos policy object
        qos_info.update({"display_name": "nsx_modified_qos-policy"})
        self.put_request(component='switching-profiles', comp_id=qos_id,
            **qos_info)
        #Send http delete request to delete the qos policy object
        self.delete_request(component='switching-profiles', comp_id=qos_id)

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('2b232060-dc42-4b2d-8185-64bd12e46e55')
    def test_security_group(self):
        """
        Create a security group
        Verify if backend shows firewall is created by openstack
        Verify if backend prevents NSX from modifying this firewall
        Verify if backend prevents NSX from deleting this firewall
        """
        self.security_group = self._create_security_group()
        sg_name = self.security_group['name']
        sg_id = self.security_group['id']
        #send http request to NSX Manager to grep all firewall sections
        data = self.get_request(component='firewall/sections')
        for item in data['results']:
            if item['display_name'] == (sg_name + ' - ' + sg_id):
                fw_id = item['id']
                fw_info = {"id": item['id'], "_revision": item['_revision'],
                    "section_type": item['section_type'],
                    "stateful": item['stateful']}
                self.assertEqual(item['_create_user'], self.openstack_tag,
                    'Incorrect tag for the create user')
        #send http put request to modify firewall object
        fw_info.update({"display_name": "nsx_modified_firewall"})
        self.put_request(component='firewall/sections',
            comp_id=fw_id, **fw_info)
        #send http get request to get firewall rules
        component = 'firewall/sections/' + fw_id + '/rules/'
        data = self.get_request(component)
        if data["result_count"] > 0:
            for item in data['results']:
                #send http delete request to delete firewall rules
                self.delete_request(component, comp_id=item['id'])
                break

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('b10d5ede-d1c7-47a0-9d55-b9aabc8f0af1')
    def test_port(self):
        """
        Create a port
        Verify if backend shows logical port is created by openstack
        Verify if backend prevents NSX from modifying the port
        Verify if backend prevents NSX from deleting the port
        """
        self.network = self._create_network(namestart="net-ca")
        self.subnet = self._create_subnet(self.network,
                                          cidr='192.153.1.0/24')
        self.port = self._create_port(network_id=self.network['id'],
            namestart='ca')
        port_name = self.port['name']
        data = self.get_request(component='logical-ports')
        for item in data['results']:
            if item['display_name'] == port_name:
                port_id = item['id']
                port_info = {"id": item['id'], "_revision": item['_revision'],
                    "admin_state": item['admin_state'],
                    "logical_switch_id": item['logical_switch_id']}
                self.assertEqual(item['_create_user'], self.openstack_tag,
                    'Incorrect tag for the create user')
        #send http put request to modify logical port object
        port_info.update({"display_name": "nsx_modified_logical_port"})
        self.put_request(component='logical-ports', comp_id=port_id,
            **port_info)
        #send http delete request to delete logical port object
        component = 'logical-ports'
        self.delete_request(component, comp_id=item['id'])

    @decorators.attr(type='nsxv3')
    @decorators.idempotent_id('280cdcc6-5bd0-472c-a8a9-954dd612a0a6')
    def test_super_admin(self):
        """
        Verify if super admin can override openstack entity
        and delete openstack logical port
        """
        self.network = self._create_network(namestart="net-ca")
        self.subnet = self._create_subnet(self.network,
                                          cidr='192.153.1.0/24')
        self.port = self._create_port(network_id=self.network['id'],
            namestart='ca')
        port_name = self.port['name']
        data = self.get_request(component='logical-ports')
        for item in data['results']:
            if item['display_name'] == port_name:
                port_id = item['id']
                self.assertEqual(item['_create_user'], self.openstack_tag,
                    'Incorrect tag for the create user')
        #send delete request and check if ports gets deleted
        http_request = ('https://%s/api/v1/logical-ports/%s'
            % (CONF.nsxv3.nsx_manager, port_id))
        r = requests.delete(http_request,
            headers={'X-Allow-Overwrite': 'true'},
            verify=False, auth=('admin', 'Admin!23Admin'))
        self.assertEqual(r.status_code, 200,
            "Superadmin unable to delete the logical port")
