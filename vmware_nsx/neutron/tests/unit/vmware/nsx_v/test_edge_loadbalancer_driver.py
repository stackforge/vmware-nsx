# Copyright 2015 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import contextlib
import mock

from neutron import context
from neutron.tests import base

from vmware_nsx.neutron.plugins.vmware.vshield import vcns_driver

EDGE_PROVIDER = ('LOADBALANCER:vmwareedge:neutron.services.'
                 'loadbalancer.drivers.vmware.edge_driver.'
                 'EdgeLoadbalancerDriver:default')

HEALTHMON_ID = 'cb297614-66c9-4048-8838-7e87231569ae'
POOL_ID = 'b3dfb476-6fdf-4ddd-b6bd-e86ae78dc30b'
TENANT_ID = 'f9135d3a908842bd8d785816c2c90d36'
SUBNET_ID = 'c8924d77-ff57-406f-a13c-a8c5def01fc9'
VIP_ID = 'f6393b95-34b0-4299-9001-cbc21e32bf03'
VIP_PORT_ID = '49c547e3-6775-42ea-a607-91e8f1a07432'
MEMBER_ID = '90dacafd-9c11-4af7-9d89-234e2d1fedb1'

EDGE_ID = 'edge-x'
EDGE_POOL_ID = '111'
EDGE_VSE_ID = '222'
APP_PROFILE_ID = '333'
EDGE_MON_ID = '444'
EDGE_FW_RULE_ID = '555'


class TestEdgeLbDriver(base.BaseTestCase):
    def setUp(self):
        super(TestEdgeLbDriver, self).setUp()
        self.context = context.get_admin_context()
        self.edge_driver = vcns_driver.VcnsDriver(self)
        self.edge_driver._lb_driver_prop = mock.Mock()

    def test_create_pool(self):
        lbaas_pool = {
            'status': 'PENDING_CREATE', 'lb_method': 'ROUND_ROBIN',
            'protocol': 'HTTP', 'description': '', 'health_monitors': [],
            'members': [], 'status_description': None, 'id': POOL_ID,
            'vip_id': None, 'name': 'testpool', 'admin_state_up': True,
            'subnet_id': SUBNET_ID, 'tenant_id': TENANT_ID,
            'health_monitors_status': [], 'provider': 'vmwareedge'}
        edge_pool = {
            'transparent': False, 'name': 'pool_' + POOL_ID,
            'algorithm': 'round-robin', 'description': ''}

        with contextlib.nested(
            mock.patch.object(self.edge_driver, '_get_lb_edge_id'),
            mock.patch.object(self.edge_driver._lb_driver,
                              'create_pool_successful'),
            mock.patch.object(self.edge_driver.vcns, 'create_pool')
        ) as (mock_get_edge, mock_create_pool_successful, mock_create_pool):

            mock_get_edge.return_value = EDGE_ID
            mock_create_pool.return_value = ({'location': 'x/' + EDGE_POOL_ID},
                                             None)

            self.edge_driver.create_pool(self.context, lbaas_pool)
            mock_create_pool.assert_called_with(EDGE_ID, edge_pool)
            mock_create_pool_successful.assert_called_with(
                self.context, lbaas_pool, EDGE_ID, EDGE_POOL_ID)

    def test_update_pool(self):
        from_pool = {
            'status': 'ACTIVE', 'lb_method': 'ROUND_ROBIN',
            'protocol': 'HTTP', 'description': '', 'health_monitors': [],
            'members': [], 'status_description': None, 'id': POOL_ID,
            'vip_id': None, 'name': 'testpool2', 'admin_state_up': True,
            'subnet_id': SUBNET_ID, 'tenant_id': TENANT_ID,
            'health_monitors_status': [], 'provider': 'vmwareedge'}

        to_pool = {
            'status': 'PENDING_UPDATE', 'lb_method': 'LEAST_CONNECTIONS',
            'protocol': 'HTTP', 'description': '', 'health_monitors': [],
            'members': [], 'status_description': None, 'id': POOL_ID,
            'vip_id': None, 'name': 'testpool2', 'admin_state_up': True,
            'subnet_id': SUBNET_ID, 'tenant_id': TENANT_ID,
            'health_monitors_status': [], 'provider': 'vmwareedge'}

        edge_pool = {
            'transparent': False, 'name': 'pool_' + POOL_ID,
            'algorithm': 'leastconn', 'description': ''}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}
        with contextlib.nested(
            mock.patch.object(self.edge_driver._lb_driver, 'pool_successful'),
            mock.patch.object(self.edge_driver.vcns, 'update_pool')) as (
                mock_pool_successful, mock_update_pool):

            self.edge_driver.update_pool(self.context, from_pool, to_pool,
                                         pool_mapping)
            mock_update_pool.assert_called_with(EDGE_ID, EDGE_POOL_ID,
                                                edge_pool)
            mock_pool_successful.assert_called_with(self.context, to_pool)

    def test_delete_pool(self):
        lbaas_pool = {
            'status': 'PENDING_CREATE', 'lb_method': 'ROUND_ROBIN',
            'protocol': 'HTTP', 'description': '', 'health_monitors': [],
            'members': [], 'status_description': None, 'id': POOL_ID,
            'vip_id': None, 'name': 'testpool', 'admin_state_up': True,
            'subnet_id': SUBNET_ID, 'tenant_id': TENANT_ID,
            'health_monitors_status': [], 'provider': 'vmwareedge'}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with contextlib.nested(
            mock.patch.object(self.edge_driver._lb_driver,
                              'delete_pool_successful'),
            mock.patch.object(self.edge_driver.vcns, 'delete_pool')
        ) as (mock_delete_successful, mock_delete_pool):

            self.edge_driver.delete_pool(self.context, lbaas_pool,
                                         pool_mapping)
            mock_delete_successful.assert_called_with(self.context, lbaas_pool)

    def test__add_vip_as_secondary_ip(self):
        get_if_list = {
            'vnics': [
                {'index': 0, 'name': 'external', 'addressGroups': {
                    'addressGroups': [
                        {'subnetMask': '255.255.255.0',
                         'primaryAddress': '172.24.4.2',
                         'subnetPrefixLength': '24'}]},
                    'portgroupName': 'VM Network', 'label': 'vNic_0',
                    'type': 'uplink', 'portgroupId': 'network-13'},
                {'index': 1, 'name': 'internal1', 'addressGroups': {
                    'addressGroups': [
                        {'subnetPrefixLength': '24',
                         'secondaryAddresses': {
                             'ipAddress': ['10.0.0.6'],
                             'type': 'secondary_addresses'},
                         'primaryAddress': '10.0.0.1',
                         'subnetMask': '255.255.255.0'}]},
                    'portgroupName': 'pg1234', 'label': 'vNic_1',
                    'type': 'internal', 'portgroupId': 'virtualwire-31'}]}
        update_if = {
            'index': 1, 'name': 'internal1', 'addressGroups': {
                'addressGroups': [
                    {'subnetPrefixLength': '24',
                     'secondaryAddresses': {
                         'ipAddress': ['10.0.0.6', '10.0.0.8'],
                         'type': 'secondary_addresses'},
                     'primaryAddress': '10.0.0.1',
                     'subnetMask': '255.255.255.0'}]},
                'portgroupName': 'pg1234', 'label': 'vNic_1',
                'type': 'internal', 'portgroupId': 'virtualwire-31'}

        with contextlib.nested(
            mock.patch.object(self.edge_driver.vcns, 'get_interfaces'),
            mock.patch.object(self.edge_driver.vcns, 'update_interface')
        ) as (mock_get_if, mock_update_if):

            mock_get_if.return_value = (None, get_if_list)

            self.edge_driver._add_vip_as_secondary_ip(EDGE_ID, '10.0.0.8')
            mock_update_if.assert_called_with(EDGE_ID, update_if)

    def test__del_vip_as_secondary_ip(self):
        get_if_list = {
            'vnics': [
                {'index': 0, 'name': 'external', 'addressGroups': {
                    'addressGroups': [
                        {'subnetMask': '255.255.255.0',
                         'primaryAddress': '172.24.4.2',
                         'subnetPrefixLength': '24'}]},
                 'portgroupName': 'VM Network', 'label': 'vNic_0',
                 'type': 'uplink', 'portgroupId': 'network-13'},
                {'index': 1, 'name': 'internal1', 'addressGroups': {
                    'addressGroups': [
                        {'subnetPrefixLength': '24',
                         'secondaryAddresses': {
                             'ipAddress': ['10.0.0.6', '10.0.0.8'],
                             'type': 'secondary_addresses'},
                         'primaryAddress': '10.0.0.1',
                         'subnetMask': '255.255.255.0'}]},
                 'portgroupName': 'pg1234',
                 'label': 'vNic_1', 'type': 'internal',
                 'portgroupId': 'virtualwire-31'},
                {'index': 2, 'name': 'vnic2',
                 'addressGroups': {'addressGroups': []},
                 'label': 'vNic_2', 'type': 'internal'},
                {'index': 3, 'name': 'vnic3',
                 'addressGroups': {'addressGroups': []},
                 'label': 'vNic_3', 'type': 'internal'}]}
        update_if = {
            'index': 1, 'name': 'internal1', 'addressGroups': {
                'addressGroups': [
                    {'subnetPrefixLength': '24',
                     'secondaryAddresses': {'ipAddress': ['10.0.0.6'],
                                             'type': 'secondary_addresses'},
                     'primaryAddress': '10.0.0.1',
                     'subnetMask': '255.255.255.0'}]},
            'portgroupName': 'pg1234', 'label': 'vNic_1',
            'type': 'internal', 'portgroupId': 'virtualwire-31'}
        with contextlib.nested(
            mock.patch.object(self.edge_driver.vcns, 'get_interfaces'),
            mock.patch.object(self.edge_driver.vcns, 'update_interface')
        ) as (mock_get_if, mock_update_if):

            mock_get_if.return_value = (None, get_if_list)

            self.edge_driver._del_vip_as_secondary_ip(EDGE_ID, '10.0.0.8')
            mock_update_if.assert_called_with(EDGE_ID, update_if)

    def test_create_vip(self):
        lbaas_vip = {
            'status': 'PENDING_CREATE', 'protocol': 'HTTP',
            'description': '', 'address': '10.0.0.8', 'protocol_port': 555,
            'port_id': VIP_PORT_ID, 'id': VIP_ID, 'status_description': None,
            'name': 'testvip1', 'admin_state_up': True,
            'subnet_id': SUBNET_ID, 'tenant_id': TENANT_ID,
            'connection_limit': -1, 'pool_id': POOL_ID,
            'session_persistence': {'type': 'SOURCE_IP'}}
        edge_app_prof = {
            'name': VIP_ID, 'insertXForwardedFor': False,
            'serverSslEnabled': False, 'template': 'HTTP',
            'sslPassthrough': False, 'persistence': {'method': 'sourceip'}}
        edge_vip = {
            'protocol': 'HTTP', 'name': 'vip_' + VIP_ID, 'connectionLimit': 0,
            'defaultPoolId': EDGE_POOL_ID, 'ipAddress': '10.0.0.8',
            'port': 555, 'applicationProfileId': APP_PROFILE_ID,
            'description': ''}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with contextlib.nested(
            mock.patch.object(self.edge_driver, '_add_vip_as_secondary_ip'),
            mock.patch.object(self.edge_driver.vcns, 'create_app_profile'),
            mock.patch.object(self.edge_driver.vcns, 'create_vip'),
            mock.patch.object(self.edge_driver, '_add_vip_fw_rule'),
            mock.patch.object(self.edge_driver._lb_driver,
                              'create_vip_successful'),
        ) as (mock_sec_ip, mock_create_app_profile, mock_create_vip,
              mock_add_fw_rule, mock_vip_successful):

            mock_create_app_profile.return_value = (
                {'location': 'x/' + APP_PROFILE_ID}, None)
            mock_create_vip.return_value = (
                {'location': 'x/' + EDGE_VSE_ID}, None)
            mock_add_fw_rule.return_value = EDGE_FW_RULE_ID

            self.edge_driver.create_vip(self.context, lbaas_vip, pool_mapping)
            mock_create_app_profile.assert_called_with(EDGE_ID, edge_app_prof)
            mock_add_fw_rule.assert_called_with(EDGE_ID, VIP_ID, '10.0.0.8')
            mock_create_vip.assert_called_with(EDGE_ID, edge_vip)
            mock_vip_successful.assert_called_with(
                self.context, lbaas_vip, EDGE_ID, APP_PROFILE_ID, EDGE_VSE_ID,
                EDGE_FW_RULE_ID)

    def test_update_vip(self):
        vip_from = {
            'status': 'ACTIVE', 'protocol': 'HTTP', 'description': '',
            'address': '10.0.0.8', 'protocol_port': 555L,
            'port_id': VIP_PORT_ID, 'id': VIP_ID, 'status_description': None,
            'name': 'testvip1', 'admin_state_up': True,
            'subnet_id': SUBNET_ID, 'tenant_id': TENANT_ID,
            'connection_limit': -1L, 'pool_id': POOL_ID,
            'session_persistence': {'type': 'SOURCE_IP'}}
        vip_to = {
            'status': 'PENDING_UPDATE', 'protocol': 'HTTP',
            'description': '', 'address': '10.0.0.8', 'protocol_port': 555L,
            'port_id': VIP_PORT_ID, 'id': VIP_ID, 'status_description': None,
            'name': 'testvip1', 'admin_state_up': True,
            'subnet_id': SUBNET_ID, 'tenant_id': TENANT_ID,
            'connection_limit': -1, 'pool_id': POOL_ID,
            'session_persistence': {'type': 'HTTP_COOKIE'}}
        edge_app_prof = {
            'name': 'testvip1', 'insertXForwardedFor': False,
            'serverSslEnabled': False, 'template': 'HTTP',
            'sslPassthrough': False,
            'persistence': {'cookieName': 'default_cookie_name',
                            'method': 'cookie', 'cookieMode': 'insert'}}
        edge_vip = {
            'protocol': 'HTTP', 'name': 'vip_' + VIP_ID, 'connectionLimit': 0,
            'defaultPoolId': EDGE_POOL_ID, 'ipAddress': '10.0.0.8',
            'port': 555L, 'applicationProfileId': '333', 'description': ''}

        pool_mapping = {'edge_pool_id': '111'}
        vip_mapping = {'edge_id': EDGE_ID, 'edge_vse_id': EDGE_VSE_ID,
                       'edge_app_profile_id': APP_PROFILE_ID}

        with contextlib.nested(
            mock.patch.object(self.edge_driver.vcns, 'update_app_profile'),
            mock.patch.object(self.edge_driver.vcns, 'update_vip'),
            mock.patch.object(self.edge_driver._lb_driver, 'vip_successful')
        ) as (mock_upd_app_prof, mock_upd_vip, mock_vip_successful):

            self.edge_driver.update_vip(self.context, vip_from, vip_to,
                                        pool_mapping, vip_mapping)

            mock_upd_app_prof.assert_called_with(EDGE_ID, APP_PROFILE_ID,
                                                 edge_app_prof)
            mock_upd_vip.assert_called_with(EDGE_ID, EDGE_VSE_ID, edge_vip)
            mock_vip_successful.assert_called_with(self.context, vip_to)

    def test_delete_vip(self):
        lbaas_vip = {
            'status': 'PENDING_DELETE', 'protocol': 'HTTP',
            'description': '', 'address': '10.0.0.11', 'protocol_port': 555L,
            'port_id': VIP_PORT_ID, 'id': VIP_ID, 'status_description': None,
            'name': 'testvip', 'admin_state_up': True, 'subnet_id': SUBNET_ID,
            'tenant_id': TENANT_ID, 'connection_limit': -1L,
            'pool_id': POOL_ID, 'session_persistence': None}

        vip_mapping = {'edge_id': EDGE_ID, 'edge_vse_id': EDGE_VSE_ID,
                       'edge_app_profile_id': APP_PROFILE_ID,
                       'edge_fw_rule_id': EDGE_FW_RULE_ID}

        with contextlib.nested(
            mock.patch.object(self.edge_driver, '_del_vip_as_secondary_ip'),
            mock.patch.object(self.edge_driver.vcns, 'delete_app_profile'),
            mock.patch.object(self.edge_driver.vcns, 'delete_vip'),
            mock.patch.object(self.edge_driver, '_del_vip_fw_rule'),
            mock.patch.object(self.edge_driver._lb_driver,
                              'delete_vip_successful')
        ) as (mock_sec_ip, mock_del_app_profile, mock_del_vip,
              mock_del_fw_rule, mock_del_successful):

            self.edge_driver.delete_vip(self.context, lbaas_vip, vip_mapping)
            mock_del_app_profile.assert_called_with(EDGE_ID, APP_PROFILE_ID)
            mock_del_vip.assert_called_with(EDGE_ID, EDGE_VSE_ID)
            mock_del_fw_rule.assert_called_with(EDGE_ID, EDGE_FW_RULE_ID)
            mock_del_successful.assert_called_with(self.context, lbaas_vip)

    def test_create_member(self):
        lbaas_member = {
            'admin_state_up': True, 'status': 'PENDING_CREATE',
            'status_description': None, 'weight': 5, 'address': '10.0.0.4',
            'tenant_id': TENANT_ID, 'protocol_port': 555, 'id': MEMBER_ID,
            'pool_id': POOL_ID}
        edge_pool = {
            'monitorId': [], 'name': POOL_ID, 'applicationRuleId': [],
            'member': [], 'poolId': 'pool-1', 'algorithm': 'round-robin',
            'transparent': False}
        edge_member = {
            'condition': 'enabled', 'ipAddress': '10.0.0.4', 'port': 555,
            'weight': 5, 'name': 'member-' + MEMBER_ID}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with contextlib.nested(
            mock.patch.object(self.edge_driver.vcns, 'get_pool'),
            mock.patch.object(self.edge_driver.vcns, 'update_pool'),
            mock.patch.object(self.edge_driver, '_update_pool_fw_rule'),
            mock.patch.object(self.edge_driver._lb_driver, 'member_successful')
        ) as (mock_get_pool, mock_update_pool, mock_upd_fw_rule,
              mock_member_successful):

            mock_get_pool.return_value = (None, edge_pool)
            self.edge_driver.create_member(self.context, lbaas_member,
                                           pool_mapping)
            edge_pool['member'].append(edge_member)
            mock_member_successful.assert_called_with(self.context,
                                                      lbaas_member)

    def test_update_member(self):
        member_from = {
            'admin_state_up': True, 'status': 'PENDING_UPDATE',
            'status_description': None, 'weight': 5, 'address': '10.0.0.4',
            'tenant_id': TENANT_ID, 'protocol_port': 555, 'id': MEMBER_ID,
            'pool_id': POOL_ID}
        member_to = {
            'admin_state_up': True, 'status': 'ACTIVE',
            'status_description': None, 'weight': 10, 'address': '10.0.0.4',
            'tenant_id': TENANT_ID, 'protocol_port': 555, 'id': MEMBER_ID,
            'pool_id': POOL_ID}
        edge_pool = {
            'monitorId': [], 'name': POOL_ID, 'applicationRuleId': [],
            'member': [
                {'condition': 'enabled', 'ipAddress': '10.0.0.4', 'port': 555,
                 'weight': 5, 'name': 'member-' + MEMBER_ID}],
            'poolId': 'pool-1', 'algorithm': 'round-robin',
            'transparent': False}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with contextlib.nested(
            mock.patch.object(self.edge_driver.vcns, 'get_pool'),
            mock.patch.object(self.edge_driver.vcns, 'update_pool'),
            mock.patch.object(self.edge_driver._lb_driver, 'member_successful')
        ) as (mock_get_pool, mock_update_pool, mock_member_successful):

            mock_get_pool.return_value = (None, edge_pool)
            self.edge_driver.update_member(self.context, member_from,
                                           member_to, pool_mapping)
            edge_pool['member'][0]['weight'] = 6
            mock_update_pool.assert_called_with(EDGE_ID, EDGE_POOL_ID,
                                                edge_pool)
            mock_member_successful.assert_called_with(self.context, member_to)

    def test_delete_member(self):
        lbaas_member = {
            'admin_state_up': True, 'status': 'PENDING_DELETE',
            'status_description': None, 'weight': 5, 'address': '10.0.0.4',
            'tenant_id': TENANT_ID, 'protocol_port': 555, 'id': MEMBER_ID,
            'pool_id': POOL_ID}
        edge_pool = {
            'monitorId': [], 'name': POOL_ID, 'applicationRuleId': [],
            'member': [
                {'condition': 'enabled', 'ipAddress': '10.0.0.4', 'port': 555,
                 'weight': 5, 'name': 'member-' + MEMBER_ID}],
            'poolId': 'pool-1', 'algorithm': 'round-robin',
            'transparent': False}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with contextlib.nested(
            mock.patch.object(self.edge_driver.vcns, 'get_pool'),
            mock.patch.object(self.edge_driver.vcns, 'update_pool'),
            mock.patch.object(self.edge_driver, '_update_pool_fw_rule'),
            mock.patch.object(self.edge_driver._lb_driver, 'member_successful')
        ) as (mock_get_pool, mock_update_pool, mock_upd_fw_rule,
              mock_member_successful):

            mock_get_pool.return_value = (None, edge_pool)
            self.edge_driver.delete_member(self.context, lbaas_member,
                                           pool_mapping)
            edge_pool['member'] = []
            mock_update_pool.assert_called_with(EDGE_ID, EDGE_POOL_ID,
                                                edge_pool)
            mock_member_successful.assert_called_with(self.context,
                                                      lbaas_member)

    def test__update_pool_fw_rule_add(self):
        edge_fw_section = (
            '<section id="1132" name="LBaaS FW Rules"><rule><name>' + POOL_ID +
            '</name><action>allow</action><sources excluded="false"><source>'
            '<type>Ipv4Address</type><value>10.0.0.1,11.0.0.1</value></source>'
            '</sources><destinations excluded="false"><destination>'
            '<type>Ipv4Address</type><value>10.0.0.10</value></destination>'
            '</destinations></rule></section>')
        edge_fw_updated_section = (
            '<section id="1132" name="LBaaS FW Rules"><rule><name>' + POOL_ID +
            '</name><action>allow</action><sources excluded="false"><source>'
            '<type>Ipv4Address</type><value>10.0.0.1,11.0.0.1</value></source>'
            '</sources><destinations excluded="false"><destination>'
            '<type>Ipv4Address</type><value>10.0.0.10,11.0.0.10</value>'
            '</destination></destinations></rule></section>')

        mock_lb_plugin = mock.Mock()

        with contextlib.nested(
            mock.patch.object(self.edge_driver, '_get_edge_ips'),
            mock.patch.object(self.edge_driver, '_get_lb_plugin'),
            mock.patch.object(mock_lb_plugin, 'get_members'),
            mock.patch.object(self.edge_driver.vcns, 'get_section'),
            mock.patch.object(self.edge_driver, '_get_lbaas_fw_section_id',
                              return_value='1111'),
            mock.patch.object(self.edge_driver.vcns, 'update_section')
        ) as (mock_get_edge_ips, mock_get_lb_plugin, mock_get_members,
              mock_get_section, mock_get_section_id, mock_update_section):

            mock_get_edge_ips.return_value = ['10.0.0.1', '11.0.0.1']
            mock_get_lb_plugin.return_value = mock_lb_plugin
            mock_get_members.return_value = [{'address': '10.0.0.10'}]
            mock_get_section.return_value = (None, edge_fw_section)
            self.edge_driver._update_pool_fw_rule(
                self.context, POOL_ID, EDGE_ID, 'add', '11.0.0.10')
            mock_update_section.assert_called_with(
                '/api/4.0/firewall/globalroot-0/config/layer3sections/1111',
                edge_fw_updated_section, None)

    def test__update_pool_fw_rule_del(self):
        edge_fw_section = (
            '<section id="1132" name="LBaaS FW Rules"><rule><name>' + POOL_ID +
            '</name><action>allow</action><sources excluded="false"><source>'
            '<type>Ipv4Address</type><value>10.0.0.1,11.0.0.1</value></source>'
            '</sources><destinations excluded="false"><destination>'
            '<type>Ipv4Address</type><value>10.0.0.10,11.0.0.10</value>'
            '</destination></destinations></rule></section>')
        edge_fw_updated_section = (
            '<section id="1132" name="LBaaS FW Rules"><rule><name>' + POOL_ID +
            '</name><action>allow</action><sources excluded="false"><source>'
            '<type>Ipv4Address</type><value>10.0.0.1,11.0.0.1</value></source>'
            '</sources><destinations excluded="false"><destination>'
            '<type>Ipv4Address</type><value>10.0.0.10</value></destination>'
            '</destinations></rule></section>')

        mock_lb_plugin = mock.Mock()

        with contextlib.nested(
            mock.patch.object(self.edge_driver, '_get_edge_ips'),
            mock.patch.object(self.edge_driver, '_get_lb_plugin'),
            mock.patch.object(mock_lb_plugin, 'get_members'),
            mock.patch.object(self.edge_driver.vcns, 'get_section'),
            mock.patch.object(self.edge_driver, '_get_lbaas_fw_section_id',
                              return_value='1111'),
            mock.patch.object(self.edge_driver.vcns, 'update_section')
        ) as (mock_get_edge_ips, mock_get_lb_plugin, mock_get_members,
              mock_get_section, mock_get_section_id, mock_update_section):

            mock_get_edge_ips.return_value = ['10.0.0.1', '11.0.0.1']
            mock_get_lb_plugin.return_value = mock_lb_plugin
            mock_get_members.return_value = [{'address': '10.0.0.10'},
                                             {'address': '11.0.0.10'}]
            mock_get_section.return_value = (None, edge_fw_section)
            self.edge_driver._update_pool_fw_rule(
                self.context, POOL_ID, EDGE_ID, 'del', '11.0.0.10')
            mock_update_section.assert_called_with(
                '/api/4.0/firewall/globalroot-0/config/layer3sections/1111',
                edge_fw_updated_section, None)

    def test__get_edge_ips(self):
        get_if_list = {
            'vnics': [
                {'index': 0, 'name': 'external', 'addressGroups': {
                    'addressGroups': [
                        {'subnetMask': '255.255.255.0',
                         'primaryAddress': '172.24.4.2',
                         'subnetPrefixLength': '24'}]},
                 'portgroupName': 'VM Network', 'label': 'vNic_0',
                 'type': 'uplink', 'portgroupId': 'network-13'},
                {'index': 1, 'name': 'internal1', 'addressGroups': {
                    'addressGroups': [
                        {'subnetPrefixLength': '24',
                         'secondaryAddresses': {
                             'ipAddress': ['10.0.0.6'],
                             'type': 'secondary_addresses'},
                         'primaryAddress': '10.0.0.1',
                         'subnetMask': '255.255.255.0'}]},
                 'portgroupName': 'pg1234', 'label': 'vNic_1',
                 'type': 'internal',
                 'portgroupId': 'virtualwire-31'},
                {'index': 2, 'name': 'vnic2',
                 'addressGroups': {'addressGroups': []},
                 'isConnected': False, 'mt': 1500,
                 'fenceParameters': [], 'label': 'vNic_2',
                 'type': 'internal'}]}

        with mock.patch.object(self.edge_driver.vcns, 'get_interfaces',
                               return_value=(None, get_if_list)):
            ip_list = self.edge_driver._get_edge_ips(EDGE_ID)
            self.assertEqual(['172.24.4.2', '10.0.0.1'], ip_list)

    def test_create_pool_health_monitor(self):
        hmon = {
            'admin_state_up': True, 'tenant_id': TENANT_ID, 'delay': 5L,
            'max_retries': 5L, 'timeout': 5L, 'pools': [
                {'status': 'PENDING_CREATE', 'status_description': None,
                 'pool_id': POOL_ID}],
            'type': 'PING', 'id': HEALTHMON_ID}
        edge_hm = {'maxRetries': 5L, 'interval': 5L, 'type': 'icmp',
                   'name': HEALTHMON_ID, 'timeout': 5L}
        edge_pool = {'monitorId': [], 'name': POOL_ID,
                     'applicationRuleId': [], 'member': [],
                     'poolId': 'pool-1', 'algorithm': 'round-robin',
                     'transparent': False}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}

        with contextlib.nested(
            mock.patch.object(self.edge_driver.vcns, 'create_health_monitor'),
            mock.patch.object(self.edge_driver.vcns, 'get_pool'),
            mock.patch.object(self.edge_driver.vcns, 'update_pool'),
            mock.patch.object(self.edge_driver._lb_driver,
                              'create_pool_health_monitor_successful')
        ) as (mock_create_mon, mock_get_pool, mock_update_pool,
              mock_create_successful):

            mock_create_mon.return_value = ({'location': 'x/' + HEALTHMON_ID},
                                            None)
            mock_get_pool.return_value = (None, edge_pool)
            self.edge_driver.create_pool_health_monitor(
                self.context, hmon, POOL_ID, pool_mapping, None)
            mock_create_mon.assert_called_with(EDGE_ID, edge_hm)
            edge_pool['monitorId'].append(HEALTHMON_ID)
            mock_update_pool.assert_called_with(EDGE_ID, EDGE_POOL_ID,
                                                edge_pool)
            mock_create_successful.assert_called_with(
                self.context, hmon, POOL_ID, EDGE_ID, HEALTHMON_ID)

    def test_update_pool_health_monitor(self):
        pool_id = POOL_ID
        from_hmon = {
            'admin_state_up': True, 'tenant_id': TENANT_ID, 'delay': 5L,
            'max_retries': 5L, 'timeout': 5L, 'pools': [
                {'status': 'PENDING_UPDATE', 'status_description': None,
                 'pool_id': POOL_ID}],
            'type': 'PING', 'id': HEALTHMON_ID}
        to_hmon = {
            'admin_state_up': True, 'tenant_id': TENANT_ID, 'delay': 5L,
            'max_retries': 10L, 'timeout': 5L, 'pools': [
                {'status': 'ACTIVE', 'status_description': None,
                 'pool_id': POOL_ID}],
            'type': 'PING', 'id': HEALTHMON_ID}
        edge_hmon = {'maxRetries': 10L, 'interval': 5L, 'type': 'icmp',
                     'name': HEALTHMON_ID, 'timeout': 5L}

        mon_mapping = {'edge_id': EDGE_ID, 'edge_monitor_id': EDGE_MON_ID}

        with contextlib.nested(
            mock.patch.object(self.edge_driver.vcns, 'update_health_monitor'),
            mock.patch.object(self.edge_driver._lb_driver,
                              'pool_health_monitor_successful')
        ) as (
                mock_update_mon, mock_hmon_successful):

            self.edge_driver.update_pool_health_monitor(
                self.context, from_hmon, to_hmon, pool_id, mon_mapping)

            mock_update_mon.assert_called_with(EDGE_ID, EDGE_MON_ID, edge_hmon)
            mock_hmon_successful.assert_called_with(self.context, to_hmon,
                                                    POOL_ID,)

    def test_delete_pool_health_monitor(self):
        hmon = {
            'admin_state_up': True, 'tenant_id': TENANT_ID, 'delay': 5L,
            'max_retries': 5L, 'timeout': 5L, 'pools': [
                {'status': 'PENDING_DELETE', 'status_description': None,
                 'pool_id': POOL_ID}],
            'type': 'PING', 'id': HEALTHMON_ID}
        edge_pool = {'monitorId': [EDGE_MON_ID], 'name': POOL_ID,
                     'applicationRuleId': [], 'member': [],
                     'poolId': 'pool-1', 'algorithm': 'round-robin',
                     'transparent': False}

        pool_mapping = {'edge_id': EDGE_ID, 'edge_pool_id': EDGE_POOL_ID}
        mon_mapping = {'edge_id': EDGE_ID, 'edge_monitor_id': EDGE_MON_ID}

        with contextlib.nested(
            mock.patch.object(self.edge_driver.vcns, 'get_pool'),
            mock.patch.object(self.edge_driver.vcns, 'update_pool'),
            mock.patch.object(self.edge_driver.vcns,
                              'delete_health_monitor'),
            mock.patch.object(self.edge_driver._lb_driver,
                              'delete_pool_health_monitor_successful')
        ) as (mock_get_pool, mock_update_pool, mock_del_mon,
              mock_del_successful):

            mock_get_pool.return_value = (None, edge_pool)
            self.edge_driver.delete_pool_health_monitor(
                self.context, hmon, POOL_ID, pool_mapping, mon_mapping)

            edge_pool['monitorId'] = []
            mock_update_pool.assert_called_with(EDGE_ID, EDGE_POOL_ID,
                                                edge_pool)
            mock_del_mon.assert_called_with(EDGE_ID, EDGE_MON_ID)
            mock_del_successful.assert_called_with(self.context, hmon, POOL_ID,
                                                   mon_mapping)
