# Copyright 2017 VMware Inc
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
from oslo_log import log as logging
import time

from tempest import config
from tempest.scenario import manager

from vmware_nsx_tempest.common import constants

CONF = config.CONF
LOG = logging.getLogger(__name__)


class NetworkElements(manager.NetworkScenarioTest):

    def get_internal_ips(self, server, network, device="network"):
        internal_ips = [p['fixed_ips'][0]['ip_address'] for p in
            self.admin_manager.ports_client.list_ports(
                tenant_id=server['tenant_id'], network_id=network['id'])[
                'ports'] if p['device_owner'].startswith(device)]
        return internal_ips

    def verify_empty_security_group_status(self, security_group):
        ip_protocols = ["IPV6", "IPV4"]
        nsx_fw_section, nsx_fw_section_rules = \
            self.nsx_client.get_firewall_section_and_rules(
                security_group['name'], security_group['id'])
        msg = "Newly created empty security group does not meet criteria !!!"
        self.assertEqual(nsx_fw_section["rule_count"], 2, msg)
        self.assertEqual(nsx_fw_section_rules[0]["action"], "ALLOW", msg)
        self.assertEqual(nsx_fw_section_rules[1]["action"], "ALLOW", msg)
        self.assertEqual(nsx_fw_section_rules[0]["direction"], "OUT", msg)
        self.assertEqual(nsx_fw_section_rules[1]["direction"], "OUT", msg)
        self.assertIn(nsx_fw_section_rules[0]["ip_protocol"],
                      ip_protocols, msg)
        self.assertIn(nsx_fw_section_rules[1]["ip_protocol"],
                      ip_protocols, msg)

    def create_empty_security_group(self, namestart="vmw_"):
        security_group = self._create_empty_security_group(namestart=namestart)
        time.sleep(constants.NSX_FIREWALL_REALIZED_DELAY)
        self.verify_empty_security_group_status(security_group)
        return security_group

    def add_security_group_rule(self, security_group, rule):
        return self._create_security_group_rule(
            secgroup=security_group, **rule)

    def get_server_key(self, server):
        return self.topology_keypairs[server['key_name']]['private_key']

    def check_server_internal_ips_using_floating_ip(
            self, floating_ip, server, address_list, should_connect=True):
        ip_address = floating_ip['floating_ip_address']
        private_key = self.get_server_key(server)
        ssh_source = self.get_remote_client(
            ip_address, private_key=private_key)
        for remote_ip in address_list:
            self.check_remote_connectivity(ssh_source, remote_ip,
                                           should_connect)

    def check_network_internal_connectivity(
            self, network, floating_ip, server, should_connect=True):
        """via ssh check VM internal connectivity:
        - ping internal gateway and DHCP port, implying in-tenant connectivity
        pinging both, because L3 and DHCP agents might be on different nodes
        """
        # get internal ports' ips:
        # get all network ports in the new network
        internal_ips = self.get_internal_ips(server, network, device="network")
        self.check_server_internal_ips_using_floating_ip(
            floating_ip, server, internal_ips, should_connect)

    def check_vm_internal_connectivity(
            self, network, floating_ip, server, should_connect=True):
        # test internal connectivity to the other VM on the same network
        compute_ips = self.get_internal_ips(server, network, device="compute")
        self.check_server_internal_ips_using_floating_ip(
            floating_ip, server, compute_ips, should_connect)

    def using_floating_ip_check_server_and_project_network_connectivity(
            self, server_details):
        network = server_details.network
        floating_ip = server_details.floating_ip
        server = server_details.server
        self.check_network_internal_connectivity(network, floating_ip, server)
        self.check_vm_internal_connectivity(network, floating_ip, server)

    def check_cross_network_connectivity(
            self, network1, floating_ip_on_network2, server_on_network2,
            should_connect=False):
        # test internal connectivity to the other VM on the same network
        remote_ips = self.get_internal_ips(
            server_on_network2, network1, device="compute")
        self.check_server_internal_ips_using_floating_ip(
            floating_ip_on_network2, server_on_network2, remote_ips,
            should_connect)
