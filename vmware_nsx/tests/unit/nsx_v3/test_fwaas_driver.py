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

import copy
import mock

from vmware_nsx.plugins.nsx_v3 import plugin as nsx_plugin
from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_v3_plugin

FAKE_FW_ID = 'fake_fw_uuid'


class NsxvFwaasTestCase(test_v3_plugin.NsxV3PluginTestCaseMixin):
    def setUp(self):
        super(NsxvFwaasTestCase, self).setUp()
        self.firewall = edge_fwaas_driver.EdgeFwaasV3Driver()

    def _fake_rules_v4(self):
        rule1 = {'enabled': True,
                 'action': 'allow',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '80',
                 'source_ip_address': '10.24.4.2',
                 'id': 'fake-fw-rule1',
                 'description': 'first rule'}
        rule2 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '22',
                 'id': 'fake-fw-rule2'}
        rule3 = {'enabled': True,
                 'action': 'reject',
                 'ip_version': 4,
                 'protocol': 'icmp',
                 'id': 'fake-fw-rule3'}
        return [rule1, rule2, rule3]

    def _fake_translated_rules(self):
        # The expected translation of the rules in _fake_rules_v4
        service1 = {'l4_protocol': 'TCP',
                    'resource_type': 'L4PortSetNSService',
                    'destination_ports': ['80'],
                    'source_ports': []}
        rule1 = {'action': 'ALLOW',
                 'services': [{'service': service1}],
                 'sources': [{'target_id': '10.24.4.2',
                              'target_type': 'IPv4Address'}],
                 'display_name': 'Fwaas-fake-fw-rule1',
                 'notes': 'first rule'}
        service2 = {'l4_protocol': 'TCP',
                    'resource_type': 'L4PortSetNSService',
                    'destination_ports': ['22'],
                    'source_ports': []}
        rule2 = {'action': 'DROP',
                 'services': [{'service': service2}],
                 'display_name': 'Fwaas-fake-fw-rule2'}
        service3_1 = {'resource_type': 'ICMPTypeNSService',
                      'protocol': 'ICMPv4'}
        service3_2 = {'resource_type': 'ICMPTypeNSService',
                      'protocol': 'ICMPv6'}
        rule3 = {'action': 'DROP',  # Reject is replaced with deny
                 # icmp is translated to icmp v4 & v6
                 'services': [{'service': service3_1},
                              {'service': service3_2}],
                 'display_name': 'Fwaas-fake-fw-rule3'}
        return [rule1, rule2, rule3]

    def _fake_firewall_no_rule(self):
        rule_list = []
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'firewall_rule_list': rule_list}
        return fw_inst

    def _fake_firewall(self, rule_list):
        _rule_list = copy.deepcopy(rule_list)
        for rule in _rule_list:
            rule['position'] = str(_rule_list.index(rule))
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'firewall_rule_list': _rule_list}
        return fw_inst

    def _fake_firewall_with_admin_down(self, rule_list):
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': False,
                   'tenant_id': 'tenant-uuid',
                   'firewall_rule_list': rule_list}
        return fw_inst

    def _fake_apply_list(self, router_count=1):
        apply_list = []
        while router_count > 0:
            router_inst = {}
            router_info_inst = mock.Mock()
            router_info_inst.router = router_inst
            apply_list.append(router_info_inst)
            router_count -= 1
        return apply_list

    def _setup_firewall_with_rules(self, func, router_count=1):
        apply_list = self._fake_apply_list(router_count=router_count)
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall(rule_list)
        with mock.patch.object(nsx_plugin.NsxV3Plugin,
                               "_update_router_firewall") as update_fw,\
            mock.patch.object(nsx_plugin.NsxV3Plugin, "_get_router"):
            func('nsx', apply_list, firewall)
            self.assertEqual(router_count, update_fw.call_count)
            update_fw.assert_called_with(
                mock.ANY, mock.ANY,
                fwaas_allow_external=False,
                fwaas_rules=self._fake_translated_rules())

    def test_create_firewall_no_rules(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_firewall_no_rule()
        with mock.patch.object(nsx_plugin.NsxV3Plugin,
                               "_update_router_firewall") as update_fw,\
            mock.patch.object(nsx_plugin.NsxV3Plugin, "_get_router"):
            self.firewall.create_firewall('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                mock.ANY, mock.ANY,
                fwaas_allow_external=False,
                fwaas_rules=[])

    def test_create_firewall_with_rules(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall)

    def test_create_firewall_with_rules_two_routers(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall,
                                        router_count=2)

    def test_update_firewall_with_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall)

    def test_delete_firewall(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_firewall_no_rule()
        with mock.patch.object(nsx_plugin.NsxV3Plugin,
                               "_update_router_firewall") as update_fw,\
            mock.patch.object(nsx_plugin.NsxV3Plugin, "_get_router"):
            self.firewall.delete_firewall('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                mock.ANY, mock.ANY,
                fwaas_allow_external=True,
                fwaas_rules=[])

    def test_create_firewall_with_admin_down(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall_with_admin_down(rule_list)
        with mock.patch.object(nsx_plugin.NsxV3Plugin,
                               "_update_router_firewall") as update_fw,\
            mock.patch.object(nsx_plugin.NsxV3Plugin, "_get_router"):
            self.firewall.create_firewall('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                mock.ANY, mock.ANY,
                fwaas_allow_external=False,
                fwaas_rules=[])
