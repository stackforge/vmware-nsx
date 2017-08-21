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

from neutron_lib.plugins import directory

from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver_base
from vmware_nsx.services.fwaas.nsx_v3 import edge_fwaas_driver_v2
from vmware_nsx.services.fwaas.nsx_v3 import fwaas_callbacks_v2
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_v3_plugin
from vmware_nsxlib.v3 import nsx_constants as consts

FAKE_FW_ID = 'fake_fw_uuid'
FAKE_ROUTER_ID = 'fake_rtr_uuid'
FAKE_PORT_ID = 'fake_port_uuid'
FAKE_NSX_PORT_ID = 'fake_nsx_port_uuid'
MOCK_NSX_ID = 'nsx_nsx_router_id'
MOCK_DEFAULT_RULE_ID = 'nsx_default_rule_id'
MOCK_SECTION_ID = 'sec_id'
DEFAULT_RULE = {'is_default': True,
                'display_name': edge_fwaas_driver_base.DEFAULT_RULE_NAME,
                'id': MOCK_DEFAULT_RULE_ID,
                'action': consts.FW_ACTION_DROP}


class Nsxv3FwaasTestCase(test_v3_plugin.NsxV3PluginTestCaseMixin):
    def setUp(self):
        super(Nsxv3FwaasTestCase, self).setUp()
        self.firewall = edge_fwaas_driver_v2.EdgeFwaasV3DriverV2()

        # Start some nsxlib/DB mocks
        mock.patch(
            "vmware_nsxlib.v3.core_resources.NsxLibLogicalRouter."
            "get_firewall_section_id",
            return_value=MOCK_SECTION_ID).start()

        mock.patch(
            "vmware_nsxlib.v3.security.NsxLibFirewallSection."
            "get_default_rule",
            return_value={'id': MOCK_DEFAULT_RULE_ID}).start()

        mock.patch(
            "vmware_nsx.db.db.get_nsx_router_id",
            return_value=MOCK_NSX_ID).start()

        self.plugin = directory.get_plugin()
        self.plugin.fwaas_callbacks_v2 = fwaas_callbacks_v2.\
            Nsxv3FwaasCallbacksV2(self.plugin.nsxlib)
        self.plugin.fwaas_callbacks_v2.fwaas_enabled = True
        self.plugin.fwaas_callbacks_v2.fwaas_driver = self.firewall

    def _default_rule(self):
        rule = DEFAULT_RULE
        rule['action'] = consts.FW_ACTION_ALLOW
        return rule

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
                 'action': 'reject',
                 'ip_version': 4,
                 'protocol': 'tcp',
                 'destination_port': '22:24',
                 'source_port': '1:65535',
                 'id': 'fake-fw-rule2'}
        rule3 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'protocol': 'icmp',
                 'id': 'fake-fw-rule3'}
        rule4 = {'enabled': True,
                 'action': 'deny',
                 'ip_version': 4,
                 'source_ip_address': '10.25.5.2',
                 'id': 'fake-fw-rule4'}
        return [rule1, rule2, rule3, rule4]

    def _fake_translated_rules(self, nsx_port_id):
        # DEBUG ADIT - support ingress too
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
                    'destination_ports': ['22-24'],
                    'source_ports': ['1-65535']}
        rule2 = {'action': 'DROP',  # Reject is replaced with deny
                 'services': [{'service': service2}],
                 'display_name': 'Fwaas-fake-fw-rule2'}
        service3_1 = {'resource_type': 'ICMPTypeNSService',
                      'protocol': 'ICMPv4'}
        service3_2 = {'resource_type': 'ICMPTypeNSService',
                      'protocol': 'ICMPv6'}
        rule3 = {'action': 'DROP',
                 # icmp is translated to icmp v4 & v6
                 'services': [{'service': service3_1},
                              {'service': service3_2}],
                 'display_name': 'Fwaas-fake-fw-rule3'}
        rule4 = {'action': 'DROP',
                 'sources': [{'target_id': '10.25.5.2',
                              'target_type': 'IPv4Address'}],
                 'display_name': 'Fwaas-fake-fw-rule4'}

        rule1['destinations'] = [{'target_id': nsx_port_id,
                                  'target_type': 'LogicalPort'}]
        rule2['destinations'] = rule1['destinations']
        rule3['destinations'] = rule1['destinations']
        rule4['destinations'] = rule1['destinations']
        return [rule1, rule2, rule3, rule4]

    def _fake_empty_firewall_group(self):
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'ingress_rule_list': [],
                   'egress_rule_list': []}
        return fw_inst

    def _fake_firewall_group(self, rule_list):
        _rule_list = copy.deepcopy(rule_list)
        for rule in _rule_list:
            rule['position'] = str(_rule_list.index(rule))
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': True,
                   'tenant_id': 'tenant-uuid',
                   'ingress_rule_list': _rule_list,
                   'egress_rule_list': []}
        return fw_inst

    def _fake_firewall_group_with_admin_down(self, rule_list):
        fw_inst = {'id': FAKE_FW_ID,
                   'admin_state_up': False,
                   'tenant_id': 'tenant-uuid',
                   'ingress_rule_list': rule_list,
                   'egress_rule_list': []}
        return fw_inst

    def _fake_apply_list(self):
        router_inst = {'id': FAKE_ROUTER_ID}
        router_info_inst = mock.Mock()
        router_info_inst.router = router_inst
        router_info_inst.router_id = FAKE_ROUTER_ID
        apply_list = [(router_info_inst, FAKE_PORT_ID)]
        return apply_list

    def _setup_firewall_with_rules(self, func):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall_group(rule_list)
        port = {'id': FAKE_PORT_ID}
        with mock.patch.object(self.plugin, '_get_router_interfaces',
                               return_value=[port]),\
            mock.patch.object(self.plugin.fwaas_callbacks_v2, 'get_port_fwg',
                              return_value=firewall),\
            mock.patch("vmware_nsx.db.db.get_nsx_switch_and_port_id",
                       return_value=(0, FAKE_NSX_PORT_ID)),\
            mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                       "update") as update_fw:
            func('nsx', apply_list, firewall)
            expected_rules = self._fake_translated_rules(FAKE_NSX_PORT_ID) + [
                {'display_name': "Block port ingress",
                 'action': consts.FW_ACTION_DROP,
                 'destinations': [{'target_type': 'LogicalPort',
                                   'target_id': FAKE_NSX_PORT_ID}],
                 'direction': 'IN'},
                {'display_name': "Block port egress",
                 'action': consts.FW_ACTION_DROP,
                 'sources': [{'target_type': 'LogicalPort',
                              'target_id': FAKE_NSX_PORT_ID}],
                 'direction': 'OUT'},
                self._default_rule()
            ]
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=expected_rules)

    def test_create_firewall_no_rules(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_empty_firewall_group()
        port = {'id': FAKE_PORT_ID}
        with mock.patch.object(self.plugin, '_get_router_interfaces',
                               return_value=[port]),\
            mock.patch.object(self.plugin.fwaas_callbacks_v2, 'get_port_fwg',
                              return_value=firewall),\
            mock.patch("vmware_nsx.db.db.get_nsx_switch_and_port_id",
                       return_value=(0, FAKE_NSX_PORT_ID)),\
            mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                       "update") as update_fw:
            self.firewall.create_firewall_group('nsx', apply_list, firewall)
            # expecting 2 block rules for the logical port (egress & ingress)
            # and last default allow all rule
            expected_rules = [
                {'display_name': "Block port ingress",
                 'action': consts.FW_ACTION_DROP,
                 'destinations': [{'target_type': 'LogicalPort',
                                   'target_id': FAKE_NSX_PORT_ID}],
                 'direction': 'IN'},
                {'display_name': "Block port egress",
                 'action': consts.FW_ACTION_DROP,
                 'sources': [{'target_type': 'LogicalPort',
                              'target_id': FAKE_NSX_PORT_ID}],
                 'direction': 'OUT'},
                self._default_rule()
            ]
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=expected_rules)

    def test_create_firewall_with_rules(self):
        self._setup_firewall_with_rules(self.firewall.create_firewall_group)

    def test_update_firewall_with_rules(self):
        self._setup_firewall_with_rules(self.firewall.update_firewall)

    def test_delete_firewall(self):
        apply_list = self._fake_apply_list()
        firewall = self._fake_empty_firewall_group()
        port = {'id': FAKE_PORT_ID}
        with mock.patch.object(self.plugin, '_get_router_interfaces',
                               return_value=[port]),\
            mock.patch.object(self.plugin.fwaas_callbacks_v2, 'get_port_fwg',
                              return_value=None),\
            mock.patch("vmware_nsx.db.db.get_nsx_switch_and_port_id",
                       return_value=(0, FAKE_NSX_PORT_ID)),\
            mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                       "update") as update_fw:
            self.firewall.delete_firewall_group('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=[self._default_rule()])

    def test_create_firewall_with_admin_down(self):
        apply_list = self._fake_apply_list()
        rule_list = self._fake_rules_v4()
        firewall = self._fake_firewall_group_with_admin_down(rule_list)
        with mock.patch("vmware_nsxlib.v3.security.NsxLibFirewallSection."
                        "update") as update_fw:
            self.firewall.create_firewall_group('nsx', apply_list, firewall)
            update_fw.assert_called_once_with(
                MOCK_SECTION_ID,
                rules=[self._default_rule()])

    # DEBUG ADIT add ingress test
    # DEBUG ADIT test illegal rule
