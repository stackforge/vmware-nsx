# Copyright 2015 VMware, Inc.
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

from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.api.v2 import attributes
from neutron.common import constants as const
from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db
from neutron.tests.unit.extensions import test_securitygroup

from vmware_nsx.db import extended_security_group_rule as ext_rule_db
from vmware_nsx.extensions import secgroup_rule_local_ip_prefix as sg_local_ip
from vmware_nsx.tests import unit as vmware


DB_PLUGIN_KLASS = ('vmware_nsx.tests.unit.extensions.'
                   'test_extended_security_group_rule.ExtendedRuleTestPlugin')

_uuid = uuidutils.generate_uuid


class ExtendedRuleTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                             securitygroups_db.SecurityGroupDbMixin,
                             ext_rule_db.ExtendedSecurityGroupRuleMixin):

    supported_extension_aliases = ["security-group",
                                   "secgroup-rule-local-ip-prefix"]

    def create_security_group_rule_bulk(self, context, security_group_rule):
        for r in security_group_rule['security_group_rules']:
            rule = r['security_group_rule']
            if not self._check_local_ip_prefix(context, rule):
                rule['local_ip_prefix'] = None
        with context.session.begin(subtransactions=True):
            super(ExtendedRuleTestPlugin,
                  self).create_security_group_rule_bulk_native(
                      context, security_group_rule)
            if rule['local_ip_prefix']:
                if rule['direction'] != 'ingress':
                    raise ext_rule_db.NotIngressRule()
                self._save_extended_rule_properties(context, rule)


class ExtendedRuleDbTestCase(test_securitygroup.SecurityGroupsTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        plugin = plugin or DB_PLUGIN_KLASS
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        ext_mgr = test_securitygroup.SecurityGroupTestExtensionManager()
        super(ExtendedRuleDbTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)
        attributes.RESOURCE_ATTRIBUTE_MAP['security_group_rules'].update(
            sg_local_ip.RESOURCE_ATTRIBUTE_MAP['security_group_rules'])

    def _build_ingress_rule_with_local_ip_prefix(self, security_group_id,
                                                 local_ip_prefix,
                                                 remote_ip_prefix):
        rule = self._build_security_group_rule(security_group_id,
                                               direction='ingress',
                                               proto=const.PROTO_NAME_UDP)
        rule['security_group_rule']['local_ip_prefix'] = local_ip_prefix
        return rule

    def test_raise_rule_not_ingress_when_local_ip_specified(self):
        local_ip_prefix = '239.255.0.0/16'
        remote_ip_prefix = '10.0.0.0/24'
        with self.security_group() as sg:
            rule = self._build_ingress_rule_with_local_ip_prefix(
                sg['security_group']['id'], local_ip_prefix, remote_ip_prefix)
            self._make_security_group_rule(self.fmt, rule)


class TestExtendedRule(ExtendedRuleDbTestCase):
    pass
