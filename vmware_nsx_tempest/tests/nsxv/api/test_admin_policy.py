# Copyright 2016 VMware Inc
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

import re

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.tests.nsxv.api import base_provider as base

CONF = config.CONF


class AdminPolicyTest(base.BaseAdminNetworkTest):

    @classmethod
    def skip_checks(cls):
        super(AdminPolicyTest, cls).skip_checks()
        if not test.is_extension_enabled('security-group-policy', 'network'):
            msg = "Extension security-group-oplicy is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(AdminPolicyTest, cls).setup_clients()
        cls.cmgr_pri = cls.get_client_manager('primary')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    @classmethod
    def resource_setup(cls):
        super(AdminPolicyTest, cls).resource_setup()
        cls.default_policy_id = CONF.nsxv.default_policy_id
        if not (cls.default_policy_id and
                cls.default_policy_id.startswith("policy-")):
            msg = "default_policy_id is not defined in session nsxv"
            raise cls.skipException(msg)

    def _delete_security_group(self, sg_client, sg_id):
        sg_client.delete_security_group(sg_id)

    def create_security_group_policy(self, cmgr=None, policy_id=None,
                                     tenant_id=None):
        policy_id = policy_id or self.default_policy_id
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg_dict = dict(policy=policy_id,
                       name=data_utils.rand_name('admin-policy'))
        if tenant_id:
            sg_dict['tenant_id'] = tenant_id
        sg = sg_client.create_security_group(**sg_dict)
        sg = sg.get('security_group', sg)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self._delete_security_group,
                        sg_client, sg.get('id'))
        return sg

    def create_security_group_rule(self, security_group_id,
                                   cmgr=None, tenant_id=None):
        cmgr = cmgr or self.cmgr_adm
        sgr_client = cmgr.security_group_rules_client
        sgr_dict = dict(security_group_id=security_group_id,
                        direction='ingress', protocol='icmp')
        if tenant_id:
            sgr_dict['tenant_id'] = tenant_id
        sgr = sgr_client.create_security_group_rule(**sgr_dict)
        return sgr.get('security_group_rule', sgr)


    def get_default_security_group_policy(self, cmgr=None):
        cmgr = cmgr or self.cmgr_adm
        sg_client = cmgr.security_groups_client
        sg_list = sg_client.list_security_groups()
        # why list twice, see bug#1772424
        sg_list = sg_client.list_security_groups(name='default')
        sg_list = sg_list.get('security_groups', sg_list)
        return sg_list[0]

    @test.idempotent_id('809d72be-c2d8-4e32-b538-09a5003630c0')
    def test_admin_can_create_policy_for_tenant(self):
        tenant_id = self.cmgr_alt.networks_client.tenant_id
        sg = self.create_security_group_policy(self.cmgr_adm,
                                               tenant_id=tenant_id)
        self.assertEqual(self.default_policy_id, sg.get('policy'))

    @test.idempotent_id('1d31ea7a-37f1-40db-b917-4acfbf565ae2')
    def test_tenant_has_default_policy(self):
        sg = self.get_default_security_group_policy(self.cmgr_pri)
        self.assertEqual(self.default_policy_id, sg.get('policy'))

    @test.attr(type=['negative'])
    @test.idempotent_id('5099604c-637a-4b25-8756-c6fc0929f963')
    def test_add_rules_to_policy_disallowed(self):
        tenant_id = self.cmgr_pri.networks_client.tenant_id
        sg = self.create_security_group_policy(self.cmgr_adm,
                                               tenant_id=tenant_id)
        self.assertRaises(exceptions.BadRequest,
            self.create_security_group_rule, sg.get('id'),
            cmgr=self.cmgr_adm, tenant_id=tenant_id)

    @test.attr(type=['negative'])
    @test.idempotent_id('9a604036-ace6-4ced-92b8-be732eee310f')
    def test_create_policy_with_invalid_policy_id(self):
        self.assertRaises(exceptions.BadRequest,
                          self.create_security_group_policy,
                          self.cmgr_adm, "invalid-policy-id")

    @test.attr(type=['negative'])
    @test.idempotent_id('d6d8c918-d488-40c4-83dc-8ce1a565e54f')
    def test_tenant_canot_create_policy(self):
        self.assertRaises(exceptions.Forbidden,
                          self.create_security_group_policy,
                          self.cmgr_pri)
