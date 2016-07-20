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

from neutron.api.v2 import attributes as attr
from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron.tests.unit.extensions import test_securitygroup
from neutron_lib.api import validators
import webob.exc

from vmware_nsx.db import extended_security_group
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.tests.unit.nsx_v3 import test_plugin as test_nsxv3_plugin


PLUGIN_NAME = ('vmware_nsx.tests.unit.extensions.'
               'test_provider_security_groups.ProviderSecurityGroupTestPlugin')


# FIXME(arosen): make common mixin for extended_security_group_properties and
# security_group_db_minxin.
class ProviderSecurityGroupTestPlugin(
    db_base_plugin_v2.NeutronDbPluginV2,
    extended_security_group.ExtendedSecurityGroupPropertiesMixin,
        securitygroups_db.SecurityGroupDbMixin):

    supported_extension_aliases = ["security-group",
                                   "provider-security-group"]

    def create_security_group(self, context, security_group, default_sg=False):
        secgroup = security_group['security_group']
        with context.session.begin(subtransactions=True):
            # NOTE(arosen): a neutron security group be default adds rules
            # that allow egress traffic. We do not want this behavior for
            # provider security_groups
            if secgroup.get(provider_sg.PROVIDER) is True:
                secgroup_db = self.create_provider_security_group(
                    context, security_group)
            else:
                secgroup_db = (
                    super(ProviderSecurityGroupTestPlugin, self
                          ).create_security_group(context, security_group,
                                                  default_sg))

            self._process_security_group_properties_create(context,
                                                           secgroup_db,
                                                           secgroup,
                                                           default_sg)
        return secgroup_db

    def create_port(self, context, port, l2gw_port_check=False):
        port_data = port['port']

        with context.session.begin(subtransactions=True):
            tenant_id = port_data['tenant_id']
            default_sg = self._ensure_default_security_group(
                context, tenant_id)
            if not validators.is_attr_set(
                port['port'].get(ext_sg.SECURITYGROUPS)
            ):
                port['port'][ext_sg.SECURITYGROUPS] = [default_sg]
            sgids = self._get_security_groups_on_port(context, port)
            port_db = super(ProviderSecurityGroupTestPlugin, self).create_port(
                context, port)
            port_data.update(port_db)

            # handle adding security groups to port
            self._process_port_create_security_group(
                context, port_db, sgids)

            # handling adding provider security group to port if there are any
            provider_groups = self._get_provider_security_groups_on_port(
                context, port)
            self._process_port_create_provider_security_group(
                context, port_data, provider_groups)
        return port_data

    def update_port(self, context, id, port):
        with context.session.begin(subtransactions=True):

            original_port = super(ProviderSecurityGroupTestPlugin,
                                  self).get_port(context, id)
            updated_port = super(ProviderSecurityGroupTestPlugin,
                                 self).update_port(context, id, port)

            self._process_port_update_provider_security_group(
                context, port, original_port, updated_port)
            return self.get_port(context, id)


class ProviderSecurityGroupExtTestCase(
        test_securitygroup.SecurityGroupDBTestCase):
    def setUp(self, plugin=PLUGIN_NAME, ext_mgr=None):
        super(ProviderSecurityGroupExtTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)

        # add provider group attributes
        attr.RESOURCE_ATTRIBUTE_MAP['security_groups'].update(
            provider_sg.EXTENDED_ATTRIBUTES_2_0['security_groups'])

        attr.RESOURCE_ATTRIBUTE_MAP['ports'].update(
            provider_sg.EXTENDED_ATTRIBUTES_2_0['ports'])

    def tearDown(self):
        # remove provider security group attributes
        del attr.RESOURCE_ATTRIBUTE_MAP['security_groups']['provider']
        del attr.RESOURCE_ATTRIBUTE_MAP['ports']['provider_security_groups']
        super(ProviderSecurityGroupExtTestCase, self).tearDown()

    def _create_provider_security_group(self):
        body = {'security_group': {'name': 'provider-deny',
                                   'tenant_id': 'foobar',
                                   'description': 'foobarzzkk',
                                   'provider': True}}
        security_group_req = self.new_create_request('security-groups', body)
        return self.deserialize(self.fmt,
                                security_group_req.get_response(self.ext_api))

    def test_create_provider_security_group(self):
        # confirm this attribute is true
        provider_secgroup = self._create_provider_security_group()
        self.assertTrue(provider_secgroup['security_group']['provider'])

        # provider security groups have no rules by default which is different
        # from normal neutron security groups which by default include a rule
        # to allow egress traffic. We confirm this here.
        self.assertEqual(
            provider_secgroup['security_group']['security_group_rules'], [])

    def test_create_port_gets_provider_sg(self):
        # need to create provider security group first.
        provider_secgroup = self._create_provider_security_group()
        with self.port(tenant_id='foobar') as p:
            # check that the provider security group is on port resource.
            self.assertEqual(provider_secgroup['security_group']['id'],
                             p['port']['provider_security_groups'][0])

            # confirm there is still a default security group.
            self.assertEqual(len(p['port']['security_groups']), 1)

    def test_update_port_remove_provider_sg(self):
        # need to create provider security group first.
        self._create_provider_security_group()
        with self.port(tenant_id='foobar') as p:
            body = {'port': {'provider_security_groups': []}}
            req = self.new_update_request('ports', body,
                                          p['port']['id'])
            port = self.deserialize(self.fmt,
                                    req.get_response(self.api))
            # confirm that the group has been removed.
            self.assertEqual(port['port']['provider_security_groups'], [])

    def test_cannot_update_port_with_provider_group_as_sec_group(self):
        with self.network() as n:
            with self.subnet(n):
                with self.port(tenant_id='foobar') as p:
                    provider_secgroup = self._create_provider_security_group()
                    sg_id = provider_secgroup['security_group']['id']
                    body = {'port': {'security_groups': [sg_id]}}
                    req = self.new_update_request('ports', body,
                                                  p['port']['id'])

                    res = req.get_response(self.api)
                    self.assertEqual(webob.exc.HTTPBadRequest.code,
                                     res.status_int)

    def test_cannot_update_port_with_sec_group_as_provider(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg1:
                    with self.port(tenant_id='foobar') as p:
                        sg_id = sg1['security_group']['id']
                        body = {'port': {'provider_security_groups': [sg_id]}}
                        req = self.new_update_request('ports', body,
                                                      p['port']['id'])

                        res = req.get_response(self.api)
                        self.assertEqual(webob.exc.HTTPBadRequest.code,
                                         res.status_int)


class TestNSXv3ProviderSecurityGrp(test_nsxv3_plugin.NsxV3PluginTestCaseMixin,
                                   ProviderSecurityGroupExtTestCase):
    pass

# TODO(roeyc): add nsxv test case mixin when ready
