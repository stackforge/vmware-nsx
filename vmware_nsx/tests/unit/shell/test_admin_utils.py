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

import importlib
import logging
import mock
import os
from oslo_config import cfg

from neutron.callbacks import registry
from neutron.common import config as neutron_config
from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_n_plugin

from vmware_nsx._i18n import _
from vmware_nsx.common import config  # noqa
from vmware_nsx.shell import resources
from vmware_nsx.tests import unit as vmware
from vmware_nsx.tests.unit.nsx_v.vshield import fake_vcns
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase

LOG = logging.getLogger(__name__)
NSX_INI_PATH = vmware.get_fake_conf('nsx.ini.test')
BASE_CONF_PATH = vmware.get_fake_conf('neutron.conf.test')


class TestAdminUtils(base.BaseTestCase):

    def setUp(self):
        cfg.CONF.register_cli_opts(resources.cli_opts)

        super(TestAdminUtils, self).setUp()

        # Init the neutron config
        neutron_config.init(args=['--config-file', BASE_CONF_PATH,
                                  '--config-file', NSX_INI_PATH])

    def _init_resource_plugin(self):
        plugin_resources = resources.get_resources(self._get_plugin_dir())
        for resource in plugin_resources:
            if (resource != '__init__' and
                # DEBUG ADIT skipping nsxv security groups (stuck)
                (resource != 'securitygroups' or
                 self._get_plugin_name() != 'nsxv')):
                importlib.import_module(
                    "." + resource,
                    "vmware_nsx.shell.admin.plugins."
                    "{}.resources".format(self._get_plugin_name()))

    def _get_plugin_dir(self):
        plugin_dir = (os.path.dirname(os.path.realpath(__file__)) +
                      "/../../../shell/admin/plugins")
        return '{}/{}/resources'.format(plugin_dir, self._get_plugin_name())

    def _test_resource(self, res_name, op):
        # Must call the internal notify_loop in order to get the errors
        errors = registry._get_callback_manager()._notify_loop(
            res_name, op, 'nsxadmin')
        if len(errors) > 0:
            msg = (_("admin util %(res)s/%(op)s failed with message: "
                     "%(err)s") % {'res': res_name,
                                   'op': op,
                                   'err': errors[0]})
            self.fail(msg=msg)

    def _test_resources(self, res_dict):
        for res in res_dict.keys():
            res_name = res_dict[res].name
            for op in res_dict[res].supported_ops:
                self._test_resource(res_name, op)


class TestNsxvAdminUtils(TestAdminUtils,
                         test_n_plugin.NeutronDbPluginV2TestCase):

    def _init_mock_plugin(self):
        mock_vcns = mock.patch(vmware.VCNS_NAME, autospec=True)
        mock_vcns_instance = mock_vcns.start()
        self.fc2 = fake_vcns.FakeVcns()
        mock_vcns_instance.return_value = self.fc2

    def setUp(self):
        super(TestNsxvAdminUtils, self).setUp()

        self._init_mock_plugin()
        self._init_resource_plugin()

    def _get_plugin_name(self):
        return 'nsxv'

    def test_nsxv_resources(self):
        # DEBUG ADIT - current resources:
        # DEBUG ADIT test security-groups/list - import stuck
        # DEBUG ADIT test security-groups/fix-mismatch - import stuck
        # DEBUG ADIT test edges/nsx-list - ok
        # DEBUG ADIT test edges/neutron-list - ok
        # DEBUG ADIT test edges/nsx-update - ok
        # DEBUG ADIT test networks/list - ok
        # DEBUG ADIT test networks/nsx-update - ok
        # DEBUG ADIT test firewall-sections/list - ok
        # DEBUG ADIT test firewall-sections/list-mismatches - ok
        # DEBUG ADIT test orphaned-edges/list - ok
        # DEBUG ADIT test orphaned-edges/clean - ok
        # DEBUG ADIT test spoofguard-policy/list - failed
        # DEBUG ADIT test spoofguard-policy/clean - ok
        # DEBUG ADIT test missing-edges/list - ok
        # DEBUG ADIT test backup-edges/list - ok
        # DEBUG ADIT test backup-edges/clean - ok
        # DEBUG ADIT test backup-edges/list-mismatches - ok
        # DEBUG ADIT test backup-edges/fix-mismatch - ok
        # DEBUG ADIT test nsx-security-groups/list - import stuck
        # DEBUG ADIT test nsx-security-groups/list-mismatches - import stuck
        # DEBUG ADIT test dhcp-binding/list - failed
        # DEBUG ADIT test dhcp-binding/nsx-update - failed
        # DEBUG ADIT test metadata/nsx-update - failed
        # DEBUG ADIT test metadata/nsx-update-secret - failed
        self._test_resources(resources.nsxv_resources)

    #def test_specific(self):
    #    self._test_resource('spoofguard-policy', 'list')


class TestNsxv3AdminUtils(TestAdminUtils,
                          test_n_plugin.NeutronDbPluginV2TestCase,
                          nsxlib_testcase.NsxClientTestCase,
                          #test_plugin.NsxV3PluginTestCaseMixin
                          ):

    def _patch_object(self, *args, **kwargs):
        patcher = mock.patch.object(*args, **kwargs)
        patcher.start()
        self._patchers.append(patcher)

    def _init_mock_plugin(self):
        #self._patch_object(client, 'NSX3Client',
        #                   new=self._mock_client_module)
        #self._patch_object(nsx_plugin, 'nsx_cluster',
        #                    new=self._mock_cluster_module)

        #mock_client_module = mock.Mock()
        #mock_cluster_module = mock.Mock()
        #client = self.new_mocked_client(
        #    nsx_client.NSX3Client, mock_cluster=self.cluster)
        #mock_cluster_module.NSXClusteredAPI.return_value = self.cluster
        #mock_client_module.NSX3Client.return_value = client
        pass

    def setUp(self):
        super(TestNsxv3AdminUtils, self).setUp()

        self._init_mock_plugin()
        self._init_resource_plugin()

    def _get_plugin_name(self):
        return 'nsxv3'

    def test_nsxv3_resources(self):
        # DEBUG ADIT - current resources:
        # DEBUG ADIT test 0 dhcp-binding/list - ok
        # DEBUG ADIT test 1 dhcp-binding/nsx-update - ok
        # DEBUG ADIT test 2 routers/list-mismatches - ok
        # DEBUG ADIT test 3 security-groups/clean - failed
        # DEBUG ADIT test 4 security-groups/list - failed
        # DEBUG ADIT test 5 security-groups/nsx-list - failed
        # DEBUG ADIT test 6 security-groups/nsx-clean - failed
        # DEBUG ADIT test 7 security-groups/neutron-list - ok
        # DEBUG ADIT test 8 security-groups/neutron-clean - failed
        # DEBUG ADIT test 9 networks/list-mismatches - ok
        # DEBUG ADIT test 10 ports/list-mismatches - failed

        # DEBUG ADIT - TO DO - why so slow??
        # DEBUG ADIT - TO DO - test the real nsxadmin on nsxt
        self._test_resources(resources.nsxv3_resources)
