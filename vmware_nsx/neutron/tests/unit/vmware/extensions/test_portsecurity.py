# Copyright (c) 2014 OpenStack Foundation.
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

import mock
from oslo_config import cfg

from neutron.tests.unit.extensions import test_portsecurity as psec
from vmware_nsx.neutron.plugins.vmware.common import sync
from vmware_nsx.neutron.tests.unit import vmware
from vmware_nsx.neutron.tests.unit.vmware.apiclient import fake


class PortSecurityTestCase(psec.PortSecurityDBTestCase):

    def setUp(self):
        cfg.CONF.set_override("default_tz_uuid", "fake_tz_uuid")
	cfg.CONF.set_override("nsx_controllers", ["fake1", "fake_2"])
        cfg.CONF.set_override("nsx_user", "foo")
        cfg.CONF.set_override("nsx_password", "bar")
        cfg.CONF.set_override("default_l3_gw_service_uuid", "whatever")
        cfg.CONF.set_override("default_l2_gw_service_uuid", "whatever")
        # mock api client
        self.fc = fake.FakeClient(vmware.STUBS_PATH)
        self.mock_nsx = mock.patch(vmware.NSXAPI_NAME, autospec=True)
        instance = self.mock_nsx.start()
        instance.return_value.login.return_value = "the_cookie"
        # Avoid runs of the synchronizer looping call
        patch_sync = mock.patch.object(sync, '_start_loopingcall')
        patch_sync.start()

        instance.return_value.request.side_effect = self.fc.fake_request
        super(PortSecurityTestCase, self).setUp(vmware.PLUGIN_NAME)
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nsx.stop)
        self.addCleanup(patch_sync.stop)


class TestPortSecurity(PortSecurityTestCase, psec.TestPortSecurity):
        pass
