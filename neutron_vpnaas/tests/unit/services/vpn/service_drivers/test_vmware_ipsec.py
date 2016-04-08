# Copyright 2016 VMware, Inc.
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

import mock

from neutron_vpnaas.services.vpn.service_drivers import vmware_ipsec
from neutron_vpnaas.tests import base

FAKE_IPSEC_CONNECTION = {}
FAKE_CONTEXT = {}
FAKE_VPNSERVICE = {}

DRIVER_PATH = ('neutron_vpnaas.services.vpn.service_drivers.'
               'vmware_ipsec.VMwareIPsecVPNDriver')
PATH = ('neutron_vpnaas.tests.unit.services.vpn.service_drivers'
        '.test_vmware_ipsec.FakeVmwareIPsecVPNDriver')


class FakeVmwareIPsecVPNDriver(object):

    def create_ipsec_site_connection(context, ipsec_site_connection):
        pass

    def update_ipsec_site_connection(context, old_ipsec_site_connection,
                                     ipsec_site_connection):
        pass

    def delete_ipsec_site_connection(context, ipsec_site_connection):
        pass

    def create_vpnservice(self, context, vpnservice):
        pass

    def ipsec_site_conn_status_update(self, context, status):
        pass


class TestVmwareIPsecVPNService(base.BaseTestCase):

    @mock.patch("%s.__init__" % DRIVER_PATH)
    def setUp(self, mock_init):
        super(TestVmwareIPsecVPNService, self).setUp()
        self.service_plugin = mock.Mock()
        self.service_plugin.ipsec_site_conn_status_update = mock.Mock()
        mock_init.return_value = None
        self.vpn_service = vmware_ipsec.VMwareIPsecVPNDriver(
                                                self.service_plugin)
        self.vpn_service._driver = FakeVmwareIPsecVPNDriver()
        self.vpn_service.service_plugin = self.service_plugin

    @mock.patch("%s.create_ipsec_site_connection" % PATH)
    def test_create_ipsec_site_connection(self, mock_create):
        self.vpn_service.create_ipsec_site_connection(FAKE_CONTEXT,
                                                      FAKE_IPSEC_CONNECTION)
        mock_create.assert_called_once_with(FAKE_CONTEXT,
                                            FAKE_IPSEC_CONNECTION)

    @mock.patch("%s.update_ipsec_site_connection" % PATH)
    def test_update_ipsec_site_connection(self, mock_update):
        self.vpn_service.update_ipsec_site_connection(FAKE_CONTEXT,
                                                      FAKE_IPSEC_CONNECTION,
                                                      FAKE_IPSEC_CONNECTION)
        mock_update.assert_called_once_with(FAKE_CONTEXT,
                                            FAKE_IPSEC_CONNECTION,
                                            FAKE_IPSEC_CONNECTION)

    @mock.patch("%s.delete_ipsec_site_connection" % PATH)
    def test_delete_ipsec_site_connection(self, mock_delete):
        self.vpn_service.delete_ipsec_site_connection(FAKE_CONTEXT,
                                                      FAKE_IPSEC_CONNECTION)
        mock_delete.assert_called_once_with(FAKE_CONTEXT,
                                            FAKE_IPSEC_CONNECTION)

    @mock.patch("%s.create_vpnservice" % PATH)
    def test_create_vpnservice(self, mock_create_vpn):
        self.vpn_service.create_vpnservice(FAKE_CONTEXT, FAKE_VPNSERVICE)
        mock_create_vpn.assert_called_once_with(FAKE_CONTEXT,
                                                FAKE_VPNSERVICE)

    def test_update_ipsec_status(self):
        self.vpn_service.ipsec_site_conn_status_update(FAKE_CONTEXT, "UP")
        self.service_plugin.update_status_by_agent.assert_called_once_with(
                                                FAKE_CONTEXT, "UP")
