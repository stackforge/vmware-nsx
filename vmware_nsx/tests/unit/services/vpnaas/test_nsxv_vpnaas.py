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

from neutron import context
from neutron.tests import base
from neutron_lib import exceptions as n_exc
from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vcns_exc
from vmware_nsx.services.vpnaas.nsxv import vpnaas_driver


DRIVER_PATH = "vmware_nsx.services.vpnaas.nsxv.vpnaas_driver.EdgeVPNDriver"
VALI_PATH = "vmware_nsx.services.vpnaas.nsxv.vpnaas_validator.VpnValidator"
FAKE_ROUTER_ID = "aaaaaa-bbbbb-ccc"
FAKE_IPSEC_CONNECTION = {"vpnservice_id": "cccc-dddd",
                         "id": "cccc-dddd"}
FAKE_EDGE_ID = "cccc-dddd"
FAKE_IPSEC_VPN_SITE = {"peerIp": "192.168.1.1"}
FAKE_VCNSAPIEXC = {"status": "fail",
                   "head": "fake_head",
                   "response": "error"}
FAKE_NEW_CONNECTION = {"peer_cidrs": "192.168.1.0/24"}
FAKE_VPN_SERVICE = {"router_id": "aaaa-ccccc",
                    "id": "1111111-222222"}


class TestVpnaasDriver(base.BaseTestCase):

    def setUp(self):
        super(TestVpnaasDriver, self).setUp()
        self.context = context.get_admin_context()
        self.service_plugin = mock.Mock()
        self.validator = mock.Mock()
        self.plugin = vpnaas_driver.EdgeVPNDriver(self.service_plugin)

    @mock.patch('%s.validate_ipsec_conn' % VALI_PATH)
    @mock.patch('%s._convert_ipsec_conn' % DRIVER_PATH)
    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._generate_new_sites' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_status' % DRIVER_PATH)
    @mock.patch('%s._update_firewall_rules' % DRIVER_PATH)
    def test_create_ipsec_site_connection(self, mock_update_fw,
                                          mock_update_status,
                                          mock_update_ipsec, mock_gen_new,
                                          mock_get_id,
                                          mock_conv_ipsec,
                                          mock_val_conn):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_conv_ipsec.return_value = FAKE_IPSEC_VPN_SITE
        mock_gen_new.return_value = FAKE_IPSEC_VPN_SITE
        self.plugin.create_ipsec_site_connection(self.context,
                                                 FAKE_IPSEC_CONNECTION)
        mock_val_conn.assert_called_with(self.context,
                                         FAKE_IPSEC_CONNECTION)
        mock_conv_ipsec.assert_called_with(self.context,
                                           FAKE_IPSEC_CONNECTION)
        mock_get_id.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)
        mock_gen_new.assert_called_with(FAKE_EDGE_ID, FAKE_IPSEC_VPN_SITE)
        mock_update_ipsec.assert_called_with(FAKE_EDGE_ID,
                                             FAKE_IPSEC_VPN_SITE,
                                             enabled=True)
        mock_update_fw.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)
        mock_update_status.assert_called_with(self.context,
                                    FAKE_IPSEC_CONNECTION["vpnservice_id"],
                                    FAKE_IPSEC_CONNECTION["id"],
                                    "ACTIVE")

    @mock.patch('%s.validate_ipsec_conn' % VALI_PATH)
    @mock.patch('%s._convert_ipsec_conn' % DRIVER_PATH)
    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._generate_new_sites' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_status' % DRIVER_PATH)
    def test_create_ipsec_site_connection_fail(self,
                                               mock_update_status,
                                               mock_update_ipsec,
                                               mock_gen_new, mock_get_id,
                                               mock_conv_ipsec,
                                               mock_val_conn):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_conv_ipsec.return_value = FAKE_IPSEC_VPN_SITE
        mock_gen_new.return_value = FAKE_IPSEC_VPN_SITE
        mock_update_ipsec.side_effect = vcns_exc.VcnsApiException(
                                                        **FAKE_VCNSAPIEXC)
        self.assertRaises(vcns_exc.VcnsApiException,
                         self.plugin.create_ipsec_site_connection,
                         self.context, FAKE_IPSEC_CONNECTION)
        mock_val_conn.assert_called_with(self.context,
                                         FAKE_IPSEC_CONNECTION)
        mock_conv_ipsec.assert_called_with(self.context,
                                           FAKE_IPSEC_CONNECTION)
        mock_get_id.assert_called_with(self.context,
                                       FAKE_IPSEC_CONNECTION)
        mock_gen_new.assert_called_with(FAKE_EDGE_ID,
                                        FAKE_IPSEC_VPN_SITE)
        mock_update_ipsec.assert_called_with(FAKE_EDGE_ID,
                                             FAKE_IPSEC_VPN_SITE,
                                         enabled=True)
        mock_update_status.assert_called_with(self.context,
                                    FAKE_IPSEC_CONNECTION["vpnservice_id"],
                                    FAKE_IPSEC_CONNECTION["id"],
                                    "ERROR")

    @mock.patch('%s.validate_ipsec_conn' % VALI_PATH)
    @mock.patch('%s._convert_ipsec_conn' % DRIVER_PATH)
    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._generate_new_sites' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_status' % DRIVER_PATH)
    @mock.patch('%s._update_firewall_rules' % DRIVER_PATH)
    def test_update_fw_fail(self, mock_update_fw, mock_update_status,
                            mock_update_ipsec, mock_gen_new,
                            mock_get_id, mock_conv_ipsec, mock_val_conn):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_conv_ipsec.return_value = FAKE_IPSEC_VPN_SITE
        mock_gen_new.return_value = FAKE_IPSEC_VPN_SITE
        mock_update_fw.side_effect = vcns_exc.VcnsApiException(
                                                        **FAKE_VCNSAPIEXC)
        self.assertRaises(vcns_exc.VcnsApiException,
                         self.plugin.create_ipsec_site_connection,
                         self.context, FAKE_IPSEC_CONNECTION)
        mock_val_conn.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)
        mock_conv_ipsec.assert_called_with(self.context,
                                           FAKE_IPSEC_CONNECTION)
        mock_get_id.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)
        mock_gen_new.assert_called_with(FAKE_EDGE_ID, FAKE_IPSEC_VPN_SITE)
        mock_update_ipsec.assert_called_with(FAKE_EDGE_ID, FAKE_IPSEC_VPN_SITE,
                                         enabled=True)
        mock_update_fw.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)
        mock_update_status.assert_called_with(self.context,
                                    FAKE_IPSEC_CONNECTION["vpnservice_id"],
                                    FAKE_IPSEC_CONNECTION["id"],
                                          "ERROR")

    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._update_site_dict' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_firewall_rules' % DRIVER_PATH)
    def test_update_ipsec(self, mock_update_fw, mock_update_ipsec,
                          mock_update_sites, mock_get_id):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_update_sites.return_value = FAKE_IPSEC_VPN_SITE
        self.plugin.update_ipsec_site_connection(self.context,
                                                 FAKE_IPSEC_CONNECTION,
                                                 FAKE_NEW_CONNECTION)
        mock_update_sites.assert_called_with(self.context, FAKE_EDGE_ID,
                                             FAKE_IPSEC_CONNECTION,
                                             FAKE_NEW_CONNECTION)
        mock_update_ipsec.assert_called_with(FAKE_EDGE_ID,
                                             FAKE_IPSEC_VPN_SITE)
        mock_update_fw.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)

    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._update_site_dict' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_firewall_rules' % DRIVER_PATH)
    def test_update_ipsec_fail_with_notfound(self, mock_update_fw,
                                             mock_update_ipsec,
                                             mock_update_sites, mock_get_id):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_update_sites.return_value = {}
        self.assertRaises(nsxv_exc.NsxIPsecVpnMappingNotFound,
                          self.plugin.update_ipsec_site_connection,
                          self.context, FAKE_IPSEC_CONNECTION,
                          FAKE_NEW_CONNECTION)
        mock_update_sites.assert_called_with(self.context, FAKE_EDGE_ID,
                                             FAKE_IPSEC_CONNECTION,
                                             FAKE_NEW_CONNECTION)

    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._update_site_dict' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_firewall_rules' % DRIVER_PATH)
    def test_update_ipsec_fail_with_fw_fail(self, mock_update_fw,
                                            mock_update_ipsec,
                                            mock_update_sites, mock_get_id):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_update_fw.side_effect = vcns_exc.VcnsApiException(
                                                        **FAKE_VCNSAPIEXC)
        self.assertRaises(vcns_exc.VcnsApiException,
                          self.plugin.update_ipsec_site_connection,
                          self.context, FAKE_IPSEC_CONNECTION,
                          FAKE_NEW_CONNECTION)
        mock_update_sites.assert_called_with(self.context, FAKE_EDGE_ID,
                                             FAKE_IPSEC_CONNECTION,
                                             FAKE_NEW_CONNECTION)
        mock_update_fw.assert_called_with(self.context, FAKE_IPSEC_CONNECTION)

    @mock.patch('%s._get_router_edge_id' % DRIVER_PATH)
    @mock.patch('%s._update_site_dict' % DRIVER_PATH)
    @mock.patch('%s._update_ipsec_config' % DRIVER_PATH)
    @mock.patch('%s._update_status' % DRIVER_PATH)
    def test_update_ipsec_fail_with_site_fail(self, mock_update_status,
                                              mock_update_ipsec,
                                              mock_update_sites, mock_get_id):
        mock_get_id.return_value = (FAKE_ROUTER_ID, FAKE_EDGE_ID)
        mock_update_sites.return_value = FAKE_IPSEC_VPN_SITE
        mock_update_ipsec.side_effect = vcns_exc.VcnsApiException(
                                                            **FAKE_VCNSAPIEXC)
        self.assertRaises(vcns_exc.VcnsApiException,
                          self.plugin.update_ipsec_site_connection,
                          self.context, FAKE_IPSEC_CONNECTION,
                          FAKE_NEW_CONNECTION)
        mock_update_sites.assert_called_with(self.context, FAKE_EDGE_ID,
                                             FAKE_IPSEC_CONNECTION,
                                             FAKE_NEW_CONNECTION)
        mock_update_ipsec.assert_called_with(FAKE_EDGE_ID,
                                             FAKE_IPSEC_VPN_SITE)
        mock_update_status.assert_called_with(self.context,
                                    FAKE_IPSEC_CONNECTION["vpnservice_id"],
                                    FAKE_IPSEC_CONNECTION["id"],
                                    "ERROR")

    @mock.patch('%s._get_router' % DRIVER_PATH)
    def test_create_vpn_service(self, mock_get_router):
        mock_get_router.return_value = None
        self.service_plugin.delete_vpnservice = mock.Mock()
        self.assertRaises(n_exc.InvalidInput,
                          self.plugin.create_vpnservice,
                          self.context, FAKE_VPN_SERVICE)
        