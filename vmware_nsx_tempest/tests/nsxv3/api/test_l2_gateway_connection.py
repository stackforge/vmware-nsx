# Copyright 2015 OpenStack Foundation
# Copyright 2015 VMware Inc
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

from oslo_serialization import jsonutils

from pprint import pformat
from pprint import pprint as pp

import netaddr

from tempest.api.network import base
from tempest import config
from tempest import test

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest._i18n import _LW
from vmware_nsx_tempest.common import constants
from vmware_nsx_tempest.services import l2_gateway_client
from vmware_nsx_tempest.services import nsxv3_client
import test_l2_gateway

from vmware_nsx_tempest.services import base_l2gw
from vmware_nsx_tempest.services import l2_gateway_connection_client
from vmware_nsx_tempest.tests.nsxv3.api import test_l2_gateway

import yaml

CONF = config.CONF
L2GW_RID = 'l2_gateway'
L2GW_RIDs = 'l2_gateways'
L2GWC_RID = 'l2_gateway_connection'
L2GWC_RIDs = 'l2_gateway_connections'
MSG_DIFF = "l2gw %s=%s is not the same as requested=%s"

LOG = constants.log.getLogger(__name__)

CONF = config.CONF


class L2GatewayConnectionTest(test_l2_gateway.L2GatewayTest):
    """Test l2-gateway-connection operations:

        l2-gateway-connection-create
        l2-gateway-connection-show
        l2-gateway-connection-update (no case)
        l2-gateway-connection-list
        l2-gateway-connection-delete

       over single device/interface/vlan
       over single device/interface/multiple-vlans
       over single device/multiple-interfaces/multiple-vlans
       over multiple-device/multiple-interfaces/multiple-vlans
    """

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(L2GatewayConnectionTest, cls).skip_checks()
        if not test.is_extension_enabled("l2-gateway", "network"):
            raise cls.skipException("l2-gateway extension not enabled.")

    @classmethod
    def setup_clients(cls):
        super(L2GatewayConnectionTest, cls).setup_clients()
        cls.l2gwc_created = {}
        try:
            manager = getattr(cls.os_adm, "manager", cls.os_adm)
            net_client = getattr(manager, "networks_client")
            _params = manager.default_params_withy_timeout_values.copy()
        except AttributeError as attribute_err:
            LOG.warning(
                _LW("Failed to locate the attribute, Error: %(err_msg)s") %
                {"err_msg": attribute_err.__str__()})
            _params = {}
        cls.l2gwc_client = \
            l2_gateway_connection_client.L2GatewayConnectionClient(
                net_client.auth_provider,
                net_client.service,
                net_client.region,
                net_client.endpoint_type,
                **_params)

    @classmethod
    def resource_setup(cls):
        super(L2GatewayConnectionTest, cls).resource_setup()
        # Create a network.
        cls.network = cls.create_network()
        # Create subnet on the network just created.
        cls.SUBNET_1_NETWORK_CIDR = getattr(CONF.l2gw, "subnet_1_network",
                                            None)
        cls.SUBNET_1_START = getattr(CONF.l2gw, "subnet_1_start", None)
        cls.SUBNET_1_END = getattr(CONF.l2gw, "subnet_1_end", None)
        cls.SUBNET_1_IP_V = getattr(CONF.l2gw, "subnet_1_ip_version", None)
        cls.SUBNET_1_MASK = getattr(CONF.l2gw, "subnet_1_mask", None)
        subnet_info = {}
        # cidr must be presented & in IPNetwork structure.
        cls.CIDR = netaddr.IPNetwork(cls.SUBNET_1_NETWORK_CIDR)
        subnet_info["allocation_pools"] = [{"start": cls.SUBNET_1_START,
                                            "end": cls.SUBNET_1_END}]
        cls.subnet = cls.create_subnet(cls.network, cidr=cls.CIDR,
                                       mask_bits=int(cls.SUBNET_1_MASK),
                                       ip_version=cls.SUBNET_1_IP_V,
                                       **subnet_info)

    @classmethod
    def resource_cleanup(cls):
        cls.l2gw_cleanup()
        cls._try_delete_resource(cls.networks_client.delete_network,
                                 cls.network["id"])

    @classmethod
    def l2gw_cleanup(cls):
        for l2gwc_id in cls.l2gwc_created.keys():
            cls.l2gwc_client.delete_l2_gateway_connection(l2gwc_id)
            cls.l2gwc_created.pop(l2gwc_id)
        for l2gw_id in cls.l2gw_created.keys():
            cls.l2gw_client.delete_l2_gateway(l2gw_id)
            cls.l2gw_created.pop(l2gw_id)

    def create_l2gw_switch(self, _name, _devices):
        _vlan_id_list = self.get_segmentation_id(_devices)
        _res_new = self.l2gw_client.create_l2_gateway(
            name=_name, **_devices)[L2GW_RID]
        self.l2gw_created[_res_new['id']] = _res_new
        _res_show = self.l2gw_client.show_l2_gateway(
            _res_new['id'])[L2GW_RID]
        return (_res_show, _vlan_id_list)

    def create_l2gw_connection(self, _l2gw, network_id=None, **kwargs):
        network_id = network_id or self.network['id']
        _seg_id = kwargs.pop('default_segmentation_id',
                             kwargs.pop('segmentation_id', None))
        cr_body = {'l2_gateway_id': _l2gw['id'], 'network_id': network_id}
        if _seg_id:
            cr_body['segmentation_id'] = _seg_id
        _res_new = self.l2gwc_client.create_l2_gateway_connection(
            **cr_body)[L2GWC_RID]
        self.l2gwc_created[_res_new['id']] = _res_new
        _res_show = self.l2gwc_client.show_l2_gateway_connection(
            _res_new['id'])[L2GWC_RID]
        return (_res_show, _seg_id)

    def create_l2gwc(self, l2gwc_param):
        """
        Creates L2GWC and return the response.

        :param l2gwc_param: L2GWC parameters.

        :return: response of L2GWC create API.
        """
        LOG.info(_LI("l2gwc param: %(param)s ") % {"param": l2gwc_param})
        l2gwc_request_body = {"l2_gateway_id": l2gwc_param["l2_gateway_id"],
                              "network_id": l2gwc_param["network_id"]}
        if "segmentation_id" in l2gwc_param:
            l2gwc_request_body["segmentation_id"] = l2gwc_param[
                "segmentation_id"]
        LOG.info(_LI("l2gwc_request_body: %s") % l2gwc_request_body)
        rsp = self.l2gwc_client.create_l2_gateway_connection(
            **l2gwc_request_body)
        LOG.info(_LI("l2gwc response: %s") % rsp)
        self.l2gwc_created[rsp[constants.L2GWC]["id"]] = rsp[constants.L2GWC]
        return rsp

    def delete_l2gwc(self, l2gwc_id):
        """
        Delete L2GWC and returns the response.

        :param l2gwc_id: L2GWC id to delete L2GWC.

        :return: response of the l2gwc delete API.
        """
        LOG.info(_LI("L2GW id: %(id)s") % {"id": l2gwc_id})
        rsp = self.l2gwc_client.delete_l2_gateway_connection(l2gwc_id)
        LOG.info(_LI("response : %(rsp)s") % {"rsp": rsp})
        return rsp

    @test.attr(type="nsxv3")
    @decorators.skip_because(bug="634513")
    @test.idempotent_id('81edfb9e-4722-4565-939c-6593b8405ff4')
    def test_l2_gateway_connection_create(self):
        """
        Create l2 gateway connection using one vlan.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1]}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"]}
        l2gwc_rsp = self.create_l2gwc(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertEqual(l2gwc_param["l2_gateway_id"],
                         l2gwc_rsp[constants.L2GWC]["l2_gateway_id"],
                         "l2gw id is not same as expected in "
                         "create l2gw connection response")
        self.assertEqual(l2gwc_param["network_id"],
                         l2gwc_rsp[constants.L2GWC]["network_id"],
                         "network id is not same as expected in "
                         "create l2gw connection response")
        self.l2gw_cleanup()

    @test.attr(type="nsxv3")
    @decorators.skip_because(bug="634513")
    @test.idempotent_id('7db4f6c9-18c5-4a99-93c1-68bc2ecb48a7')
    def test_l2_gateway_connection_create_with_multiple_vlans(self):
        """
        Create l2 gateway connection using multiple vlans.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name,
                    "vlans": [self.VLAN_1, self.VLAN_2]}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"]}
        l2gwc_rsp = self.create_l2gwc(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertEqual(l2gwc_param["l2_gateway_id"],
                         l2gwc_rsp[constants.L2GWC]["l2_gateway_id"],
                         "l2gw id is not same as expected in "
                         "create l2gw connection response")
        self.assertEqual(l2gwc_param["network_id"],
                         l2gwc_rsp[constants.L2GWC]["network_id"],
                         "network id is not same as expected in "
                         "create l2gw connection response")
        self.l2gw_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id('de70d6a2-d454-4a09-b06b-8f39be67b635')
    def test_l2_gateway_connection_with_seg_id_create(self):
        """
        Create l2 gateway connection using one vlan.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gwc(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        self.assertEqual(l2gwc_param["l2_gateway_id"],
                         l2gwc_rsp[constants.L2GWC]["l2_gateway_id"],
                         "l2gw id is not same as expected in "
                         "create l2gw connection response")
        self.assertEqual(l2gwc_param["network_id"],
                         l2gwc_rsp[constants.L2GWC]["network_id"],
                         "network id is not same as expected in "
                         "create l2gw connection response")
        self.assertEqual(l2gwc_param["segmentation_id"],
                         l2gwc_rsp[constants.L2GWC]["segmentation_id"],
                         "segmentation id is not same as expected in "
                         "create l2gw connection response")
        self.l2gw_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id('819d9b50-9159-48d0-be2a-493ec686534c')
    def test_l2_gateway_connection_show(self):
        """
        Create l2 gateway connection using one vlan and tes l2 gateway
        connection show api
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gwc(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        l2gwc_id = l2gwc_rsp[constants.L2GWC]["id"]
        show_rsp = self.l2gwc_client.show_l2_gateway_connection(l2gwc_id)
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         show_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_200})
        self.assertEqual(l2gwc_param["l2_gateway_id"],
                         show_rsp[constants.L2GWC]["l2_gateway_id"],
                         "l2gw id is not same as expected in "
                         "show l2gw connection response")
        self.assertEqual(l2gwc_param["network_id"],
                         show_rsp[constants.L2GWC]["network_id"],
                         "network id is not same as expected in "
                         "show l2gw connection response")
        show_rsp_seg_id = str(yaml.safe_load(
            jsonutils.dumps(show_rsp[constants.L2GWC][
                                "segmentation_id"])))
        self.assertEqual(l2gwc_param["segmentation_id"],
                         show_rsp_seg_id,
                         "segmentation id is not same as expected in "
                         "show l2gw connection response")
        self.l2gw_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id('4188f8e7-cd65-427e-92b8-2a9e0492ab21')
    def test_l2_gateway_connection_list(self):
        """
        Create l2 gateway connection using one vlan and test l2 gateway
        connection list api.

        Create 2 l2 gateway connections and test l2gwc list api.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        # Create 2 l2 gateways.
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        # Create 2 l2 gateway connections.
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gwc(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        list_rsp = self.l2gwc_client.list_l2_gateway_connections()
        LOG.info(_LI("l2gw connection list response: %s") % list_rsp)
        # Assert in case of failure.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         list_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_200})
        list_response = yaml.safe_load(
            jsonutils.dumps(list_rsp["l2_gateway_connections"][0]))
        l2gwc_response = yaml.safe_load(
            jsonutils.dumps(l2gwc_rsp["l2_gateway_connection"]))
        self.assertEqual(l2gwc_rsp["l2_gateway_connection"]["id"],
                         list_rsp["l2_gateway_connections"][0]["id"],
                         "l2gw connection list does not show proper id")
        self.assertEqual(l2gwc_rsp["l2_gateway_connection"]["l2_gateway_id"],
                         list_rsp["l2_gateway_connections"][0][
                             "l2_gateway_id"],
                         "l2gw connection list does not show proper "
                         "l2_gateway_id")
        self.assertEqual(l2gwc_rsp["l2_gateway_connection"]["network_id"],
                         list_rsp["l2_gateway_connections"][0]["network_id"],
                         "l2gw connection list does not show proper "
                         "network_id")
        self.assertEqual(l2gwc_rsp["l2_gateway_connection"]["tenant_id"],
                         list_rsp["l2_gateway_connections"][0]["tenant_id"],
                         "l2gw connection list does not show proper tenant_id")
        self.assertEqual(l2gwc_rsp["l2_gateway_connection"]["segmentation_id"],
                         str(list_rsp["l2_gateway_connections"][0][
                                 "segmentation_id"]),
                         "l2gw connection list does not show proper "
                         "segmentation_id")
        self.l2gw_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id('4d71111f-3d2b-4557-97c7-2e149a6f41fb')
    def test_l2_gateway_connection_recreate(self):
        """
        Recreate l2 gateway connection.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        # List all the L2GW connection.
        list_rsp = self.l2gwc_client.list_l2_gateway_connections()
        LOG.info(_LI("l2gw connection list response: %s") % list_rsp)
        # Assert in case of failure.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         list_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_200})
        list_rsp = list_rsp["l2_gateway_connections"]
        l2gwc_ids = [item.get("id") for item in list_rsp if item.has_key("id")]
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gwc(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        l2gwc_id = l2gwc_rsp[constants.L2GWC]["id"]
        # Delete l2gw.
        rsp = self.delete_l2gwc(l2gwc_id)
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_204,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_204})
        # Since we delete l2gwc pop that id from list.
        self.l2gwc_created.pop(l2gwc_id)
        l2gwc_rsp = self.create_l2gwc(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        # List all the L2GW connection.
        list_rsp = self.l2gwc_client.list_l2_gateway_connections()
        LOG.info(_LI("l2gw connection list response: %s") % list_rsp)
        # Assert in case of failure.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_200,
                         list_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_200})
        list_rsp = list_rsp["l2_gateway_connections"]
        l2gwc_ids = l2gwc_ids + [item.get("id") for item in list_rsp if \
                item.has_key("id")]
        self.assertNotIn(l2gwc_id, l2gwc_ids, "l2gwc list api shows hanging "
                                              "l2gwc id")
        self.l2gw_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id("670cacb5-134e-467d-ba41-0d7cdbcf3903")
    def test_l2_gateway_connection_delete(self):
        """
        Delete l2gw will create l2gw and delete recently created l2gw. To
        delete l2gw we need l2gw id.
        """
        LOG.info(_LI("Testing l2_gateway_connection_delete api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gwc(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        l2gwc_id = l2gwc_rsp[constants.L2GWC]["id"]
        # Delete l2gw.
        rsp = self.delete_l2gwc(l2gwc_id)
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_204,
                         rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_204})
        # Since we delete l2gwc pop that id from list.
        self.l2gwc_created.pop(l2gwc_id)
        self.l2gw_cleanup()

    @test.attr(type="nsxv3")
    @test.idempotent_id('de70d6a2-d454-4a09-b06b-8f39be67b635')
    def test_l2_gateway_connection_active_port_delete(self):
        """
        Create l2 gateway connection using one vlan.
        """
        LOG.info(_LI("Testing test_l2_gateway_connection_create api"))
        device_name, interface_name = self.nsx_bridge_cluster_info()
        l2gw_name = data_utils.rand_name(constants.L2GW)
        device_1 = {"dname": device_name, "iname": interface_name}
        l2gw_param = [device_1]
        l2gw_rsp, _ = self.create_l2gw(l2gw_name, l2gw_param)
        l2gwc_param = {"l2_gateway_id": l2gw_rsp[constants.L2GW]["id"],
                       "network_id": self.network["id"],
                       "segmentation_id": self.VLAN_1}
        l2gwc_rsp = self.create_l2gwc(l2gwc_param)
        # Assert if create fails.
        self.assertEqual(constants.EXPECTED_HTTP_RESPONSE_201,
                         l2gwc_rsp.response["status"],
                         "Response code is not %(code)s" % {
                             "code": constants.EXPECTED_HTTP_RESPONSE_201})
        l2gw_id = l2gw_rsp[constants.L2GW]["id"]
        # Delete l2gw.
        try:
            self.delete_l2gw(l2gw_id)
        except Conflict:
            pp("pass")
        self.l2gw_cleanup()
