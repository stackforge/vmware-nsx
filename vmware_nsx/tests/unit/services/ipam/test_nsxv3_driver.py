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

from oslo_config import cfg
from oslo_utils import uuidutils

from vmware_nsx.tests.unit.nsx_v3 import test_plugin


class MockIPPools(object):

    def patch_nsxlib_ipam(self):
        self.nsx_pool = None

        def _create_pool(*args, **kwargs):
            subnet = {"allocation_ranges": kwargs.get('ranges'),
                      "gateway_ip": str(kwargs.get('gateway_ip')),
                      "cidr": args[0]}
            pool = {'id': uuidutils.generate_uuid(),
                    'subnets': [subnet]}
            self.nsx_pool = pool
            return {'id': pool['id']}

        def _delete_pool(*args, **kwargs):
            self.nsx_pool = None

        def _get_pool(*args, **kwargs):
            return self.nsx_pool

        mock.patch(
            "vmware_nsxlib.v3.resources.IpPool.get",
            side_effect=_get_pool).start()
        mock.patch(
            "vmware_nsxlib.v3.resources.IpPool.create",
            side_effect=_create_pool).start()
        mock.patch(
            "vmware_nsxlib.v3.resources.IpPool.delete",
            side_effect=_delete_pool).start()


class TestNsxv3IpamSubnets(test_plugin.TestSubnetsV2, MockIPPools):
    """Run the nsxv3 plugin subnets tests with the ipam driver."""
    def setUp(self):
        cfg.CONF.set_override(
            "ipam_driver",
            "vmware_nsx.services.ipam.nsx_v3.driver.Nsxv3IpamDriver")
        super(TestNsxv3IpamSubnets, self).setUp()
        self.patch_nsxlib_ipam()

    def test_update_subnet_from_gw_to_new_gw(self):
        self.skipTest('not supported')

    def test_update_subnet_gw_outside_cidr_returns_200(self):
        self.skipTest('not supported')

    def test_update_subnet_from_gw_to_no_gw(self):
        self.skipTest('not supported')

    def test_update_subnet_allocation_pools(self):
        self.skipTest('not supported')

    def test_update_subnet_allocation_pools_and_gateway_ip(self):
        self.skipTest('not supported')


class TestNsxv3IpamPorts(test_plugin.TestPortsV2, MockIPPools):
    """Run the nsxv3 plugin ports tests with the ipam driver."""
    def setUp(self):
        cfg.CONF.set_override(
            "ipam_driver",
            "vmware_nsx.services.ipam.nsx_v3.driver.Nsxv3IpamDriver")
        super(TestNsxv3IpamPorts, self).setUp()
        self.patch_nsxlib_ipam()
