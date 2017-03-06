# Copyright 2017 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from neutron.tests import base

from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.nsx_v3 import availability_zones as nsx_az


class Nsxv3AvailabilityZonesTestCase(base.BaseTestCase):

    def setUp(self):
        super(Nsxv3AvailabilityZonesTestCase, self).setUp()
        self.az_name = 'zone1'
        self.group_name = 'az:%s' % self.az_name
        config.register_nsxv3_azs(cfg.CONF, [self.az_name])
        self.global_md_proxy = uuidutils.generate_uuid()
        cfg.CONF.set_override(
            "metadata_proxy", self.global_md_proxy, group="nsx_v3")
        self.global_dhcp_profile = uuidutils.generate_uuid()
        cfg.CONF.set_override(
            "dhcp_profile", self.global_dhcp_profile, group="nsx_v3")
        cfg.CONF.set_override(
            "native_metadata_route", "1.1.1.1", group="nsx_v3")
        cfg.CONF.set_override("dns_domain", "xxx", group="nsx_v3")
        cfg.CONF.set_override("nameservers", ["yyy"], group="nsx_v3")

    def _config_az(self,
                   metadata_proxy="metadata_proxy1",
                   dhcp_profile="dhcp_profile1",
                   native_metadata_route="2.2.2.2",
                   dns_domain='aaaa',
                   nameservers=['bbbb']):
        if metadata_proxy is not None:
            cfg.CONF.set_override("metadata_proxy", metadata_proxy,
                                  group=self.group_name)
        if dhcp_profile is not None:
            cfg.CONF.set_override("dhcp_profile", dhcp_profile,
                                  group=self.group_name)
        if native_metadata_route is not None:
            cfg.CONF.set_override("native_metadata_route",
                                  native_metadata_route,
                                  group=self.group_name)
        if dns_domain is not None:
            cfg.CONF.set_override("dns_domain", dns_domain,
                                  group=self.group_name)
        if nameservers is not None:
            cfg.CONF.set_override("nameservers", nameservers,
                                  group=self.group_name)

    def test_simple_availability_zone(self):
        self._config_az()
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual(self.az_name, az.name)
        self.assertEqual("metadata_proxy1", az.metadata_proxy)
        self.assertEqual("dhcp_profile1", az.dhcp_profile)
        self.assertEqual("2.2.2.2", az.native_metadata_route)
        self.assertEqual("aaaa", az.dns_domain)
        self.assertEqual(["bbbb"], az.nameservers)

    def test_missing_group_section(self):
        self.assertRaises(
            nsx_exc.NsxInvalidConfiguration,
            nsx_az.NsxV3AvailabilityZone,
            "doesnt_exist")

    def test_availability_zone_missing_metadata_proxy(self):
        self._config_az(metadata_proxy=None)
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual(self.global_md_proxy, az.metadata_proxy)
        self.assertEqual("dhcp_profile1", az.dhcp_profile)

    def test_availability_zone_missing_dhcp_profile(self):
        self._config_az(dhcp_profile=None)
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual("metadata_proxy1", az.metadata_proxy)
        self.assertEqual(self.global_dhcp_profile, az.dhcp_profile)

    def test_availability_zone_missing_md_route(self):
        self._config_az(native_metadata_route=None)
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual("1.1.1.1", az.native_metadata_route)

    def test_availability_zone_missing_dns_domain(self):
        self._config_az(dns_domain=None)
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual("xxx", az.dns_domain)

    def test_availability_zone_missing_nameservers(self):
        self._config_az(nameservers=None)
        az = nsx_az.NsxV3AvailabilityZone(self.az_name)
        self.assertEqual(["yyy"], az.nameservers)
