# Copyright 2016 VMware, Inc.
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

from vmware_nsx._i18n import _
from vmware_nsx.common import availability_zones as common_az
from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc


class NsxV3AvailabilityZone(common_az.ConfiguredAvailabilityZone):

    def init_from_config_line(self, config_line):
        # Not supported for nsx_v3 (old configuration)
        raise nsx_exc.NsxInvalidConfiguration(
            opt_name="availability_zones",
            opt_value=config_line,
            reason=_("Expected 4 or 5 values per zone"))

    def init_from_config_section(self, az_name):
        az_info = config.get_nsxv3_az_opts(self.name)

        # The optional parameters will get the global values if not
        # defined for this AZ
        self.metadata_proxy = az_info.get('metadata_proxy')
        if self.metadata_proxy is None:
            self.metadata_proxy = (
                cfg.CONF.nsx_v3.metadata_proxy)

        self.dhcp_profile = az_info.get('dhcp_profile')
        if self.dhcp_profile is None:
            self.dhcp_profile = (
                cfg.CONF.nsx_v3.dhcp_profile)

    def init_default_az(self):
        # use the default configuration
        self.metadata_proxy = cfg.CONF.nsx_v3.metadata_proxy
        self.dhcp_profile = cfg.CONF.nsx_v3.dhcp_profile


class NsxV3AvailabilityZones(common_az.ConfiguredAvailabilityZones):

    def __init__(self):
        return super(NsxV3AvailabilityZones, self).__init__(
            cfg.CONF.nsx_v3.availability_zones,
            NsxV3AvailabilityZone)

    def get_resources(self):
        """Return a list of all the resources in all the availability zones
        """
        resources = []
        # DEBUG ADIT not yet. do we need it?
        return resources
