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

import abc

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc

DEFAULT_NAME = 'default'


class ConfiguredAvailabilityZone(object):

    def __init__(self, config_line):
        self.name = ""
        if config_line and ':' in config_line:
            # Older configuration - each line contains all the relevant
            # values for one availability zones, separated by ':'
            values = config_line.split(':')
            self.name = values[0]
            self._validate_zone_name(config_line)
            self.init_from_config_line(config_line)
        elif config_line:
            # Newer configuration - the name of the availability zone can be
            # used to get the rest of the configuration for this AZ
            self.name = config_line
            self._validate_zone_name(config_line)
            self.init_from_config_section(self.name)
        else:
            # Default zone configuration
            self.name = DEFAULT_NAME
            self.init_default_az()

    def is_default(self):
        return self.name == DEFAULT_NAME

    def _validate_zone_name(self, config_line):
        if len(self.name) > 36:
            raise nsx_exc.NsxInvalidConfiguration(
                opt_name="availability_zones",
                opt_value=config_line,
                reason=_("Maximum name length is 36"))

    @abc.abstractmethod
    def init_from_config_line(self, config_values):
        pass

    @abc.abstractmethod
    def init_from_config_section(self, az_name):
        pass

    @abc.abstractmethod
    def init_default_az(self):
        pass


class ConfiguredAvailabilityZones(object):

    def __init__(self, az_conf, az_class):
        self.availability_zones = {}

        # Add the configured availability zones
        for az in az_conf:
            obj = az_class(az)
            self.availability_zones[obj.name] = obj

        # add a default entry
        obj = az_class(None)
        self.availability_zones[obj.name] = obj

    @abc.abstractmethod
    def get_resources(self):
        """Return a list of all the resources in all the availability zones
        """
        pass

    def get_availability_zone(self, name):
        """Return an availability zone object by its name
        """
        if name in self.availability_zones.keys():
            return self.availability_zones[name]
        return self.get_default_availability_zone()

    def get_default_availability_zone(self):
        """Return the default availability zone object
        """
        return self.availability_zones[DEFAULT_NAME]

    def list_availability_zones(self):
        """Return a list of availability zones names
        """
        return self.availability_zones.keys()
