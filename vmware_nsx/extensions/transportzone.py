# Copyright 2016 VMware, Inc.  All rights reserved.
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

from neutron.api import extensions


TRANSPORT_ZONE = 'transport_zone'
EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        TRANSPORT_ZONE: {'allow_post': True, 'allow_put': False,
                         'is_visible': True},
    }
}


class Transportzone(extensions.ExtensionDescriptor):
    """Extension class supporting multiple transport zones."""

    @classmethod
    def get_name(cls):
        return "Transport Zone"

    @classmethod
    def get_alias(cls):
        return "transport-zone"

    @classmethod
    def get_description(cls):
        return "Multiple transport zone support for network."

    @classmethod
    def get_updated(cls):
        return "2016-02-03T10:00:00-00:00"

    def get_required_extensions(self):
        return ["network"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        return {}
