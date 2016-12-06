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

from neutron_lib.api import converters
from neutron_lib.api import extensions


VRF_ID = 'vrf:id'
NO_VRF = 'novrf'

EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        VRF_ID: {
            'allow_post': False,
            'allow_put': True,
            'is_visible': True,
            'default': None,
            'validate': {'type:uuid': None}
        },
        NO_VRF: {
            'allow_post': False,
            'allow_put': True,
            'is_visible': True,
            'default': None,
            'convert_to': converters.convert_to_boolean
        }
    }
}


class Vrf(extensions.ExtensionDescriptor):
    """Extension class supporting VRF for routers."""

    @classmethod
    def get_name(cls):
        return "VRF"

    @classmethod
    def get_alias(cls):
        return "vrf"

    @classmethod
    def get_description(cls):
        return "Enables VRF configuration for routers"

    @classmethod
    def get_updated(cls):
        return "2016-12-0122T10:00:00-00:00"

    def get_required_extensions(self):
        return ["router"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        return {}
