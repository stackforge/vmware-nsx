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

from neutron.api import extensions
from neutron.extensions import l3


VRF_ID = 'vrf_id'

EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        l3.EXTERNAL_GW_INFO: {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            'default': None,
            'enforce_policy': True,
            'validate': {
                'type:dict_or_nodata': {
                    'network_id': {'type:uuid': None, 'required': True},
                    'enable_snat': {
                        'type:boolean': None,
                        'required': False,
                        'convert_to': converters.convert_to_boolean
                    },
                    'external_fixed_ips': {
                        'type:fixed_ips': None,
                        'default': None,
                        'required': False,
                        'convert_list_to': converters.convert_kvp_list_to_dict
                    },
                    VRF_ID: {
                        'type:uuid': None,
                        'default': None,
                        'required': False
                    }
                }
            }
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
        return "Enable VRF configuration for routers"

    @classmethod
    def get_updated(cls):
        return "2016-11-07T10:00:00-00:00"

    def get_required_extensions(self):
        return ["ext-gw-mode"]

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(EXTENDED_ATTRIBUTES_2_0.items())
        return {}
