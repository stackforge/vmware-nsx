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
from neutron.api.v2 import attributes
from neutron.extensions import securitygroup
from neutron_lib import constants

STRICT = 'strict'
STRICT_SECURITY_GROUPS = 'strict_security_groups'

RESOURCE_ATTRIBUTE_MAP = {
    'security_groups': {
        STRICT: {
            'allow_post': True,
            'allow_put': False,
            'convert_to': attributes.convert_to_boolean,
            'default': False,
            'enforce_policy': True,
            'is_visible': True}
    }
}


EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {STRICT_SECURITY_GROUPS: {
        'allow_post': True,
        'allow_put': True,
        'is_visible': True,
        'convert_to': securitygroup.convert_to_uuid_list_or_none,
        'default': constants.ATTR_NOT_SPECIFIED}
    }
}


NUM_STRICT_SGS_ON_PORT = 1
# TODO(roeyc): Define exceptions

class Strictsecuritygroup(extensions.ExtensionDescriptor):
    """Strict security-group extension."""

    @classmethod
    def get_name(cls):
        return "Strict security group"

    @classmethod
    def get_alias(cls):
        return "strict-security-group"

    @classmethod
    def get_description(cls):
        return "Admin controlled security groups with blocking rules."

    @classmethod
    def get_updated(cls):
        return "2016-07-13T10:00:00-00:00"

    def get_required_extensions(self):
        return ["security-group"]

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        return []

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
