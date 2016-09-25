# Copyright 2014 VMware, Inc.
#
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
#

from neutron.api import extensions
from neutron.api.v2 import base
from neutron import manager


EXT_ALIAS = 'nsxv_plugin'
COLLECTION_NAME = "%ss" % EXT_ALIAS

RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
    },
}


class Nsxv_plugin(extensions.ExtensionDescriptor):
    """Dummy extension for openstackclient plugin to know which plugin is used

    """
    @classmethod
    def get_name(cls):
        return "NSX-V Plugin"

    @classmethod
    def get_alias(cls):
        return EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "NSX-V Plugin."

    @classmethod
    def get_updated(cls):
        return "2016-10-05T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        resource_name = EXT_ALIAS
        collection_name = resource_name.replace('_', '-') + "s"
        params = RESOURCE_ATTRIBUTE_MAP.get(COLLECTION_NAME, dict())
        controller = base.create_resource(collection_name,
                                          resource_name,
                                          plugin, params, allow_bulk=False)
        ex = extensions.ResourceExtension(collection_name, controller)
        exts.append(ex)
        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
