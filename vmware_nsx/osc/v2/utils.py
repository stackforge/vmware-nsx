# Copyright 2016 VMware, Inc.
# All rights reserved.
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
from osc_lib import utils as osc_utils


def get_extensions(client_manager):
    """Return a list of all current extensions aliases"""
    data = client_manager.network.extensions()
    extensions = []
    for s in data:
        prop = osc_utils.get_item_properties(
            s, ('Alias',), formatters={})
        extensions.append(prop[0])
    return extensions


def is_nsx_v(client_manager):
    # If the extensions list contains the dummy V plugin extension
    # we know it is nsx-v
    extensions = get_extensions(client_manager)
    if 'nsxv_plugin' in extensions:
        return True
    return False


def is_nsx_v3(client_manager):
    # If the extensions list contains the dummy V3 plugin extension
    # we know it is nsx-v3
    extensions = get_extensions(client_manager)
    if 'nsxv3_plugin' in extensions:
        return True
    return False
