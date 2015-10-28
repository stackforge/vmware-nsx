# Copyright 2015 VMware, Inc.  All rights reserved.
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


import logging

from admin.plugins.common import constants
from admin.plugins.common.utils import output_header
import admin.plugins.nsxv.resources.utils as utils
from admin.shell import Operations

from neutron.callbacks import registry

from vmware_nsx.db import nsxv_db

LOG = logging.getLogger(__name__)


def get_dhcp_bindings_per_edge():
    neutron_db = utils.NeutronDbClient()
    return nsxv_db.get_nsxv_dhcp_bindings_count_per_edge(
        neutron_db.context.session)


@output_header
def neutron_list_dhcp_bindings(resource, event, trigger, **kwargs):
    """List # of dhcp bindings per NSXv Edge"""
    bindings = get_dhcp_bindings_per_edge()
    LOG.info(bindings)


registry.subscribe(neutron_list_dhcp_bindings,
                   constants.DHCP,
                   Operations.LIST.value)
