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

from admin.shell import Operations
from admin.shell import Resources
from admin.plugins.common import constants
from admin.plugins.common import formatters
from admin.plugins.common.utils import output_header
import admin.plugins.nsxv.resources.utils as utils

from neutron.callbacks import registry

from vmware_nsx.db import nsxv_db

LOG = logging.getLogger(__name__)


def get_spoofguard_policies():
    nsxv = utils.get_nsxv_client()
    return nsxv.get_spoofguard_policies()[1].get("policies")


@output_header
def nsx_list_spoofguard_policies(resource, event, trigger, **kwargs):
    """List spoofguard policies from NSXv backend"""
    policies = get_spoofguard_policies()
    LOG.info(formatters.output_formatter(
                 constants.SPOOFGUARD_POLICIES, policies,
                 ['policyId', 'name']))


def get_spoofguard_policy_network_mappings():
    spgapi = utils.NeutronDbClient()
    return nsxv_db.get_nsxv_spoofguard_policy_network_mappings(
        spgapi.context)


@output_header
def neutron_list_spoofguard_policy_mappings(resource, event, trigger,
                                            **kwargs):
    mappings = get_spoofguard_policy_network_mappings()
    LOG.info(formatters.output_formatter(
                 constants.SPOOFGUARD_POLICIES, mappings,
                 ['network_id', 'policy_id']))



registry.subscribe(nsx_list_spoofguard_policies,
                   Resources.SPOOFGUARD_POLICIES.value,
                   Operations.LIST.value)
registry.subscribe(neutron_list_spoofguard_policy_mappings,
                   Resources.SPOOFGUARD_POLICIES.value,
                   Operations.LIST.value)
