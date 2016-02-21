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


from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters

import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
import vmware_nsx.shell.admin.plugins.nsxv.resources.utils as utils
import vmware_nsx.shell.nsxadmin as shell

from neutron.callbacks import registry
from neutron_lib import exceptions

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.db import nsxv_db

LOG = logging.getLogger(__name__)
nsxv = utils.get_nsxv_client()


def get_spoofguard_policies():
    nsxv = utils.get_nsxv_client()
    return nsxv.get_spoofguard_policies()[1].get("policies")


@admin_utils.output_header
def nsx_list_spoofguard_policies(resource, event, trigger, **kwargs):
    """List spoofguard policies from NSXv backend"""
    policies = get_spoofguard_policies()
    LOG.info(formatters.output_formatter(constants.SPOOFGUARD_POLICY, policies,
                                         ['policyId', 'name']))


def get_spoofguard_policy_network_mappings():
    spgapi = utils.NeutronDbClient()
    return nsxv_db.get_nsxv_spoofguard_policy_network_mappings(
        spgapi.context)


@admin_utils.output_header
def neutron_list_spoofguard_policy_mappings(resource, event, trigger,
                                            **kwargs):
    mappings = get_spoofguard_policy_network_mappings()
    LOG.info(formatters.output_formatter(constants.SPOOFGUARD_POLICY, mappings,
                                         ['network_id', 'policy_id']))


def get_missing_spoofguard_policy_mappings(reverse=None):
    nsxv_spoofguard_policies = set()
    for spg in get_spoofguard_policies():
        nsxv_spoofguard_policies.add(spg.get('policyId'))

    neutron_spoofguard_policy_mappings = set()
    for binding in get_spoofguard_policy_network_mappings():
        neutron_spoofguard_policy_mappings.add(binding.policy_id)

    if reverse:
        return nsxv_spoofguard_policies - neutron_spoofguard_policy_mappings
    else:
        return neutron_spoofguard_policy_mappings - nsxv_spoofguard_policies


@admin_utils.output_header
def nsx_list_missing_spoofguard_policies(resource, event, trigger,
                                         **kwargs):
    """List missing spoofguard policies on NSXv.

    Spoofguard policies that have a binding in Neutron Db but there is
    no policy on NSXv backend to back it.
    """
    props = kwargs.get('property')
    reverse = True if props and props[0] == 'reverse' else False
    if reverse:
        LOG.info(_LI("Spoofguard policies on NSXv but not present in "
                     "Neutron Db"))
    else:
        LOG.info(_LI("Spoofguard policies in Neutron Db but not present "
                     "on NSXv"))
    missing_policies = get_missing_spoofguard_policy_mappings(reverse)
    if not missing_policies:
        LOG.info(_LI("\nNo missing spoofguard policies found."
                     "\nNeutron DB and NSXv backend are in sync\n"))
    else:
        LOG.info(missing_policies)
        missing_policies = [{'policy_id': pid} for pid in missing_policies]
        LOG.info(formatters.output_formatter(
            constants.SPOOFGUARD_POLICY, missing_policies, ['policy_id']))


def nsx_clean_spoofguard_policy(resource, event, trigger, **kwargs):
    """Delete spoofguard policy"""
    errmsg = ("Need to specify policy-id. Add --property "
              "policy-id=<policy-id>")
    if not kwargs.get('property'):
        LOG.error(_LE("%s"), errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    policy_id = properties.get('policy-id')
    if not policy_id:
        LOG.error(_LE("%s"), errmsg)
        return
    try:
        nsxv.get_spoofguard_policy(policy_id)
    except exceptions.NeutronException as e:
        LOG.error(_LE("%s"), str(e))
    else:
        confirm = admin_utils.query_yes_no(
            "Do you want to delete spoofguard-policy: %s" % policy_id,
            default="no")
        if not confirm:
            LOG.info(_LI("spoofguard-policy deletion aborted by user"))
            return
        try:
            nsxv.delete_spoofguard_policy(policy_id)
        except Exception as e:
            LOG.error(_LE("%s"), str(e))
        LOG.info(_LI('spoofguard-policy successfully deleted.'))


registry.subscribe(neutron_list_spoofguard_policy_mappings,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_list_spoofguard_policies,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_list_missing_spoofguard_policies,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_clean_spoofguard_policy,
                   constants.SPOOFGUARD_POLICY,
                   shell.Operations.CLEAN.value)
