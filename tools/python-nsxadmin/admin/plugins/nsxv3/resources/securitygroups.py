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
from admin.plugins.common import formatters
from admin.plugins.common.utils import output_header
from admin.plugins.common.utils import query_yes_no
from admin.shell import Operations

from neutron.callbacks import registry
from neutron import context as neutron_context
from neutron.db import common_db_mixin as common_db
from neutron.db import securitygroups_db as sg_db

from vmware_nsx.nsxlib.v3 import dfw_api as firewall

LOG = logging.getLogger(__name__)


class NeutronSecurityGroupApi(sg_db.SecurityGroupDbMixin,
                              common_db.CommonDbMixin):
    def __init__(self):
        self.sg_api = super(NeutronSecurityGroupApi, self)
        self.neutron_admin_context = neutron_context.get_admin_context()

    def get_security_groups(self):
        self.sg_api.get_security_groups(self.neutron_admin_context)

    def delete_security_group(self, sg_id):
        self.sg_api.delete_security_group(self.neutron_admin_context,
                                          sg_id)

neutron_sg = NeutronSecurityGroupApi()


@output_header
def nsx_list_security_groups(resource, event, trigger, **kwargs):
    sections = firewall.list_sections()
    LOG.info(formatters.output_formatter(constants.FIREWALL_SECTIONS,
                                         sections, ['display_name', 'id']))
    nsgroups = firewall.list_nsgroups()
    LOG.info(formatters.output_formatter(constants.FIREWALL_NSX_GROUPS,
                                         nsgroups, ['display_name', 'id']))
    return bool(sections) or bool(nsgroups)


@output_header
def nsx_delete_security_groups(resource, event, trigger, **kwargs):
    if kwargs['force'] is False:
        if nsx_list_security_groups(resource, event, trigger, **kwargs):
            user_confirm = query_yes_no('Do you want to delete the following '
                                        'NSX firewall sections/nsgroups?',
                                        default='no')

            if user_confirm is False:
                LOG.info('NSX security groups cleanup aborted by user')
                return

    sections = firewall.list_sections()
    # NOTE(gangila): We use -1 indexing because we trying to delete default
    # security group on NSX Manager raises an exception.
    if sections:
        NON_DEFAULT_SECURITY_GROUPS = -1
        for section in sections[:NON_DEFAULT_SECURITY_GROUPS]:
            LOG.info("Deleting firewall section %(display_name)s, "
                     "section id %(id)s",
                     {'display_name': section['display_name'],
                      'id': section['id']})
            firewall.delete_section(section['id'])

    nsgroups = firewall.list_nsgroups()
    if nsgroups:
        for nsgroup in nsgroups:
            LOG.info("Deleting ns-group %(display_name)s, "
                     "ns-group id %(id)s",
                     {'display_name': nsgroup['display_name'],
                      'id': nsgroup['id']})
            firewall.delete_nsgroup(nsgroup['id'])


@output_header
def neutron_list_security_groups(resource, event, trigger, **kwargs):
    security_groups = neutron_sg.get_security_groups()
    LOG.info(formatters.output_formatter(constants.SECURITY_GROUPS,
                                         security_groups, ['name', 'id']))
    return bool(security_groups)


@output_header
def neutron_delete_security_groups(resource, event, trigger, **kwargs):
    if kwargs['force'] is False:
        if neutron_list_security_groups(resource, event, trigger, **kwargs):
            user_confirm = query_yes_no('Do you want to delete the followin '
                                        'neutron security groups?',
                                        default='no')
            if user_confirm is False:
                LOG.info('Neutron security groups cleanup aborted by user')
                return

    security_groups = neutron_sg.get_security_groups()
    if not security_groups:
        return

    for security_group in security_groups:
        try:
            LOG.info('Trying to delete %(sg_id)s',
                     {'sg_id': security_group['id']})
            neutron_sg.delete_security_group(security_group['id'])
            LOG.info("Deleted security group name: %(name)s id: %(id)s",
                     {'name': security_group['name'],
                      'id': security_group['id']})
        except Exception as e:
            LOG.warning(str(e))


registry.subscribe(nsx_list_security_groups,
                   constants.SECURITY_GROUPS,
                   Operations.LIST.value)
registry.subscribe(nsx_list_security_groups,
                   constants.SECURITY_GROUPS,
                   Operations.NSX_LIST.value)

registry.subscribe(neutron_list_security_groups,
                   constants.SECURITY_GROUPS,
                   Operations.LIST.value)
registry.subscribe(neutron_list_security_groups,
                   constants.SECURITY_GROUPS,
                   Operations.NEUTRON_LIST.value)

registry.subscribe(nsx_delete_security_groups,
                   constants.SECURITY_GROUPS,
                   Operations.CLEAN.value)
registry.subscribe(nsx_delete_security_groups,
                   constants.SECURITY_GROUPS,
                   Operations.NSX_CLEAN.value)

registry.subscribe(neutron_delete_security_groups,
                   constants.SECURITY_GROUPS,
                   Operations.CLEAN.value)
registry.subscribe(neutron_delete_security_groups,
                   constants.SECURITY_GROUPS,
                   Operations.NEUTRON_CLEAN.value)
