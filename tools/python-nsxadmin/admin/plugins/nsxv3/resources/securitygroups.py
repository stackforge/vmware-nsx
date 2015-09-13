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

from neutron import context as neutron_context
from neutron.db import common_db_mixin as common_db
from neutron.db import securitygroups_db as sg_db

from neutron.callbacks import registry

from vmware_nsx.nsxlib.v3 import dfw_api as firewall

LOG = logging.getLogger(__name__)


class NeutronSecurityGroupApi(sg_db.SecurityGroupDbMixin,
                              common_db.CommonDbMixin):
    def __init__(self):
        self.sg_api = super(NeutronSecurityGroupApi, self)
        self.neutron_admin_context = neutron_context.get_admin_context()

    def get_security_groups(self):
        securitygroups = self.sg_api.get_security_groups(
            self.neutron_admin_context)
        return securitygroups

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


@output_header
def nsx_delete_security_groups(resource, event, trigger, **kwargs):
    sections = firewall.list_sections()
    # NOTE: We use -1 indexing because we trying to delete default
    # security group on NSX Manager raises an exception.
    # TODO(gangila): Find a better way.
    for section in sections[:-1]:
        LOG.info("Deleting firewall section %(display_name)s, "
                 "section id %(id)s",
                 {'display_name': section['display_name'],
                  'id': section['id']})
        firewall.delete_section(section['id'])

    nsgroups = firewall.list_nsgroups()
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


@output_header
def neutron_delete_security_groups(resource, event, trigger, **kwargs):
    security_groups = neutron_sg.get_security_groups()
    for security_group in security_groups:
        try:
            LOG.info('Trying to delete %(sg_id)s',
                     {'sg_id': security_group['id']})
            neutron_sg.delete_security_group(security_group['id'])
            LOG.info("Deleted security group name: %(name)s id: %(id)s",
                     {'name': security_group['name'],
                      'id': security_group['id']})
        except Exception as e:
            LOG.warning(e.value())


registry.subscribe(nsx_list_security_groups, "security-groups", "list")
registry.subscribe(nsx_list_security_groups, "security-groups", "nsx-list")

registry.subscribe(neutron_list_security_groups, "security-groups", "list")
registry.subscribe(neutron_list_security_groups, "security-groups",
                                                 "neutron-list")

registry.subscribe(nsx_delete_security_groups, "security-groups", "delete")
registry.subscribe(nsx_delete_security_groups, "security-groups", "nsx-delete")

registry.subscribe(neutron_delete_security_groups, "security-groups", "delete")
registry.subscribe(neutron_delete_security_groups, "security-groups",
                                                   "nsx-delete")
