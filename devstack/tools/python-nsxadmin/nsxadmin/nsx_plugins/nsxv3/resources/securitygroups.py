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


from nsxadmin.nsx_plugins.common import formatters

from oslo_log import log as logging

from neutron import context as neutron_context
from neutron.db import securitygroups_db as sg_db
from neutron.db import common_db_mixin as common_db

from vmware_nsx.nsxlib.v3 import dfw_api as firewall


LOG = logging.getLogger(__name__)


class NeutronSecurityGroupApi(sg_db.SecurityGroupDbMixin,
                              common_db.CommonDbMixin):
    def __init__(self):
        self.sg_api = super(NeutronSecurityGroupApi, self)
        self.neutron_admin_context = neutron_context.get_admin_context()

    def get_security_groups(self):
        securitygroups = self.sg_api.\
                         get_security_groups(self.neutron_admin_context)
        return securitygroups

    def delete_security_group(self, sg_id):
        self.sg_api.delete_security_group(self.neutron_admin_context,
                                          sg_id)

neutron_sg = NeutronSecurityGroupApi()


def nsx_list_security_groups(resource, event, trigger, **kwargs):
    LOG.info('[NSX] List security groups')
    sections = firewall.list_sections()
    formatters.output_formatter('Firewall Sections', sections, ['display_name', 'id'])
    nsgroups = firewall.list_nsgroups()
    formatters.output_formatter('Firewall NS Groups', nsgroups, ['display_name', 'id'])
    (sections, nsgroups)


def nsx_clean_security_groups(resource, event, trigger, **kwargs):
    LOG.info('[NSX] Clean up security groups')
    sections = firewall.list_sections()
    for section in sections[:-1]:
        LOG.info(("Deleting firewall section %(display_name)s, "
                 "section id %(id)s"), {'display_name': section['display_name'],
                 'id': section['id']})
        firewall.delete_section(section['id'])

    nsgroups = firewall.list_nsgroups()
    for nsgroup in nsgroups:
        LOG.info(("Deleting ns-group %(display_name)s, "
                "ns-group id %(id)s"),
                {'display_name': nsgroup['display_name'], 'id': nsgroup['id']})
        firewall.delete_nsgroup(nsgroup['id'])


def neutron_list_security_groups(resource, event, trigger, **kwargs):
    LOG.info('[Neutron] List security groups')
    security_groups = neutron_sg.get_security_groups()
    formatters.output_formatter('security groups', security_groups, ['name', 'id'])
    return security_groups


def neutron_clean_security_groups(resource, event, trigger, **kwargs):
    LOG.info('[Neutron] Clean up security groups')
    security_groups = neutron_sg.get_security_groups()
    for security_group in security_groups:
        try:
            LOG.info(('Trying to delete %(sg_id)s'), {'sg_id': security_group['id']})
            neutron_sg.delete_security_group(security_group['id'])
            LOG.info(("Deleted security group name: %(name)s id: %(id)s"),
                     {'name': security_group['name'], 'id': security_group['id']})
        except Exception as e:
            LOG.warning(e.value())
            pass

def unsynced_security_groups(resource, event, trigger, **kwargs):
    LOG.info('Unsycned security groups')

