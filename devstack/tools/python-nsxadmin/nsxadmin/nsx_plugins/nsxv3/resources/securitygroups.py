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
#     under the License.


from oslo_log import log as logging

from neutron.db import api as db_api
from neutron.db import securitygroups_db as sg_db

from vmware_nsx.nsxlib.v3 import dfw_api as firewall


LOG = logging.getLogger(__name__)


def nsx_list_security_groups(resource, event, trigger, **kwargs):
    LOG.info('[NSX] List security groups')
    sections = firewall.list_sections()
    for section in sections:
        LOG.info(("Firewall section: %(display_name)s, ID: %(id)s"),
                 {'display_name': section['display_name'],
                  'id': section['id']})

    nsgroups = firewall.list_nsgroups()
    for nsgroup in nsgroups:
        LOG.info(("ns-group: %(display_name)s, "
                  "ns-group id: %(id)s"),
                {'display_name': nsgroup['display_name'], 'id': nsgroup['id']})


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
    session = db_api.get_session()
    with session.begin():
        query = session.query(sg_db.SecurityGroup)
        if not query.all():
            LOG.info('No security groups found')
        for item in query:
            LOG.info(("Security group name: %(name)s id: %(id)s"),
                    {'name': item['name'], 'id': item['id']})


def neutron_clean_security_groups(resource, event, trigger, **kwargs):
    LOG.info('[Neutron] Clean up security groups')
    session = db_api.get_session()
    with session.begin():
        query = session.query(sg_db.SecurityGroup)
        if not query.all():
            LOG.info('No security groups found')
        for item in query:
            LOG.info(("Delete security group name: %(name)s id: %(id)s"),
                    {'name': item['name'], 'id': item['id']})
            session.delete(item)
