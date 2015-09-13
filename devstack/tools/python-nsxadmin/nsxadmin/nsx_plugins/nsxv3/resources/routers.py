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
from neutron.db import l3_db
from neutron.db import common_db_mixin as common_db

LOG = logging.getLogger(__name__)


class NeutronL3Api(l3_db.L3_NAT_dbonly_mixin,
                       common_db.CommonDbMixin):
    def __init__(self):
        self.router_api= super(NeutronL3Api, self)
        self.neutron_admin_context = neutron_context.get_admin_context()

    def get_routers(self):
        routers = self.router_api.get_routers(self.neutron_admin_context)
        return routers

    def delete_router(self, router_id):
        self.l3_api.delete_router(self.neutron_admin_context,
                                  router_id)

neutron_l3 = NeutronL3Api()


def nsx_list_routers(resource, event, trigger, **kwargs):
    LOG.info('[NSX] List routers')
    routers = plugin.get_routers(neutron_context)
    for router in routers:
        LOG.info(router)


def nsx_clean_routers(resource, event, trigger, **kwargs):
    LOG.info('[NSX] Clean up routers')
    pass


def neutron_list_routers(resource, event, trigger, **kwargs):
    LOG.info('[Neutron] List routers')
    routers = neutron_l3.get_routers()
    formatters.output_formatter('Routers', routers, ['name', 'id'])
    return routers


def neutron_clean_routers(resource, event, trigger, **kwargs):
    LOG.info('[Neutron] Clean up routers')
    routers = neutron_l3.get_routers()
    for router in routers:
        try:
            LOG.info(('Trying to delete %(router_id)s'),
                     {'router_id': router['id']})
            neutron_l3.delete_router(router['id'])
            LOG.info(('Deleted router name: %(name)s id: %(id)s'),
                     {'name': router['name'], 'id': router['id']})
        except Exception as e:
            LOG.warning(('Unable to delete %(router_id)s'),
                        {'router_id': router['id']})
            pass
