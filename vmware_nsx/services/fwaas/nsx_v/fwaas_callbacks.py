# Copyright 2017 VMware, Inc.
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

from oslo_config import cfg

from neutron.common import config as neutron_config  # noqa
from neutron_fwaas.services.firewall.agents.l3reference \
    import firewall_l3_agent
from neutron_lib import context as n_context
from neutron_lib.plugins import directory


class NsxvFwaasCallbacks(firewall_l3_agent.L3WithFWaaS):
    """NSX-V RPC callbacks for Firewall As A Service - V1."""
    def __init__(self):
        # The super code needs a configuration object with the neutron host
        # and an agent_mode, hich our driver doesn't use.
        neutron_conf = cfg.CONF
        neutron_conf.agent_mode = 'nsx'
        super(NsxvFwaasCallbacks, self).__init__(conf=neutron_conf)

    @property
    def core_plugin(self):
        return directory.get_plugin()

    # Override functions using the agent_api that is not used by our plugin
    def _has_router_insertion_fields(self, fw):
        return 'add-router-ids' in fw

    def _get_router_ids_for_fw(self, context, fw, to_delete=False):
        """Return the router_ids either from fw dict or tenant routers."""
        if self._has_router_insertion_fields(fw):
            # it is a new version of plugin
            return (fw['del-router-ids'] if to_delete
                    else fw['add-router-ids'])
        else:
            return [router['id'] for router in
                self._get_routers_in_project(context, fw['tenant_id'])]

    def _get_routers_in_project(self, context, project_id):
        return self.core_plugin.get_routers(
            context,
            filters={'tenant_id': project_id})

    def _get_router_info_list_for_tenant(self, router_ids, tenant_id):
        """Returns the list of router info objects on which to apply the fw."""
        context = n_context.get_admin_context()
        tenant_routers = self._get_routers_in_project(context, tenant_id)
        return [ri for ri in tenant_routers if ri.router_id in router_ids]
