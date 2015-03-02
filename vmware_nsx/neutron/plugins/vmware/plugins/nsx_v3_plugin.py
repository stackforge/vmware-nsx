# Copyright 2015 OpenStack Foundation
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

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.common import constants as const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.openstack.common import log as logging


from vmware_nsx.neutron.plugins.vmware.common import nsx_v3_config  # noqa
from vmware_nsx.neutron.plugins.vmware import nsx_v3_lib


LOG = logging.getLogger(__name__)


class NSXv3Plugin(db_base_plugin_v2.NeutronDbPluginV2,
                  agentschedulers_db.DhcpAgentSchedulerDbMixin):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    _supported_extension_aliases = ["quotas",
                                    "dhcp_agent_scheduler",
                                    "agent"]

    def __init__(self):
        super(NSXv3Plugin, self).__init__()
        LOG.info(_("Starting NSXv3Plugin"))
        # XXXX Read in config

        # TODO(arosen): setup dhcp notifier

    def _setup_rpc(self):
        self.conn = n_rpc.create_connection(new=True)
        self.topic = topics.PLUGIN
        # init dhcp agent support
        self._dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()

        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            self._dhcp_agent_notifier,
        )
        self.endpoints = [dhcp_rpc.DhcpRpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        # Consume from all consumers in threads
        self.conn.consume_in_threads()

    def create_network(self, context, network):
        result = nsx_v3_lib.create_logical_switch(
            network['network']['name'],
            cfg.CONF.nsx_v3.default_transport_zone_uuid)
        network['network']['id'] = result['id']
        network = super(NSXv3Plugin, self).create_network(context,
                                                          network)
        return network

    def delete_network(self, context, id):
        nsx_v3_lib.delete_logical_switch(id)
        return super(NSXv3Plugin, self).delete_network(context, id)

    def update_network(self, context, id, network):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).update_network(context, id,
                                                       network)

    def create_port(self, context, port):

        # XXX rollback error handing
        port = super(NSXv3Plugin, self).create_port(context,
                                                    port)
        nsx_v3_lib.create_logical_port(
            id=port['id'],
            lswitch_id=port['network_id'],
            vif_uuid=port['id'])
        return port

    def delete_port(self, context, id, l3_port_check=True):
        nsx_v3_lib.delete_logical_port(id)
        return super(NSXv3Plugin, self).delete_port(context, id)

    def update_port(self, context, id, port):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).update_port(context, id,
                                                    port)

    def create_router(self, context, router):
        # TODO(arosen) - call to backend
        router = super(NSXv3Plugin, self).create_router(context,
                                                        router)
        return router

    def delete_router(self, context, router_id):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).delete_router(context,
                                                      router_id)

    def update_router(self, context, router_id, router):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).update_router(context, id,
                                                      router)
