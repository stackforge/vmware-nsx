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
from oslo.utils import importutils

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.v2 import attributes
from neutron.extensions import l3

from neutron.common import constants as const
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agentschedulers_db
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2
from neutron.db import models_v2
from neutron.db import l3_db
from neutron.openstack.common import log as logging


from vmware_nsx.neutron.plugins.vmware.common import nsx_v3_config  # noqa
from vmware_nsx.neutron.plugins.vmware import nsx_v3_lib


LOG = logging.getLogger(__name__)


class NSXv3Plugin(db_base_plugin_v2.NeutronDbPluginV2,
                  l3_db.L3_NAT_dbonly_mixin,
                  agentschedulers_db.DhcpAgentSchedulerDbMixin):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["quotas",
                                    "dhcp_agent_scheduler",
                                    "agent",
                                    "router"]

    def __init__(self):
        super(NSXv3Plugin, self).__init__()
        LOG.info(_("Starting NSXv3Plugin"))
        # XXXX Read in config

        self._setup_rpc()

    def _setup_rpc(self):
        self.topic = topics.PLUGIN
        self.conn = n_rpc.create_connection(new=True)
        self.endpoints = [dhcp_rpc.DhcpRpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI())
        self.conn.consume_in_threads()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.supported_extension_aliases.extend(
            ['agent', 'dhcp_agent_scheduler'])

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
        result = nsx_v3_lib.create_logical_router(
            display_name=router['router']['name'],
            router_id=None, # <-- does not work..
            router_type="TIER0",
            edge_cluster_uuid=cfg.CONF.nsx_v3.default_edge_cluster_uuid)

        router['router']['id'] = result['id']
        router = super(NSXv3Plugin, self).create_router(context,
                                                        router)
        print result

        return router

    def delete_router(self, context, router_id):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).delete_router(context,
                                                      router_id)

    def update_router(self, context, router_id, router):
        # TODO(arosen) - call to backend
        return super(NSXv3Plugin, self).update_router(context, id,
                                                      router)


    def add_router_interface(self, context, router_id, interface_info):
        print "add: ", interface_info
        # NOTE(arosen): I think there is a bug here since I believe we
        # can also get a port or ip here....
        subnet = self.get_subnet(context, interface_info['subnet_id'])
        port = {'port': {'network_id': subnet['network_id'], 'name': '',
                         'admin_state_up': True, 'device_id': '',
                         'device_owner': l3_db.DEVICE_OWNER_ROUTER_INTF,
                         'mac_address': attributes.ATTR_NOT_SPECIFIED,
                         'fixed_ips': [{'subnet_id': subnet['id'],
                                        'ip_address': subnet['gateway_ip']}]}}
        port = self.create_port(context, port)
        print port
        result = nsx_v3_lib.create_logical_router_port(
            router_id=router_id,
            resource_type="LogicalRouterUpLinkPort",
            cidr_length=24, ip_addresses=subnet['gateway_ip'],
            port_id=port['id'])
        print result
        interface_info['port_id'] = port['id']
        del interface_info['subnet_id']
        result = super(NSXv3Plugin, self).add_router_interface(
            context, router_id, interface_info)
        print result
        return result


    def remove_router_interface(self, context, router_id, interface_info):
        print "REMOVE: ", interface_info

        if 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._get_subnet(context, subnet_id)
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
                network_id=subnet['network_id'])
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                    port_id = p['id']
                    break
            else:
                raise l3.RouterInterfaceNotFoundForSubnet(router_id=router_id,
                                                          subnet_id=subnet_id)
        print port_id
        nsx_v3_lib.delete_logical_router_port(port_id)
        return super(NSXv3Plugin, self).remove_router_interface(
            context, router_id, interface_info)



