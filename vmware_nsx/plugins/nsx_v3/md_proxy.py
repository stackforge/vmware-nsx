# Copyright 2015 VMware, Inc.
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

from neutron.agent.metadata import agent
from neutron.common import constants

from oslo_log import log as logging

METADATA_IP_ADDR = '169.254.169.254'
INTERNAL_SUBNET = '169.254.169.252/30'

LOG = logging.getLogger(__name__)


class NsxV3MetadataProxyHandler(agent.MetadataProxyHandler):

    def __init__(self, conf):
        super(NsxV3MetadataProxyHandler, self).__init__(conf)

    def _get_ports(self, remote_address, network_id=None, router_id=None):
        """Search for all ports that contain passed ip address and belongs to
        given network.

        If no network is passed ports are searched on all networks connected to
        given router. Either one of network_id or router_id must be passed.

        If no port is found and network_id is an internal metadata network,
        find the associated router and search ports on all networks connected
        to the router.

        """
        if network_id:
            networks = (network_id,)
        elif router_id:
            networks = self._get_router_networks(router_id)
        else:
            raise TypeError(_("Either one of parameter network_id or router_id"
                              " must be passed to _get_ports method."))

        ports = self._get_ports_for_remote_address(remote_address, networks)
        if not ports and network_id:
            # Try again if on an internal metadata network.
            networks = self._get_networks_by_metadata_network(network_id)
            ports = self._get_ports_for_remote_address(
                remote_address, networks)
        return ports

    def _get_subnets_by_network(self, network_id):
        filters = {'network_id': [network_id]}
        return self.plugin_rpc.get_subnets(self.context, filters)

    def _get_networks_by_metadata_network(self, network_id):
        # Check if it is an internal metadata network.
        subnets = self._get_subnets_by_network(network_id)
        if (len(subnets) == 1 and
            subnets[0]['cidr'] == INTERNAL_SUBNET):
            # Find the gateway port in the metadata network.
            filters = {
                'device_owner': [constants.DEVICE_OWNER_ROUTER_INTF],
                'fixed_ips': {
                    'subnet_id': [subnets[0]['id']],
                    'ip_address': [subnets[0]['gateway_ip']]
                }
            }
            ports = self.plugin_rpc.get_ports(self.context, filters)
            if len(ports) == 1:
                # Find all the networks connected to the router on the gateway.
                return self._get_router_networks(ports[0]['device_id'])
        return []
