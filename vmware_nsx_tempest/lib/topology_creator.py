# Copyright 2017 VMware Inc
# All Rights Reserved.
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
import collections
import copy
from oslo_log import log as logging

from tempest import config
from tempest.lib.common.utils import test_utils

from vmware_nsx_tempest.lib import network_elements

CONF = config.CONF
LOG = logging.getLogger(__name__)


class TopologyBuilder(network_elements.NetworkElements):
    server_details = collections.namedtuple('server_details',
                                            ['server', 'floating_ip',
                                             'network', 'subnet'])

    def setUp(self):
        super(TopologyBuilder, self).setUp()
        self.topology_routers = {}
        self.topology_networks = {}
        self.topology_subnets = {}
        self.topology_servers = {}
        self.topology_servers_floating_ip = []
        self.topology_public_network_id = CONF.network.public_network_id
        self.topology_config_drive = CONF.compute_feature_enabled.config_drive
        self.topology_keypairs = {}
        self.servers_details = {}


    def create_router(self, router, **kwargs):
        return self._create_router(namestart="vmw_" + router, **kwargs)

    def create_network(self, network, **kwargs):
        return self._create_network(namestart="vmw_" + network, **kwargs)

    def create_subnet(self, subnet, network, **kwargs):
        return self._create_subnet(network, namestart="vmw_" + subnet,
                                   **kwargs)

    def create_instance(self, server, network, **kwargs):
        return self.create_server(name="vmw_" + server,
                                  networks=[{"uuid": network['id']}],
                                  **kwargs)

    def create_security_group(self, **kwargs):
        return self._create_security_group()

    def deploy_topology(self, topology):
        """Topology creator will deploy topology based on args
        topology: is a dict of required topology such as router, network,
        subnet and servers
        """
        router_given = True
        if not topology.keys()[0].startswith("router"):
            new_topology = {}
            new_topology["no_router"] = copy.deepcopy(topology)
            topology = new_topology
            router_given = False
        for router, topology_elements in topology.items():
            if router != "no_router":
                router_attribute = topology_elements.pop("router_attribute")
                if router_attribute.get("client"):
                    router_client = router_attribute["client"]
                else:
                    router_client = self.routers_client
                result = _router = self.create_router(router, **router_attribute)
                kwargs = {"external_gateway_info": dict(
                    network_id=self.topology_public_network_id)}
                router_client.update_router(_router['id'], **kwargs)
                self.topology_routers[router] = _router
            else:

                for network, net_elements in topology_elements.items():
                    network_attribute = net_elements.pop("network_attribute")
                    result = _network = self.create_network(
                        network, **network_attribute)
                    self.topology_networks[network] = _network
                    for subnet, subnet_elements in net_elements.items():
                        subnet_attribute = subnet_elements.pop("subnet_attribute")
                        result = _subnet = self.create_subnet(
                            subnet, _network, **subnet_attribute)
                        if router_given:
                            router_client.add_router_interface(_router["id"],
                                subnet_id=_subnet["id"])
                            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                                            router_client.remove_router_interface,
                                            _router["id"], subnet_id=_subnet["id"])
                        self.topology_subnets[subnet] = _subnet
                        for server, server_elements in subnet_elements.items():
                            server_attribute = server_elements.pop(
                                "server_attribute")
                            if not server_attribute.get("security_groups"):
                                _sg = self.create_security_group()
                                _security_groups = [{'name': _sg['name']}]
                                server_attribute["security_groups"] = \
                                    _security_groups
                            if not server_attribute.get("config_drive"):
                                server_attribute["config_drive"] = \
                                    self.topology_config_drive
                            if not server_attribute.get("key_name"):
                                keypair = self.create_keypair()
                                self.topology_keypairs[keypair['name']] = keypair
                                server_attribute["key_name"] = keypair['name']
                            result = _server = self.create_instance(
                                server, _network, **server_attribute)
                            if router_given:
                                _floating_ip = self.create_floating_ip(_server)
                                result["floating_ip"] = _floating_ip
                                self.topology_servers_floating_ip.append(_floating_ip)
                            else:
                                _floating_ip = None
                            _server_details = self.server_details(
                                server=_server, floating_ip=_floating_ip,
                                network=_network, subnet=_subnet)
                            self.servers_details[server] = _server_details
                            self.topology_servers[server] = _server
