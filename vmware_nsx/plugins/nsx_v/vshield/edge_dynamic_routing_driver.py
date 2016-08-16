# Copyright 2016 VMware, Inc
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


class EdgeDynamicRoutingDriver(object):

    """Edge driver API to implement the dynamic routing"""

    def __init__(self):
        # it will be initialized at subclass
        self.vcns = None

    def _construct_global_dr_config(self, router_id):
        return {'routingGlobalConfig':
                    {'routerId': router_id}}

    def _construct_bgp_filters(self, bgp_speaker, fips=None, subnets=None):
        bgp_filters = []
        ad_tenant_networks = bgp_speaker.get('advertise_tenant_networks')
        ad_fip_host_routes = bgp_speaker.get('advertise_floating_ip_host_routes')
        if (ad_tenant_networks is not None and
            not ad_tenant_networks):
            # decline the advertisement for tenant networks
            for subnet in subnets:
                bgp_filter = {
                    'direction': 'out',
                    'action': 'deny',
                    'network': subnet
                }
                bgp_filters.append(bgp_filter)
        if (ad_fip_host_routes is not None and
            not ad_fip_host_routes):
            for fip in fips:
                bgp_filter = {
                    'direction': 'out',
                    'action': 'deny',
                    'network': '%s/32' % fip
                }
                bgp_filters.append(bgp_filter)

        common_filter = {
                'direction': 'in',
                'action': 'deny'
        }
        bgp_filters.append(common_filter)
        return {'bgpFilters': bgp_filters}

    def _convert_bgp_routing_config(self, bgp_speaker, bgp_peers,
                                    fips=None, subnets=None):

        bgp = {
            'enabled': True,
            'localAS': bgp_speaker['local_as']
        }

        bgp_neighbours = []
        for bgp_peer in bgp_peers:
            bgp_filter_dict = self._construct_bgp_filters(bgp_speaker,
                                                          fips,
                                                          subnets)
            bgp_neighbour = {
                'ipAddress': bgp_peer['peer_ip'],
                'remoteAS': bgp_peer['remote_as'],
                'bgpFilters': bgp_filter_dict
            }
            if bgp_peer['password']:
                bgp_neighbour['password'] = bgp_peer['password']

            bgp_neighbours.append(bgp_neighbour)

        if bgp_neighbours:
            bgp['bgpNeighbours'] = {'bgpNeighbours': bgp_neighbours}

        return bgp

    def add_bgp_speaker_config(self, edge_id, global_router_id,
                               bgp_speaker, bgp_peers=[],
                               fips=None, subnets=None):
        routing_config = self._construct_global_dr_config(global_router_id)
        self.vcns.enable_dynamic_routing_service(edge_id, routing_config)
        nsx_bgp_obj = self._convert_bgp_routing_config(bgp_speaker, bgp_peers,
                                                       fips, subnets)
        self.vcns.enable_bgp_dynamic_routing(edge_id, nsx_bgp_obj)

    def delete_bgp_speaker_config(self, edge_id):
        self.vcns.delete_bgp_routing_config(edge_id)

    def update_bgp_speaker_config(self, edge_id, bgp_speaker):
        pass

    def add_bgp_peer_config(self, edge_id, bgp_speaker,
                            bgp_peer, subnets=None, fips=None):
        bgp_filters_dict = self._construct_bgp_filters(bgp_speaker,
                                                       fips, subnets)
        bgp_neighbor = {
            'ipAddress': bgp_peer['peer_ip'],
            'remoteAS': bgp_peer['remote_as'],
            'password': bgp_peer['password'],
            'bgpFilters': bgp_filters_dict
        }
        # Query the bgp config first and update the bgpNeighbor
        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        bgp_neighbors = edge_bgp_info['bgpNeighbours']['bgpNeighbours']
        bgp_neighbors.append(bgp_neighbor)
        edge_bgp_info['bgpNeighbours']['bgpNeighbours'] = bgp_neighbors
        edge_bgp_info.pop('redistribution', None)
        self.vcns.enable_bgp_dynamic_routing(edge_id, edge_bgp_info)

    def delete_bgp_peer_config(self, edge_id, bgp_peer):
        # Query the bgp config first and update the bgpNeighbor
        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        bgp_neighbors = edge_bgp_info['bgpNeighbours']['bgpNeighbours']
        for bgp_neighbor in bgp_neighbors:
            if bgp_neighbor['ipAddress'] == bgp_peer['peer_ip']:
                bgp_neighbors.remove(bgp_neighbor)
                break
        edge_bgp_info['bgpNeighbours']['bgpNeighbours'] = bgp_neighbors
        self.vcns.enable_bgp_dynamic_routing(edge_id, edge_bgp_info)

    def update_bgp_peer_config(self, edge_id, bgp_peer):
        # Query the bgp config first and update the bgpNeighbor
        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        bgp_neighbors = edge_bgp_info['bgpNeighbours']['bgpNeighbours']
        for bgp_neighbor in bgp_neighbors:
            if bgp_neighbor['ipAddress'] == bgp_peer['peer_ip']:
                bgp_neighbor['password'] = bgp_peer['password']
                break
        edge_bgp_info['bgpNeighbours']['bgpNeighbours'] = bgp_neighbors
        self.vcns.enable_bgp_dynamic_routing(edge_id, edge_bgp_info)

    def update_bgp_filters(self, edge_id, bgp_speaker,
                           fips=None, subnets=None):
        bgp_filters_dict = self._construct_bgp_filters(bgp_speaker,
                                                       fips, subnets)
        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        new_bgp_neighbours = []
        for bgp_neighbour in edge_bgp_info['bgpNeighbours']['bgpNeighbours']:
            bgp_neighbour['bgpFilters'] = bgp_filters_dict.get('bgpFilters')
            new_bgp_neighbours.append(bgp_neighbour)
        edge_bgp_info['bgpNeighbours']['bgpNeighbours'] = new_bgp_neighbours
        edge_bgp_info.pop('redistribution', None)
        self.vcns.enable_bgp_dynamic_routing(edge_id, edge_bgp_info)
