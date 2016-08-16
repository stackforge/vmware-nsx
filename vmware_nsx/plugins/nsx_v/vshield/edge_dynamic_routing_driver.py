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

from neutron_dynamic_routing.db import bgp_db


CREATE_OP = 'create'
ADD_OP = 'add'
DELETE_OP = 'delete'
DEFAULT_HEADER = {
    'enabled': True,
    'rules': {
        'rules': [{
            'from': {
                'ospf': False,
                'bgp': False,
                'connected': False,
                'static': False
            },
            'action': 'deny'
        }]
    }
}


class EdgeDynamicRoutingDriver(object):

    """Edge driver API to implement the dynamic routing"""

    def __init__(self):
        # it will be initialized at subclass
        self.vcns = None

    @staticmethod
    def _construct_global_dr_config(self, router_id=None, fips=[], subnets=[]):
        global_config = {}
        if router_id:
            global_config['routerId'] = router_id
        ip_prefixes = []
        for fip in fips:
            ip_prefix = {
                'name': fip['id'],
                'ipAddress': '%s/32' % fip['ip_address']
            }
            ip_prefixes.append(ip_prefix)
        for subnet in subnets:
            ip_prefix = {
                'name': subnet['id'],
                'ipAddress': subnet['cidr']
            }
            ip_prefixes.append(ip_prefix)
        global_config['ipPrefixes'] = {'ipPrefixes': ip_prefixes}

        return global_config

    @staticmethod
    def _construct_global_bgp_filter(self):
        return {
            'bgpFilters': [{'direction': 'in', 'action': 'deny'}]
        }

    @staticmethod
    def _construct_redistribution_rules(self, bgp_speaker, fips=[], subnets=[],
                                        redis_rules=DEFAULT_HEADER, action=CREATE_OP):
        if bgp_speaker.get('advertise_tenant_networks'):
            for subnet in subnets:
                redis_rule = {
                    'prefixName': subnet['id'],
                    'from': {
                        'ospf': False,
                        'bgp': False,
                        'connected': True,
                        'static': True
                    },
                    'action': 'permit'
                }
                if action == CREATE_OP or action == ADD_OP:
                    redis_rules['rules']['rules'].append(redis_rule)
                else:
                    redis_rules['rules']['rules'].remove(redis_rule)
        if bgp_speaker.get('advertise_floating_ip_host_routes'):
            for fip in fips:
                redis_rule = {
                    'prefixName': fip['id'],
                    'from': {
                        'ospf': False,
                        'bgp': False,
                        'connected': True,
                        'static': True
                    },
                    'action': 'permit'
                }
                if action == CREATE_OP or action == ADD_OP:
                    redis_rules['rules']['rules'].append(redis_rule)
                else:
                    redis_rules['rules']['rules'].remove(redis_rule)
        return redis_rules

    def _convert_bgp_routing_config(self, bgp_speaker, bgp_peers,
                                    fips=[], subnets=[]):

        bgp = {
            'enabled': True,
            'localAS': bgp_speaker['local_as'],
            'redistribution': self._construct_redistribution_rules(bgp_speaker,
                                                                   fips,
                                                                   subnets)
        }

        bgp_neighbours = []
        for bgp_peer in bgp_peers:
            bgp_neighbour = {
                'ipAddress': bgp_peer['peer_ip'],
                'remoteAS': bgp_peer['remote_as'],
                'bgpFilters': self._construct_global_bgp_filter()
            }
            if bgp_peer['password']:
                bgp_neighbour['password'] = bgp_peer['password']

            bgp_neighbours.append(bgp_neighbour)

        if bgp_neighbours:
            bgp['bgpNeighbours'] = {'bgpNeighbours': bgp_neighbours}

        return bgp

    def add_bgp_speaker_config(self, edge_id, global_router_id,
                               bgp_speaker, bgp_peers=[],
                               fips=[], subnets=[]):
        routing_config = self._construct_global_dr_config(global_router_id,
                                                          fips, subnets)
        self.vcns.enable_dynamic_routing_service(edge_id, routing_config)
        nsx_bgp_obj = self._convert_bgp_routing_config(bgp_speaker, bgp_peers,
                                                       fips, subnets)
        self.vcns.enable_bgp_dynamic_routing(edge_id, nsx_bgp_obj)

    def delete_bgp_speaker_config(self, edge_id):
        self.vcns.delete_bgp_routing_config(edge_id)
        routing_config = self._construct_global_dr_config()
        self.vcns.enable_dynamic_routing_service(edge_id, routing_config)

    def update_bgp_speaker_config(self, edge_id, bgp_speaker):
        pass

    def add_bgp_peer_config(self, edge_id, bgp_peer):
        bgp_neighbor = {
            'ipAddress': bgp_peer['peer_ip'],
            'remoteAS': bgp_peer['remote_as'],
            'password': bgp_peer['password'],
            'bgpFilters': self._construct_global_bgp_filter()
        }
        # Query the bgp config first and update the bgpNeighbor
        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        bgp_neighbors = edge_bgp_info['bgpNeighbours']['bgpNeighbours']
        bgp_neighbors.append(bgp_neighbor)
        edge_bgp_info['bgpNeighbours']['bgpNeighbours'] = bgp_neighbors
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

    def update_bgp_redistribution_rules(self, edge_id, bgp_speaker,
                                        fips=[], subnets=[]):
        bgp_redis_rules = self._construct_redistribution_rules(
            bgp_speaker, fips, subnets)
        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        edge_bgp_info['redistribution'] = bgp_redis_rules
        self.vcns.enable_bgp_dynamic_routing(edge_id, edge_bgp_info)

    def add_bgp_redistribution_rule(self, context, edge_id, bgp_speaker_id, subnet):
        # Create new dynamic routing rule
        _, global_dr_config = self.vcns.get_dynamic_routing_service(edge_id)
        new_ip_prefix = {
            'name': subnet['id'],
            'ipAddress': subnet['cidr']
        }
        global_dr_config['ipPrefixes']['ipPrefixes'].append(new_ip_prefix)
        self.vcns.enable_dynamic_routing_service(edge_id, global_dr_config)

        bgp_speaker = bgp_db.get_bgp_speaker(context, bgp_speaker_id)
        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        orig_bgp_redis_rules = edge_bgp_info['redistribution']
        new_bgp_redis_rules = self._construct_redistribution_rules(bgp_speaker,
            subnets=[subnet], redis_rules=orig_bgp_redis_rules, action=ADD_OP)
        edge_bgp_info['redistribution'] = new_bgp_redis_rules
        self.vcns.enable_bgp_dynamic_routing(edge_id, edge_bgp_info)

    def delete_bgp_redistribution_rule(self, context, edge_id, bgp_speaker_id, subnet):
        # Delete the existing dynamic routing rule
        _, global_dr_config = self.vcns.get_dynamic_routing_service(edge_id)
        new_ip_prefix = {
            'name': subnet['id'],
            'ipAddress': subnet['cidr']
        }
        global_dr_config['ipPrefixes']['ipPrefixes'].remove(new_ip_prefix)
        self.vcns.enable_dynamic_routing_service(edge_id, global_dr_config)

        bgp_speaker = bgp_db.get_bgp_speaker(context, bgp_speaker_id)
        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        orig_bgp_redis_rules = edge_bgp_info['redistribution']
        new_bgp_redis_rules = self._construct_redistribution_rules(bgp_speaker,
            subnets=[subnet], redis_rules=orig_bgp_redis_rules, action=DELETE_OP)
        edge_bgp_info['redistribution'] = new_bgp_redis_rules
        self.vcns.enable_bgp_dynamic_routing(edge_id, edge_bgp_info)