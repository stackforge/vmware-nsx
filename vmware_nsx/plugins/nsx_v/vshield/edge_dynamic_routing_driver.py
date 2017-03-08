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
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class EdgeDynamicRoutingDriver(object):

    """Edge driver API to implement the dynamic routing"""

    def __init__(self):
        # it will be initialized at subclass
        self.vcns = None

    def _get_routing_global_config(self, edge_id):
        h, config = self.vcns.get_dynamic_routing_service(edge_id)
        global_config = config if config else {}
        global_config.setdefault('ipPrefixes', {'ipPrefixes': []})
        curr_prefixes = [{'ipPrefix': prx}
                         for prx in global_config['ipPrefixes']['ipPrefixes']]
        global_config['ipPrefixes'] = curr_prefixes
        return {'routingGlobalConfig': global_config}

    def _update_global_routing_config(self, edge_id, **kwargs):
        global_config = self._get_routing_global_config(edge_id)
        current_prefixes = global_config['routingGlobalConfig']['ipPrefixes']

        if 'ecmp' in kwargs:
            global_config['routingGlobalConfig']['ecmp'] = kwargs['ecmp']

        if 'router_id' in kwargs:
            global_config['routingGlobalConfig']['routerId'] = (
                kwargs['router_id'])

        current_prefixes[:] = [p for p in current_prefixes
                               if p['ipPrefix']['name'] not in
                               kwargs.get('prefixes_to_remove', [])]
        # Avoid adding duplicate rules when shared router relocation
        current_prefixes.extend([p for p in kwargs.get('prefixes_to_add', [])
                                 if p not in current_prefixes])

        self.vcns.update_dynamic_routing_service(edge_id, global_config)

    def _reset_routing_global_config(self, edge_id):
        global_config = self._get_routing_global_config(edge_id)
        global_config['routingGlobalConfig']['ecmp'] = False
        global_config['routingGlobalConfig'].pop('routerId', None)
        global_config['routingGlobalConfig'].pop('ipPrefixes', None)
        self.vcns.update_dynamic_routing_service(edge_id, global_config)

    def _get_routing_bgp_config(self, edge_id):
        h, config = self.vcns.get_bgp_routing_config(edge_id)
        bgp_config = config if config else {}
        bgp_config.setdefault('enabled', True)
        bgp_config.setdefault('bgpNeighbours', {'bgpNeighbours': []})
        bgp_config.setdefault('redistribution', {'rules': {'rules': []}})

        curr_neighbours = [{'bgpNeighbour': nbr} for nbr in
                           bgp_config['bgpNeighbours']['bgpNeighbours']]
        bgp_config['bgpNeighbours'] = curr_neighbours
        for nbr in curr_neighbours:
            bgp_filters = [{'bgpFilter': bf} for bf
                           in nbr['bgpNeighbour']['bgpFilters']['bgpFilters']]
            nbr['bgpNeighbour']['bgpFilters'] = bgp_filters
        redistribution_rules = [{'rule': rule} for rule in
                                bgp_config['redistribution']['rules']['rules']]
        bgp_config['redistribution']['rules'] = redistribution_rules
        return {'bgp': bgp_config}

    def _update_bgp_routing_config(self, edge_id, **kwargs):
        bgp_config = self._get_routing_bgp_config(edge_id)
        curr_neighbours = bgp_config['bgp']['bgpNeighbours']
        curr_rules = bgp_config['bgp']['redistribution']['rules']

        if 'local_as' in kwargs:
            bgp_config['bgp']['localAS'] = kwargs['local_as']

        if 'enabled' in kwargs:
            bgp_config['bgp']['redistribution']['enabled'] = kwargs['enabled']

        curr_rules[:] = [rule for rule in curr_rules
                         if rule['rule']['prefixName'] not in
                         kwargs.get('rules_to_remove', [])]
        # Avoid adding duplicate rules when shared router relocation
        curr_rules_prefixes = [r['rule']['prefixName'] for r in curr_rules]
        curr_rules.extend([r for r in kwargs.get('rules_to_add', [])
                           if r['rule']['prefixName'] not in
                           curr_rules_prefixes])

        curr_neighbours[:] = [nbr for nbr in curr_neighbours
                              if nbr['bgpNeighbour']['ipAddress']
                              not in kwargs.get('neighbours_to_remove', [])]
        curr_neighbours.extend(kwargs.get('neighbours_to_add', []))

        self.vcns.update_bgp_dynamic_routing(edge_id, bgp_config)

    def _get_edge_static_routes(self, edge_id):
        h, routes = self.vcns.get_routes(edge_id)
        static_routes = routes if routes else {}
        static_routes.setdefault('staticRoutes', {'staticRoutes': []})
        return static_routes

    def _delete_default_static_routes(self, edge_id):
        routes = self._get_edge_static_routes(edge_id)
        route_list = routes['staticRoutes']['staticRoutes']
        routes['staticRoutes']['staticRoutes'] = [
            r for r in route_list if r['network'] != '0.0.0.0/0']
        self.vcns.update_routes(edge_id, routes)

    def _add_default_static_routes(self, edge_id, default_routes):
        routes = self._get_edge_static_routes(edge_id)
        routes['staticRoutes']['staticRoutes'].extend(default_routes)
        self.vcns.update_routes(edge_id, routes)

    def add_bgp_speaker_config(self, edge_id, prot_router_id, local_as,
                               enabled, ecmp, default_routes, bgp_neighbours,
                               prefixes, redistribution_rules):
        self._update_global_routing_config(edge_id,
                                           ecmp=ecmp,
                                           router_id=prot_router_id,
                                           prefixes_to_add=prefixes)
        self._update_bgp_routing_config(edge_id, enabled=enabled,
                                        local_as=local_as,
                                        neighbours_to_add=bgp_neighbours,
                                        prefixes_to_add=prefixes,
                                        rules_to_add=redistribution_rules)
        if ecmp:
            self._add_default_static_routes(edge_id, default_routes)

    def delete_bgp_speaker_config(self, edge_id):
        self.vcns.delete_bgp_routing_config(edge_id)
        self._delete_default_static_routes(edge_id)
        self._reset_routing_global_config(edge_id)

    def add_bgp_neighbours(self, edge_id, bgp_neighbours):
        # Query the bgp config first and update the bgpNeighbour
        self._update_bgp_routing_config(edge_id,
                                        neighbours_to_add=bgp_neighbours)

    def delete_bgp_neighbours(self, edge_id, bgp_neighbours):
        self._update_bgp_routing_config(edge_id,
                                        neighbours_to_remove=bgp_neighbours)

    def update_bgp_neighbour(self, edge_id, bgp_neighbour):
        self._update_bgp_routing_config(edge_id,
                                        neighbours_to_remove=[bgp_neighbour],
                                        neighbours_to_add=[bgp_neighbour])

    def update_routing_redistribution(self, edge_id, enabled):
        self._update_bgp_routing_config(edge_id, enabled=enabled)

    def add_bgp_redistribution_rules(self, edge_id, prefixes, rules):
        self._update_global_routing_config(edge_id,
                                           prefixes_to_add=prefixes)
        self._update_bgp_routing_config(edge_id, rules_to_add=rules)
        LOG.debug("Added redistrution rules %s on edge %s", rules, edge_id)

    def delete_bgp_redistribution_rules(self, edge_id, prefixes):
        self._update_bgp_routing_config(edge_id, rules_to_remove=prefixes)
        self._update_global_routing_config(edge_id,
                                           prefixes_to_remove=prefixes)
        LOG.debug("Removed redistrution rules for prefixes %s on edge %s",
                  prefixes, edge_id)
