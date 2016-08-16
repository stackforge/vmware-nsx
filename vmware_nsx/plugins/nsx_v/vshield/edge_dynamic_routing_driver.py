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
from oslo_utils import excutils
from vmware_nsx._i18n import _LE
from vmware_nsx.plugins.nsx_v.vshield.common import (
    exceptions as vcns_exc)

LOG = logging.getLogger(__name__)


class EdgeDynamicRoutingDriver(object):

    """Edge driver API to implement the dynamic routing"""

    def __init__(self):
        # it will be initialized at subclass
        self.vcns = None

    def _construct_global_dr_config(self, router_id=None,
                                    fips=None, subnets=None):
        global_config = {}
        if router_id:
            global_config['routerId'] = router_id
        ip_prefixes = []
        if fips:
            for fip in fips:
                ip_prefix = {
                    'name': 'fip-%s' % fip['id'],
                    'ipAddress': '%s/32' % fip['ip_address']
                }
                ip_prefixes.append(ip_prefix)
        if subnets:
            for subnet in subnets:
                ip_prefix = {
                    'name': 'cidr-' % subnet['id'],
                    'ipAddress': subnet['cidr']
                }
                ip_prefixes.append(ip_prefix)
        global_config['ipPrefixes'] = {'ipPrefixes': ip_prefixes}

        return global_config

    def _construct_global_bgp_filter(self):
        return {
            'bgpFilters': [{'direction': 'in', 'action': 'deny'}]
        }

    def _construct_redistribution_rules(self, bgp_speaker,
                                        fips=None, subnets=None):
        """
        :rtype: {
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
        """
        redis_rules = {
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

        if bgp_speaker.get('advertise_tenant_networks') and subnets:
            for subnet in subnets:
                redis_rule = {
                    'prefixName': 'cidr-%s' % subnet['id'],
                    'from': {
                        'ospf': False,
                        'bgp': False,
                        'connected': True,
                        'static': True
                    },
                    'action': 'permit'
                }
                redis_rules['rules']['rules'].append(redis_rule)

        if bgp_speaker.get('advertise_floating_ip_host_routes') and fips:
            for fip in fips:
                redis_rule = {
                    'prefixName': 'fip-%s' % fip['id'],
                    'from': {
                        'ospf': False,
                        'bgp': False,
                        'connected': True,
                        'static': True
                    },
                    'action': 'permit'
                }
                redis_rules['rules']['rules'].append(redis_rule)
        return redis_rules

    def _convert_bgp_routing_config(self, bgp_speaker, bgp_peers,
                                    fips=None, subnets=None):
        """

        :param bgp_speaker: the bgp speaker including advertisement policy
        :param bgp_peers: all bgp peers connected to the bgp speaker
        :param fips: the advertised floating ips
        :param subnets: the advertised tenant subnets
        :return: the NSXv bgp json object
        """

        bgp = {
            'enabled': True,
            'localAS': bgp_speaker['local_as'],
            'redistribution': self._construct_redistribution_rules(
                    bgp_speaker, fips, subnets)
        }

        if bgp_peers:
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
                               bgp_speaker, bgp_peers=None,
                               fips=None, subnets=None):
        routing_config = self._construct_global_dr_config(global_router_id,
                                                          fips, subnets)
        nsx_bgp_obj = self._convert_bgp_routing_config(bgp_speaker, bgp_peers,
                                                       fips, subnets)
        try:
            self.vcns.enable_dynamic_routing_service(edge_id,
                                                     routing_config)
            self.vcns.enable_bgp_dynamic_routing(edge_id, nsx_bgp_obj)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to enable BGP for %s'), edge_id)

    def delete_bgp_speaker_config(self, edge_id):
        routing_config = self._construct_global_dr_config()
        try:
            self.vcns.delete_bgp_routing_config(edge_id)
            self.vcns.enable_dynamic_routing_service(edge_id,
                                                     routing_config)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to delete BGP for %s'), edge_id)

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
                                        fips=None, subnets=None):
        bgp_redis_rules = self._construct_redistribution_rules(
            bgp_speaker, fips, subnets)
        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        edge_bgp_info['redistribution'] = bgp_redis_rules
        self.vcns.enable_bgp_dynamic_routing(edge_id, edge_bgp_info)

    def add_bgp_redistribution_rule(self, context, edge_id,
                                    bgp_speaker_id, subnet):
        # Create new dynamic routing rule
        _, global_dr_config = self.vcns.get_dynamic_routing_service(edge_id)
        new_ip_prefix = {
            'name': 'cidr-%s' % subnet['id'],
            'ipAddress': subnet['cidr']
        }
        global_dr_config['ipPrefixes']['ipPrefixes'].append(new_ip_prefix)
        self.vcns.enable_dynamic_routing_service(edge_id, global_dr_config)

        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        bgp_redis_rules = edge_bgp_info['redistribution']
        for r in bgp_redis_rules:
            if r.get('prefixName') and r.get('prefixName').startswith('cidr'):
                redis_rule = {
                        'prefixName': 'cidr-%s' % subnet['id'],
                        'from': {
                            'ospf': False,
                            'bgp': False,
                            'connected': True,
                            'static': True
                        },
                        'action': 'permit'
                }
                bgp_redis_rules.append(redis_rule)
                edge_bgp_info['redistribution'] = bgp_redis_rules
                LOG.debug('Update edge %(edge_id)s with redistrution rules'
                          ' %(rules)s', {'edge_id': edge_id,
                                         'rules': bgp_redis_rules})
                self.vcns.enable_bgp_dynamic_routing(edge_id, edge_bgp_info)
                return

    def delete_bgp_redistribution_rule(self, context, edge_id, subnet):
        _, edge_bgp_info = self.vcns.get_bgp_routing_config(edge_id)
        bgp_redis_rules = edge_bgp_info['redistribution']
        bgp_redis_rules = [r for r in bgp_redis_rules
                           if r.get('prefixName') != subnet['id']]
        edge_bgp_info['redistribution'] = bgp_redis_rules
        self.vcns.enable_bgp_dynamic_routing(edge_id, edge_bgp_info)

        # Delete the existing dynamic routing rule
        _, global_dr_config = self.vcns.get_dynamic_routing_service(edge_id)
        new_ip_prefix = {
            'name': 'cidr-%s' % subnet['id'],
            'ipAddress': subnet['cidr']
        }
        global_dr_config['ipPrefixes']['ipPrefixes'].remove(new_ip_prefix)
        self.vcns.enable_dynamic_routing_service(edge_id, global_dr_config)
