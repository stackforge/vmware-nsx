# Copyright 2015 VMware, Inc.
#
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

from oslo_log import log as logging

from neutron import manager
from neutron_dynamic_routing.db import bgp_db
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from neutron._i18n import _
from neutron._i18n import _LI

from vmware_nsx.common import nsxv_constants
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import (
    exceptions as vcns_exc)

LOG = logging.getLogger(__name__)


class NsxvBGPDriver(bgp_db.BgpDbMixin):

    """Class driver to address the neutron_dynamic_routing API"""

    def __init__(self):
        super(NsxvBGPDriver, self).__init__()

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    @property
    def _nsxv(self):
        return self._core_plugin.nsx_v

    @property
    def _edge_manager(self):
        return self._core_plugin.edge_manager

    def _get_service_edge_list_for_router(self, context, gateway_network_id):
        network = self._core_plugin._get_network(context, gateway_network_id)
        # Check the network is an external network
        if not (hasattr(network, 'external') and network.external):
            err_msg = 'Can not attach private network to bgp speaker'
            raise n_exc.InvalidInput(err_msg)

        # Filter the routers attached this network as gateway interface
        filters = {'network_id': gateway_network_id,
                   'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW]}
        fields = ['device_id', 'fixed_ips']
        gateway_ports = self._core_plugin.get_ports(context, filters=filters,
                                                    fields=fields)
        # {
        #   'edge_id': <service_edge_id>
        #   'dr_router_id': <gateway_uplink_ip>
        # }
        distinct_edge_set = []
        edge_router_list = []
        for port in gateway_ports:
            edge_router_dict = {}
            router_id = port['device_id']
            dr_router_id = port['fixed_ips']['ip_address']
            edge_binding = nsxv_db.get_nsxv_router_binding(context, router_id)
            if (edge_binding['edge_type'] == nsxv_constants.SERVICE_EDGE and
                edge_binding['edge_id'] not in distinct_edge_set):
                edge_router_dict['edge_id'] = edge_binding['edge_id']
                edge_router_dict['dr_router_id'] = dr_router_id
                edge_router_list.append(edge_router_dict)
                distinct_edge_set.append(edge_binding['edge_id'])
        return edge_router_list, distinct_edge_set

    def _query_fips_and_tenant_subnets(self, context, gateway_network_id):
        filters = {'network_id': gateway_network_id,
                   'device_owner': [n_const.DEVICE_OWNER_FLOATINGIP,
                                    n_const.DEVICE_OWNER_ROUTER_INTF]}
        fields = ['fixed_ips', 'device_owner']
        ports = self._core_plugin.get_ports(context, filters=filters,
                                            fields=fields)
        fips = [p['fixed_ips']['ip_address'] for p in ports if
                p['device_owner'] == n_const.DEVICE_OWNER_FLOATINGIP]
        subnet_ids = []
        subnets = []
        for p in ports:
            if (p['device_owner'] == n_const.DEVICE_OWNER_ROUTER_INTF and
                p['fixed_ips']['subnet_id'] not in subnet_ids):
                subnet_id = p['fixed_ips']['subnet_id']
                subnet = self._core_plugin.get_subnets(context, subnet_id)
                subnet_ids.append(subnet_id)
                subnets.append(subnet)
        LOG.debug(_LI('Got related floating ips %(f)s and tenant subnets %(s)s'
                      ' for external network %(n)s.',
                  {'f': fips, 's': subnets, 'n': gateway_network_id}))
        return fips, subnets

    def create_bgp_speaker(self, context, bgp_speaker):
        # Check ip version first
        bgp_speaker_data = bgp_speaker['bgp_speaker']
        ip_version = bgp_speaker_data.get('ip_version')
        if ip_version and ip_version == 6:
            err_msg = _("NSXv BGP does not support for IPv6")
            raise n_exc.InvalidInput(err_msg)

        return self.create_bgp_speaker(context, bgp_speaker)

    def update_bgp_speaker(self, context, bgp_speaker_id, bgp_speaker):
        old_speaker_info = self.get_bgp_speaker(bgp_speaker_id)
        old_network_policy = old_speaker_info['advertise_tenant_networks']
        old_fip_policy = old_speaker_info['advertise_floating_ip_host_routes']
        gateway_network_ids = old_speaker_info['networks']

        # update router edge backend
        for network_id in gateway_network_ids:
            edge_router_list, e_ids = self._get_service_edge_list_for_router(
                context, network_id)
            LOG.debug(_LI('Update the BGP speaker %(bgp_speaker)s with'
                          'router backends %(edge_id)s',
                          {'bgp_speaker': bgp_speaker_id,
                           'edge_id': e_ids}))
            new_fip_policy = bgp_speaker['advertise_floating_ip_host_routes']
            new_network_policy = bgp_speaker['advertise_tenant_networks']
            if (old_fip_policy != new_fip_policy or
                old_network_policy != new_network_policy):
                # filter all fips and subnets related to gateway network id
                fips, subnets = self._query_fips_and_tenant_subnets(context,
                                                                    network_id)
                self._nsxv.update_bgp_filters(context, bgp_speaker,
                                              fips, subnets)
        return self.update_bgp_speaker(bgp_speaker_id, bgp_speaker)

    def delete_bgp_speaker(self, context, bgp_speaker_id):
        pass

    def create_bgp_peer(self, context, bgp_peer):
        return self.create_bgp_peer(context, bgp_peer)

    def update_bgp_peer(self, context, bgp_peer_id, bgp_peer):
        return

    def delete_bgp_peer(self, context, bgp_peer_id):
        pass

    def add_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        edge_ids = nsxv_db.get_nsxv_bgp_speaker_bindings(context.session,
                                                         bgp_speaker_id)
        # Should update the edge backend for bgp peer
        if not edge_ids:
            bgp_peer_id = bgp_peer_info['bgp_peer_id']
            bgp_peer_obj = self.get_bgp_peer(context, bgp_peer_id)
            for edge_id in edge_ids:
                self._nsxv.add_bgp_peer_config(edge_id,
                                               bgp_peer_obj)
        # Update db
        self.add_bgp_peer(context, bgp_speaker_id, bgp_peer_info)

    def remove_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        pass

    def add_bgp_speaker_to_dragent(self, context, agent_id, speaker_id):
        pass

    def remove_bgp_speaker_from_dragent(self, context, agent_id, speaker_id):
        pass

    def list_bgp_speaker_on_dragent(self, context, agent_id):
        return

    def list_dragent_hosting_bgp_speaker(self, context, speaker_id):
        return

    def add_gateway_network(self, context, bgp_speaker_id, network_info):
        gateway_network_id = network_info['network_id']
        edge_router_list, _ = self._get_service_edge_list_for_router(
                context, gateway_network_id)

        # Enable BGP configuration on service edge backend
        bgp_speaker_info = self.get_bgp_speaker(context, bgp_speaker_id)
        bgp_peers = self.get_bgp_peers_by_bgp_speaker(context,
                                                      bgp_speaker_id)
        fips, subnets = self._query_fips_and_tenant_subnets(context,
                                                            gateway_network_id)
        try:
            for edge_router_config in edge_router_list:
                LOG.debug(_LI('Enable BGP dynamic routing for %(edge_id)s with'
                              ' global router id %(router_id)s.',
                              {'edge_id': edge_router_config['edge_id'],
                               'router_id': edge_router_config['dr_router_id']}))
                self._nsxv.add_bgp_speaker_config(edge_router_config['edge_id'],
                                                  edge_router_config['dr_router_id'],
                                                  bgp_speaker_info,
                                                  bgp_peers,
                                                  fips,
                                                  subnets)
        except vcns_exc.VcnsApiException as e:
            raise e

        self.add_gateway_network(bgp_speaker_id, network_info)

    def remove_gateway_network(self, context, bgp_speaker_id, network_info):
        return
