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
from oslo_utils import excutils

from neutron import manager
from neutron_dynamic_routing.db import bgp_db
from neutron_dynamic_routing.extensions import bgp as bgp_ext
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _, _LE
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import (
    exceptions as vcns_exc)

LOG = logging.getLogger(__name__)


class NsxvBGPDriver(bgp_db.BgpDbMixin):
    """Class driver to address the neutron_dynamic_routing API"""

    def __init__(self, service_plugin):
        super(NsxvBGPDriver, self).__init__()
        self.service_plugin = service_plugin

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    @property
    def _nsxv(self):
        return self._core_plugin.nsx_v

    @property
    def _edge_manager(self):
        return self._core_plugin.edge_manager

    def _get_dynamic_routing_edge_list(self, context, gateway_network_id):
        network = self._core_plugin._get_network(context, gateway_network_id)
        # Check the network is an external network
        if not (hasattr(network, 'external') and network.external):
            err_msg = _('Can not attach private network to bgp speaker')
            raise n_exc.InvalidInput(error_message=err_msg)

        # Filter the routers attached this network as gateway interface
        filters = {'network_id': [gateway_network_id],
                   'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW]}
        fields = ['device_id', 'fixed_ips']
        gateway_ports = self._core_plugin.get_ports(context, filters=filters,
                                                    fields=fields)

        edge_router_list = []
        for port in gateway_ports:
            # {
            #   'edge_id': <service_edge_id>
            #   'dr_router_id': <gateway_uplink_ip>
            #   'router_id_list': [<router_id>,<router_id>]
            # }
            router_id = port['device_id']
            dr_router_id = port['fixed_ips'][0]['ip_address']
            edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                           router_id)
            # Address exclusive/shared router
            if edge_binding['edge_type'] == nsxv_constants.SERVICE_EDGE:
                create_new = True
                edge_id = edge_binding['edge_id']
                for i in range(len(edge_router_list)):
                    if edge_router_list[i]['edge_id'] == edge_id:
                        edge_router_list[i]['router_id_list'].append(router_id)
                        create_new = False
                        break
                # There is no same edge_id here
                if create_new:
                    edge_router_dict = {
                        'edge_id': edge_id,
                        'dr_router_id': dr_router_id,
                        'router_id_list': [router_id]}
                    edge_router_list.append(edge_router_dict)
            else:
                # Address distributed router
                plr_id = self._edge_manager.get_plr_by_tlr_id(context,
                                                              router_id)
                plr_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                              plr_id)
                edge_router_dict = {
                    'edge_id': plr_binding['edge_id'],
                    'dr_router_id': dr_router_id,
                    'router_id_list': [router_id]}
                edge_router_list.append(edge_router_dict)
        return edge_router_list

    def _query_fips_and_tenant_subnets(self, context,
                                       gateway_network_id, router_ids):
        # Query floating ips allocated in gateway network
        filters = {'network_id': [gateway_network_id],
                   'device_owner': [n_const.DEVICE_OWNER_FLOATINGIP]}
        fields = ['id', 'fixed_ips']
        fip_ports = self._core_plugin.get_ports(context, filters=filters,
                                                fields=fields)
        fips = [{'id': p['id'], 'ip_address': p['fixed_ips'][0]['ip_address']}
                for p in fip_ports]

        # Query subnets attached to all of routers attached to same edge
        subnets = []
        for router_id in router_ids:
            filters = {'device_id': [router_id],
                       'device_owner': [n_const.DEVICE_OWNER_ROUTER_INTF]}
            int_ports = self._core_plugin.get_ports(context, filters=filters,
                                                    fields=fields)
            subnet_ids = []
            for p in int_ports:
                if p['fixed_ips'][0]['subnet_id'] not in subnet_ids:
                    subnet_id = p['fixed_ips'][0]['subnet_id']
                    subnet = self._core_plugin.get_subnet(context, subnet_id)
                    subnet_ids.append(subnet_id)
                    subnets.append({'id': subnet_id,
                                    'cidr': subnet['cidr']})
        LOG.debug('Got related floating ips %(f)s and subnets %(s)s',
                  {'f': fips, 's': subnets})
        return fips, subnets

    def _get_bgp_speakers_by_bgp_peer(self, context, bgp_peer_id):
        fields = ['id', 'peers']
        bgp_speakers = self.get_bgp_speakers(context, fields=fields)
        bgp_speaker_ids = []
        for bgp_speaker in bgp_speakers:
            if bgp_peer_id in bgp_speaker['peers']:
                bgp_speaker_ids.append(bgp_speaker['id'])
        return bgp_speaker_ids

    def create_bgp_speaker(self, context, bgp_speaker):
        # Check ip version first
        bgp_speaker_data = bgp_speaker['bgp_speaker']
        ip_version = bgp_speaker_data.get('ip_version')
        if ip_version and ip_version == 6:
            err_msg = _("NSXv BGP does not support for IPv6")
            raise n_exc.InvalidInput(error_message=err_msg)

        return super(NsxvBGPDriver, self).create_bgp_speaker(context,
                                                             bgp_speaker)

    def update_bgp_speaker(self, context, bgp_speaker_id, bgp_speaker):
        bgp_obj = bgp_speaker['bgp_speaker']
        old_speaker_info = self.get_bgp_speaker(context, bgp_speaker_id)
        old_network_policy = old_speaker_info['advertise_tenant_networks']
        old_fip_policy = old_speaker_info['advertise_floating_ip_host_routes']
        gateway_network_ids = old_speaker_info['networks']

        # update router edge backend
        for network_id in gateway_network_ids:
            edge_router_list = self._get_dynamic_routing_edge_list(
                    context, network_id)
            LOG.debug('Update the BGP speaker %(bgp_speaker)s with'
                      'edge backend %(edge_router_list)s',
                      {'bgp_speaker': bgp_speaker_id,
                       'edge_router_list': edge_router_list})
            new_fip_policy = bgp_obj.get('advertise_floating_ip_host_routes')
            new_network_policy = bgp_obj.get('advertise_tenant_networks')
            if ((new_fip_policy is not None and
                 new_fip_policy != old_fip_policy) or
                (new_network_policy is not None and
                 new_network_policy != old_network_policy)):
                for edge_router_config in edge_router_list:
                    # filter all fips and subnets related to gateway network id
                    router_ids = edge_router_config['router_id_list']
                    fips, subnets = self._query_fips_and_tenant_subnets(
                            context, network_id, router_ids)
                    self._nsxv.update_bgp_redistribution_rules(
                        edge_router_config['edge_id'], bgp_obj, fips, subnets)
        return super(NsxvBGPDriver, self).update_bgp_speaker(context,
                                                             bgp_speaker_id,
                                                             bgp_speaker)

    def delete_bgp_speaker(self, context, bgp_speaker_id):
        edge_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(
                context.session, bgp_speaker_id)
        if edge_bindings:
            for edge_binding in edge_bindings:
                self._nsxv.delete_bgp_speaker_config(edge_binding['edge_id'])
                nsxv_db.delete_nsxv_bgp_speaker_binding(
                    context.session, edge_binding['edge_id'], bgp_speaker_id)
        super(NsxvBGPDriver, self).delete_bgp_speaker(context, bgp_speaker_id)

    def create_bgp_peer(self, context, bgp_peer):
        return super(NsxvBGPDriver, self).create_bgp_peer(context,
                                                          bgp_peer)

    def update_bgp_peer(self, context, bgp_peer_id, bgp_peer):
        password = bgp_peer['bgp_peer'].get('password')
        old_bgp_peer = self.get_bgp_peer(context, bgp_peer_id)
        auth_type = old_bgp_peer['auth_type']

        # NSXv backend only saves the password
        if (((auth_type == 'none' and password is None) or
            (auth_type != 'none' and password is not None)) and
            old_bgp_peer['password'] != password):
            bgp_speaker_ids = self._get_bgp_speakers_by_bgp_peer(context,
                                                                 bgp_peer_id)
            # Update the password for the old bgp peer and update NSX
            old_bgp_peer['password'] = password
            for bgp_speaker_id in bgp_speaker_ids:
                edge_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(
                        context.session, bgp_speaker_id)
                if edge_bindings:
                    try:
                        for binding in edge_bindings:
                            self._nsxv.update_bgp_peer_config(
                                    binding['edge_id'], old_bgp_peer)
                    except vcns_exc.VcnsApiException:
                        with excutils.save_and_reraise_exception():
                            LOG.exception(_LE("Failed to update BGP peer"
                                              " for %s"), binding['edge_id'])
        return super(NsxvBGPDriver, self).update_bgp_peer(context,
                                                          bgp_peer_id,
                                                          bgp_peer)

    def delete_bgp_peer(self, context, bgp_peer_id):
        bgp_speaker_ids = self._get_bgp_speakers_by_bgp_peer(context,
                                                             bgp_peer_id)
        for bgp_speaker_id in bgp_speaker_ids:
            edge_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(
                    context.session, bgp_speaker_id)
            if edge_bindings:
                bgp_peer_info = self.get_bgp_peer(context, bgp_peer_id)
                try:
                    for binding in edge_bindings:
                        self._nsxv.delete_bgp_peer_config(binding['edge_id'],
                                                          bgp_peer_info)
                except vcns_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_LE("NSXv: Failed to delete BGP peer"
                                          " for %s"), binding['edge_id'])
        super(NsxvBGPDriver, self).delete_bgp_peer(context, bgp_peer_id)

    def add_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        bgp_speaker_obj = self.get_bgp_speaker(context, bgp_speaker_id)
        gw_network_ids = bgp_speaker_obj['networks']
        bgp_peer_obj = self.get_bgp_peer(context,
                                         bgp_peer_info['bgp_peer_id'])
        ret_value = None
        try:
            ret_value = super(NsxvBGPDriver, self).add_bgp_peer(
                    context, bgp_speaker_id, bgp_peer_info)
            for gw_network_id in gw_network_ids:
                edge_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(
                        context.session, bgp_speaker_id)
                for binding in edge_bindings:
                    self._nsxv.add_bgp_peer_config(binding['edge_id'],
                                                   bgp_peer_obj)
        except (bgp_ext.BgpPeerNotFound, bgp_ext.BgpSpeakerNotFound,
                bgp_ext.DuplicateBgpPeerIpException) as ex:
            with excutils.save_and_reraise_exception():
                LOG.exception(ex)
        except vcns_exc.VcnsApiException:
            LOG.exception(_LE("NSXv: Failed to update BGP peer for edge"))
            super(NsxvBGPDriver, self).remove_bgp_peer(
                    context, bgp_speaker_id, bgp_peer_info)
        return ret_value

    def remove_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        edge_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(context.session,
                                                              bgp_speaker_id)
        if edge_bindings:
            bgp_peer_id = bgp_peer_info['bgp_peer_id']
            bgp_peer_obj = self.get_bgp_peer(context, bgp_peer_id)
            try:
                for binding in edge_bindings:
                    self._nsxv.delete_bgp_peer_config(binding['edge_id'],
                                                      bgp_peer_obj)
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Failed to delete BGP peer"
                                      " for %s"), binding['edge_id'])
        super(NsxvBGPDriver, self).remove_bgp_peer(context, bgp_speaker_id,
                                                   bgp_peer_info)

    def add_bgp_speaker_to_dragent(self, context, agent_id, speaker_id):
        err_msg = _("NSX BGP is an agentless driver")
        raise n_exc.InvalidInput(error_message=err_msg)

    def remove_bgp_speaker_from_dragent(self, context, agent_id, speaker_id):
        err_msg = _("NSX BGP is an agentless driver")
        raise n_exc.InvalidInput(error_message=err_msg)

    def list_bgp_speaker_on_dragent(self, context, agent_id):
        err_msg = _("NSX BGP is an agentless driver")
        raise n_exc.InvalidInput(error_message=err_msg)

    def list_dragent_hosting_bgp_speaker(self, context, speaker_id):
        err_msg = _("NSX BGP is an agentless driver")
        raise n_exc.InvalidInput(error_message=err_msg)

    def add_gateway_network(self, context, bgp_speaker_id, network_info):
        gateway_network_id = network_info['network_id']
        bgp_speaker_info = self.get_bgp_speaker(context, bgp_speaker_id)

        # Validate if the network can be added to the bgp speaker
        if gateway_network_id in bgp_speaker_info['networks']:
            msg = (_("The network %s has been added to bgp speaker") %
                   gateway_network_id)
            raise n_exc.BadRequest(resource='BGPSpeaker', msg=msg)

        if bgp_speaker_info['networks']:
            msg = _("The NSX backend only supports one network added to"
                    " bgp speaker")
            raise n_exc.BadRequest(resource='BGPSpeaker', msg=msg)

        # Enable BGP configuration on service edge backend
        edge_router_list = self._get_dynamic_routing_edge_list(
                context, gateway_network_id)
        bgp_peers = self.get_bgp_peers_by_bgp_speaker(context,
                                                      bgp_speaker_id)
        try:
            for edge_router_config in edge_router_list:
                edge_id = edge_router_config['edge_id']
                router_ids = edge_router_config['router_id_list']
                LOG.debug('Enable BGP dynamic routing for %(edge_id)s with'
                          ' global router id %(router_id)s.',
                          {'edge_id': edge_id, 'router_id': router_ids})

                fips, subnets = self._query_fips_and_tenant_subnets(
                        context, gateway_network_id, router_ids)
                self._nsxv.add_bgp_speaker_config(edge_id,
                                                  router_ids,
                                                  bgp_speaker_info,
                                                  bgp_peers,
                                                  fips,
                                                  subnets)
                nsxv_db.add_nsxv_bgp_speaker_binding(context.session,
                                                     edge_id, bgp_speaker_id)
        except vcns_exc.VcnsApiException as e:
            raise e

        super(NsxvBGPDriver, self).add_gateway_network(context,
                                                       bgp_speaker_id,
                                                       network_info)

    def remove_gateway_network(self, context, bgp_speaker_id, network_info):
        edge_bindings = nsxv_db.get_nsxv_bgp_speaker_bindings(context.session,
                                                              bgp_speaker_id)
        if edge_bindings:
            for edge_binding in edge_bindings:
                self._nsxv.delete_bgp_speaker_config(edge_binding['edge_id'])
                nsxv_db.delete_nsxv_bgp_speaker_binding(
                    context.session, edge_binding['edge_id'], bgp_speaker_id)
        super(NsxvBGPDriver, self).remove_gateway_network(context,
                                                          bgp_speaker_id,
                                                          network_info)
