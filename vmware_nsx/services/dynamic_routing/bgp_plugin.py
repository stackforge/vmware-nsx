# Copyright 2017 VMware, Inc.
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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.services import service_base
from neutron_lib import context as n_context
from neutron_dynamic_routing.db import bgp_db
from neutron_dynamic_routing.extensions import bgp as bgp_ext

from vmware_nsx.services.dynamic_routing.nsx_v import driver as nsxv_driver

PLUGIN_NAME = bgp_ext.BGP_EXT_ALIAS + '_nsx_svc_plugin'
LOG = logging.getLogger(__name__)


class BgpPluginBase(service_base.ServicePluginBase,
                    bgp_db.BgpDbMixin):

    supported_extension_aliases = [bgp_ext.BGP_EXT_ALIAS, ]

    def __init__(self, nsx_driver):
        super(BgpPluginBase, self).__init__()
        self.nsx_driver = nsx_driver
        self._register_callbacks()

    def get_plugin_name(self):
        return PLUGIN_NAME

    def get_plugin_type(self):
        return bgp_ext.BGP_EXT_ALIAS

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("BGP dynamic routing service for announcement of next-hops "
                "for project networks, floating IP's, and DVR host routes.")

    def _register_callbacks(self):
        registry.subscribe(self.router_interface_callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_CREATE)
        registry.subscribe(self.router_interface_callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_DELETE)
        registry.subscribe(self.router_gateway_callback,
                           resources.ROUTER_GATEWAY,
                           events.AFTER_CREATE)
        registry.subscribe(self.router_gateway_callback,
                           resources.ROUTER_GATEWAY,
                           events.AFTER_DELETE)

    def create_bgp_speaker(self, context, bgp_speaker):
        self.nsx_driver.create_bgp_speaker(context, bgp_speaker)
        return super(BgpPluginBase, self).create_bgp_speaker(context,
                                                             bgp_speaker)

    def update_bgp_speaker(self, context, bgp_speaker_id, bgp_speaker):
        self.nsx_driver.update_bgp_speaker(context,
                                           bgp_speaker_id,
                                           bgp_speaker)
        return super(BgpPluginBase, self).update_bgp_speaker(
            context, bgp_speaker_id, bgp_speaker)

    def delete_bgp_speaker(self, context, bgp_speaker_id):
        self.nsx_driver.delete_bgp_speaker(context, bgp_speaker_id)
        super(BgpPluginBase, self).delete_bgp_speaker(context, bgp_speaker_id)

    def create_bgp_peer(self, context, bgp_peer):
        self.nsx_driver.create_bgp_peer(context, bgp_peer)
        return super(BgpPluginBase, self).create_bgp_peer(context, bgp_peer)

    def update_bgp_peer(self, context, bgp_peer_id, bgp_peer):
        self.nsx_driver.update_bgp_peer(context, bgp_peer_id, bgp_peer)
        return super(BgpPluginBase, self).update_bgp_peer(context,
                                                          bgp_peer_id,
                                                          bgp_peer)

    def delete_bgp_peer(self, context, bgp_peer_id):
        self.nsx_driver.delete_bgp_peer(context, bgp_peer_id)
        super(BgpPluginBase, self).delete_bgp_peer(context, bgp_peer_id)

    def add_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        ret_value = super(BgpPluginBase, self).add_bgp_peer(context,
                                                            bgp_speaker_id,
                                                            bgp_peer_info)
        self.nsx_driver.add_bgp_peer(context, bgp_speaker_id, bgp_peer_info)
        return ret_value

    def remove_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        self.nsx_driver.remove_bgp_peer(context, bgp_speaker_id, bgp_peer_info)
        ret_value = super(BgpPluginBase, self).remove_bgp_peer(context,
                                                               bgp_speaker_id,
                                                               bgp_peer_info)
        return ret_value

    def add_gateway_network(self, context, bgp_speaker_id, network_info):
        super(BgpPluginBase, self).add_gateway_network(context,
                                                       bgp_speaker_id,
                                                       network_info)
        self.nsx_driver.add_gateway_network(context,
                                            bgp_speaker_id,
                                            network_info)

    def remove_gateway_network(self, context, bgp_speaker_id, network_info):
        super(BgpPluginBase, self).remove_gateway_network(
            context, bgp_speaker_id, network_info)
        self.nsx_driver.remove_gateway_network(context,
                                               bgp_speaker_id,
                                               network_info)

    def get_advertised_routes(self, context, bgp_speaker_id):
        return super(BgpPluginBase, self).get_advertised_routes(
            context, bgp_speaker_id)

    def router_interface_callback(self, resource, event, trigger, **kwargs):
        context = n_context.get_admin_context()
        if not kwargs['network_id']:
            # No GW network, hence no BGP speaker associated
            return

        router_id = kwargs['router_id']
        subnet_id = kwargs.get('interface_info', {}).get('subnet_id')
        subnets = kwargs.get('subnets')

        speakers = self._bgp_speakers_for_gateway_network(context,
                                                          kwargs['network_id'])
        for speaker in speakers:
            if event == events.AFTER_CREATE:
                self.nsx_driver.advertise_subnet(speaker.id, router_id,
                                                 subnets[0])
            if event == events.AFTER_DELETE:
                self.nsx_driver.withdraw_subnet(speaker.id, router_id,
                                                subnet_id)

    def router_gateway_callback(self, resource, event, trigger, **kwargs):
        context = n_context.get_admin_context()
        router_id = kwargs['router_id']
        gw_ips = kwargs.get('gateway_ips')
        speakers = self._bgp_speakers_for_gateway_network(context,
                                                          kwargs['network_id'])
        for speaker in speakers:
            if event == events.AFTER_CREATE:
                self.nsx_driver.enable_bgp_on_router(speaker, router_id)
            if event == events.AFTER_DELETE:
                self.nsx_driver.disable_bgp_on_router(speaker,
                                                      router_id,
                                                      gw_ips[0])


class NSXvBgpPlugin(BgpPluginBase):
    def __init__(self):
        super(NSXvBgpPlugin, self).__init__(nsxv_driver.NSXvBgpDriver(self))
