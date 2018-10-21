# Copyright 2017 VMware, Inc.
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

from neutron_lib.exceptions import firewall_v1 as exceptions
from neutron_lib.plugins import directory
from oslo_log import log as logging

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.nsx_v.vshield import edge_utils

LOG = logging.getLogger(__name__)
RULE_NAME_PREFIX = 'Fwaas-'

try:
    from neutron_fwaas.services.firewall.service_drivers.agents.drivers \
        import fwaas_base
except ImportError:
    # FWaaS project no found
    from vmware_nsx.services.fwaas.common import fwaas_mocks \
        as fwaas_base


class EdgeFwaasDriverBase(fwaas_base.FwaasDriverBase):
    """NSX-V driver for Firewall As A Service - V1/V2."""

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
            if self._core_plugin.is_tvd_plugin():
                self._core_plugin = self._core_plugin.get_plugin_by_type(
                    projectpluginmap.NsxPlugins.NSX_V)
            # make sure plugin init was completed
            if not self._core_plugin.init_is_complete:
                self._core_plugin.init_complete(None, None, {})
        return self._core_plugin

    @property
    def edge_manager(self):
        return self.core_plugin.edge_manager

    def __init__(self):
        super(EdgeFwaasDriverBase, self).__init__()
        self._core_plugin = None

    def should_apply_firewall_to_router(self, router_data,
                                        raise_exception=True):
        """Return True if the firewall rules should be added the router

        Return False in those cases:
        - router without an external gateway (rule may be added later when
                                              there is a gateway)

        Raise an exception if the router is unsupported
        (and raise_exception is True):
        - shared router (not supported)
        - md proxy router (not supported)

        """
        if (not router_data.get('distributed') and
            router_data.get('router_type') == 'shared'):
            LOG.error("Cannot apply firewall to shared router %s",
                      router_data['id'])
            if raise_exception:
                # DEBUG ADIT replace with the right type of exception
                raise exceptions.FirewallInternalDriverError(
                    driver=self.driver_name)
            return False

        if router_data.get('name', '').startswith('metadata_proxy_router'):
            LOG.error("Cannot apply firewall to the metadata proxy router %s",
                      router_data['id'])
            if raise_exception:
                raise exceptions.FirewallInternalDriverError(
                    driver=self.driver_name)
            return False

        if not router_data.get('external_gateway_info'):
            LOG.info("Cannot apply firewall to router %s with no gateway",
                     router_data['id'])
            return False

        return True

    def _get_routers_edges(self, context, apply_list, delete_fw=False):
        # Get edges for all the routers in the apply list.
        # note that shared routers are currently not supported
        edge_manager = self.edge_manager
        edges_map = {}
        for router_info in apply_list:

            # No FWaaS rules needed if there is no external gateway
            if not self.should_apply_firewall_to_router(
                router_info.router, raise_exception=(not delete_fw)):
                continue

            lookup_id = None
            router_id = router_info.router_id
            if router_info.router.get('distributed'):
                # Distributed router
                # we need the plr edge id
                lookup_id = edge_manager.get_plr_by_tlr_id(
                    context, router_id)
            else:
                # Exclusive router
                lookup_id = router_id
            if lookup_id:
                # look for the edge id in the DB
                edge_id = edge_utils.get_router_edge_id(context, lookup_id)
                if edge_id:
                    edges_map[router_id] = {'edge_id': edge_id,
                                            'lookup_id': lookup_id}
        return edges_map

    def _translate_rules(self, fwaas_rules, logged=False):
        # DEBUG ADIT - support v2 rules too?
        translated_rules = []
        for rule in fwaas_rules:
            if not rule['enabled']:
                # skip disabled rules
                continue
            # Make sure the rule has a name, and it starts with the prefix
            # (backend max name length is 30)
            if rule.get('name'):
                rule['name'] = RULE_NAME_PREFIX + rule['name']
            else:
                rule['name'] = RULE_NAME_PREFIX + rule['id']
            rule['name'] = rule['name'][:30]
            # source & destination should be lists
            if rule.get('destination_ip_address'):
                rule['destination_ip_address'] = [
                    rule['destination_ip_address']]
            if rule.get('source_ip_address'):
                rule['source_ip_address'] = [rule['source_ip_address']]
            if logged:
                rule['logged'] = True
            translated_rules.append(rule)

        return translated_rules
