#    Copyright 2015 VMware, Inc.
#    All Rights Reserved.
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
#    under the License

from oslo_log import log as logging
from oslo_utils import excutils
from neutron import manager
from neutron.common import exceptions as n_exc

from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx._i18n import _, _LE
from vmware_nsx.plugins.nsx_v.vshield import edge_utils
from vmware_nsx.plugins.nsx_v.vshield import edge_ipsecvpn_driver
from vmware_nsx.plugins.nsx_v.vshield import edge_firewall_driver
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as vcns_exc
from vmware_nsx.services.vpnaas.nsxv import vpnaas_validator

LOG = logging.getLogger(__name__)


class EdgeVPNDriver(object):

    def __init__(self, service_plugin):
        self.vpn_plugin = service_plugin
        self.validator = vpnaas_validator.VpnValidator(service_plugin)

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    @property
    def vcns(self):
        return self._core_plugin.nsx_v.vcns

    def _get_edge_id(self, context, ipsec_site_connection):
        conn_info = ipsec_site_connection
        vpnservice = self.vpn_plugin._get_vpnservice(
            context, conn_info['vpnservice_id'])

        router_id = vpnservice['router_id']
        edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                       router_id)
        if edge_binding['edge_type'] == nsxv_constants.VDR_EDGE:
            # Get plr edge_id
            plr_id = (self._core_plugin.edge_manager.
                      get_plr_by_tlr_id(context, router_id))
            binding = nsxv_db.get_nsxv_router_binding(context.session, plr_id)
            edge_id = binding['edge_id']
        else:
            # Get exclusive edge id
            edge_id = edge_binding['edge_id']
        return edge_id

    def _convert_ipsec_conn(self, context, ipsec_site_connection):
        conn_info = ipsec_site_connection
        ipsecpolicy = self.vpn_plugin.get_ipsecpolicy(context,
                                        conn_info['ipsecpolicy_id'])
        vpnservice = self.vpn_plugin._get_vpnservice(
            context, conn_info['vpnservice_id'])
        local_cidr = vpnservice['subnet']['cidr']
        router_id = vpnservice['router_id']
        router = self._get_router(context, router_id)
        local_addr = (router['external_gateway_info']['external_fixed_ips']
                      [0]["ip_address"])

        edge_id = self._get_edge_id(context, conn_info)
        site = {
            'enabled': True,
            'enablePfs': True,
            'dhGroup': nsxv_constants.PFS_MAP.get(ipsecpolicy.get('pfs')),
            'name': conn_info.get('name'),
            'description': conn_info.get('description'),
            'localId': local_addr,
            'localIp': local_addr,
            'peerId': conn_info['peer_id'],
            'peerIp': conn_info.get('peer_address'),
            'localSubnets': {
                'subnets': [local_cidr]},
            'peerSubnets': {
                'subnets': conn_info.get('peer_cidrs')},
            'authenticationMode': conn_info.get('auth_mode'),
            'psk': conn_info.get('psk'),
            'encryptionAlgorithm': (nsxv_constants.
                                    ENCRYPTION_ALGORITHM_MAP.get(
                                    ipsecpolicy.get('encryption_algorithm')))}
        return site

    def _generate_new_sites(self, edge_id, ipsec_site_conn):
        # Fetch the previous ipsec vpn configuration
        ipsecvpn__configs = self.get_ipsec_config(edge_id)
        vse_sites = []
        if ipsecvpn__configs[1]['enabled']:
            vse_sites = ([site for site
                          in ipsecvpn__configs[1]['sites']['sites']])
        vse_sites.append(ipsec_site_conn)
        return vse_sites

    def _generate_new_firewall(self, edge_id, peersubnets):
        edge_firewall_driver = edge_firewall_driver.EdgeFirewallDriver()
        ipsec_vpn_fw_rules = edge_firewall_driver.get_firewall(context,
                                                               edge_id)
        ipsec_vpn_fw_rules['firewall_rule_list'].append({
                    'action': 'allow',
                    'enabled': True,
                    'source_vnic_groups': ["external"],
                    'destination_ip_address': peersubnets})

    def _update_firewall_rule(self, context, router_id, edge_id):
        edge_firewall_driver = edge_firewall_driver.EdgeFirewallDriver()
        ipsec_vpn_fw_rules = edge_firewall_driver.get_firewall(context,
                                                               edge_id)
        ipsec_vpn_fw_rules.append({
                    'action': 'allow',
                    'enabled': True,
                    'source_vnic_groups': ["external"],
                    'destination_ip_address': new_ipsec['peerSubnets']})
        try:
            edge_utils.update_firewall(self.plugin.nsx_v, context, router_id,
                                {'firewall_rule_list': ipsec_vpn_fw_rules},
                                allow_external=False)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update firewall rule "
                                  "for ipsec vpn with %(edge_id)s."),
                                  {'edge_id': edge_id})

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        LOG.debug('Creating ipsec site connection %s', ipsec_site_connection)
        conn_info = ipsec_site_connection
        vpnservice = self.vpn_plugin._get_vpnservice(
            context, conn_info['vpnservice_id'])
        router_id = vpnservice['router_id']
        edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                       router_id)
        if edge_binding['edge_type'] == nsxv_constants.VDR_EDGE:
            router_id = self.edge_manager.get_plr_by_tlr_id(context,
                                                            router_id)

        self.validator.validate_ipsec_connn(context, conn_info)
        new_ipsec = self._convert_ipsec_conn(context, conn_info)
        edge_id = self._get_edge_id(context, conn_info)
        # Fetch the previous ipsec vpn configuration
        ipsecvpn__configs = self.get_ipsec_config(edge_id)
        vse_sites = self._generate_new_sites(edge_id, new_ipsec)

        try:
            self.update_ipsec_config(edge_id, vse_sites, enabled=True)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to create ipsec site connection "
                                  "configuration with %(edge_id)s."),
                                  {'edge_id': edge_id})
                # Rolling back change on the neutron
                self.vpn_plugin.delete_ipsec_site_connection(context,
                                                     conn_info.get("id"))
        try:
            self._update_firewall_rule(context, router_id, edge_id)
        except vcns_exc.VcnsApiException:
                self.vpn_plugin.delete_ipsec_site_connection()

    def get_ipsec_config(self, edge_id):
        return self.vcns.get_ipsec_config(edge_id)

    def _delete_site_dict(self, edge_id, site):
        # Fetch the previous ipsec vpn configuration
        ipsecvpn__configs = self.get_ipsec_config(edge_id)[1]
        if ipsecvpn__configs['enabled']:
            vse_sites = ([site for site in
                          ipsecvpn__configs['sites']['sites']])
            for s in vse_sites:
                if s == site:
                    vse_sites.remove(s)
                    break
            return vse_sites

    def delete_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Deleting ipsec site connection %s', ipsec_site_conn)
        del_site = self._convert_ipsec_conn(context, ipsec_site_conn)
        edge_id = self._get_edge_id(context, ipsec_site_conn)
        vse_sites = self._delete_site_dict(edge_id, del_site)
        if vse_sites:
            try:
                self.update_ipsec_config(edge_id, vse_sites)
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Failed to delete ipsec site connection"
                                      " configuration with edge_id:"
                                      "%(edge_id)s."),
                                      {'egde_id': edge_id})

    def update_ipsec_site_connection(self, context, old_ipsec_id,
                                     ipsec_site_connection):
        LOG.debug('Updating ipsec site connection %s', ipsec_site_connection)
        conn_info = self.vpn_plugin.get_ipsec_site_connection(old_ipsec_id)
        edge_id = self._get_edge_id(context, conn_info)
        old_site = self._convert_ipsec_conn(context, conn_info)

        if ipsec_site_connection['peer_address'] != old_site['peerIp']:
            vse_sites = self._delete_site_dict(edge_id, old_site)
            old_site['peerIp'] = ipsec_site_connection['peer_address']

        if (ipsec_site_connection['peer_cidrs'] !=
            old_site['peerSubnets']['subnets']):
            vse_sites = self._delete_site_dict(edge_id, old_site)
            old_site['peerSubnets'] = ipsec_site_connection['peer_cidrs']
            # Update firewall

            try:
                firewall_driver = edge_firewall_driver.EdgeFirewallDriver()
                ipsec_vpn_fw_rules = firewall_driver.get_firewall(context,
                                                                  edge_id)
                ipsec_vpn_fw_rules.append({
                    'action': 'allow',
                    'enabled': True,
                    'source_vnic_groups': ["external"],
                    'destination_ip_address':
                ipsec_site_connection['peer_cidrs']})
                edge_utils.update_firewall(self.plugin.nsx_v, context,
                                           router_id,
                                           {'firewall_rule_list':
                                            ipsec_vpn_fw_rules},
                                            allow_external=False)
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Failed to update firewall rule "
                                      "for ipsec vpn with %(edge_id)s."),
                                      {'edge_id': edge_id})

    def _get_router(self, context, router_id):
        router = self._core_plugin.get_router(context, router_id)
        ex_type = nsxv_constants.EXCLUSIVE
        if router.get('distributed') or router.get('router_type') == ex_type:
            LOG.debug('Router type')
            return router
        else:
            return False

    def create_vpnservice(self, context, vpnservice):
        LOG.debug('Creating VPN service %s', vpnservice)
        # Only support distributed and exclusive router type
        router_id = vpnservice['router_id']
        vpnservice_id = vpnservice['id']
        if not self._get_router(context, router_id):
             # Rolling back change on the neutron
            self.vpn_plugin.delete_vpnservice(context, vpnservice_id)
            msg = _("Router type is not supported for VPN service, only"
                    "support distributed and exclusive router")
            raise n_exc.InvalidInput(error_message=msg)

    def update_ipsec_config(self, edge_id, sites, enabled=True):
        ipsec_config = {'featureType': "ipsec_4.0",
                        'enabled': enabled}

        ipsec_config['sites'] = {'sites': sites}
        try:
            self.vcns.update_ipsec_config(edge_id, ipsec_config)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update ipsec vpn "
                                  "configuration with edge_id: %s"),
                              edge_id)

    def delete_ipsec_config(self, edge_id):
        try:
            self.vcns.delete_ipsec_config(edge_id)
        except vcns_exc.ResourceNotFound:
            LOG.warning(_LW("IPsec config not found on edge: %s"), edge_id)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to delete ipsec vpn configuration "
                                  "with edge_id: %s"), edge_id)