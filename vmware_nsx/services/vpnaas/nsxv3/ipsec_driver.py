# Copyright 2017 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import netaddr
from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn import service_drivers
from oslo_log import log as logging

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_validator

LOG = logging.getLogger(__name__)
IPSEC = 'ipsec'


class NSXv3IPsecVpnDriver(service_drivers.VpnDriver):

    def __init__(self, service_plugin):
        self.vpn_plugin = service_plugin
        self._core_plugin = directory.get_plugin()
        self._nsxlib = self._core_plugin.nsxlib
        self._nsx_vpn = self._nsxlib.vpn_ipsec
        validator = ipsec_validator.IPsecV3Validator(service_plugin)
        super(NSXv3IPsecVpnDriver, self).__init__(service_plugin, validator)

    @property
    def l3_plugin(self):
        return self._core_plugin

    @property
    def service_type(self):
        return IPSEC

    def _convert_ipsec_conn(self, context, ipsec_site_connection):
        #ipsec_id = ipsec_site_connection['ipsecpolicy_id']
        vpnservice_id = ipsec_site_connection['vpnservice_id']
        #ipsecpolicy = self.service_plugin.get_ipsecpolicy(context, ipsec_id)
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        local_cidr = vpnservice['subnet']['cidr']
        router_id = vpnservice['router_id']
        router = self._core_plugin.get_router(context, router_id)
        local_addr = (router['external_gateway_info']['external_fixed_ips']
                      [0]["ip_address"])
        #encrypt = nsxv_constants.ENCRYPTION_ALGORITHM_MAP.get(
        #    ipsecpolicy.get('encryption_algorithm'))
        site = {
            'enabled': True,
            'enablePfs': True,
            #'dhGroup': nsxv_constants.PFS_MAP.get(ipsecpolicy.get('pfs')),
            'name': ipsec_site_connection.get('name'),
            'description': ipsec_site_connection.get('description'),
            'localId': local_addr,
            'localIp': local_addr,
            'peerId': ipsec_site_connection['peer_id'],
            'peerIp': ipsec_site_connection.get('peer_address'),
            'localSubnets': {
                'subnets': [local_cidr]},
            'peerSubnets': {
                'subnets': ipsec_site_connection.get('peer_cidrs')},
            'authenticationMode': ipsec_site_connection.get('auth_mode'),
            'psk': ipsec_site_connection.get('psk'),
            #'encryptionAlgorithm': encrypt
        }
        return site

    def _generate_ipsecvpn_firewall_rules(self, router_id):
        # Firewall rules to allow vpn traffic if fwaas is enabled
        # DEBUG ADIT todo
        # ipsecvpn_configs = self._get_ipsec_config(edge_id)
        # ipsec_vpn_fw_rules = []
        # if ipsecvpn_configs[1]['enabled']:
        #     for site in ipsecvpn_configs[1]['sites']['sites']:
        #         peer_subnets = site['peerSubnets']['subnets']
        #         local_subnets = site['localSubnets']['subnets']
        #         ipsec_vpn_fw_rules.append({
        #             'name': 'VPN ' + site['name'],
        #             'action': 'allow',
        #             'enabled': True,
        #             'source_ip_address': peer_subnets,
        #             'destination_ip_address': local_subnets})
        # return ipsec_vpn_fw_rules
        return []

    def _update_firewall_rules(self, context, vpnservice_id):
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        LOG.debug("Updating vpn firewall rules for router %s",
            vpnservice['router_id'])
        self._core_plugin.update_router_firewall(
            context, vpnservice['router_id'])

    def _update_status(self, context, vpn_service_id, ipsec_site_conn_id,
                       status, updated_pending_status=True):
        status_list = []
        vpn_status = {}
        ipsec_site_conn = {}
        vpn_status['id'] = vpn_service_id
        vpn_status['updated_pending_status'] = updated_pending_status
        vpn_status['status'] = status
        ipsec_site_conn['status'] = status
        ipsec_site_conn['updated_pending_status'] = updated_pending_status
        vpn_status['ipsec_site_connections'] = {ipsec_site_conn_id:
                                                ipsec_site_conn}
        status_list.append(vpn_status)
        self.service_plugin.update_status_by_agent(context, status_list)

    def _create_ike_profile(self, context, connection):
        ike_policy_id = connection['ikepolicy_id']
        ikepolicy = self.vpn_plugin.get_ikepolicy(context, ike_policy_id)

        try:
            profile = self._nsx_vpn.ike_profile.create(
                ikepolicy['name'],
                description=ikepolicy['description'],
                encryption_algorithm=ipsec_utils.ENCRYPTION_ALGORITHM_MAP[
                    ikepolicy['encryption_algorithm']],
                digest_algorithm=ipsec_utils.AUTH_ALGORITHM_MAP[
                    ikepolicy['auth_algorithm']],
                ike_version=ipsec_utils.IKE_VERSION_MAP[
                    ikepolicy['ike_version']],
                #pfs=None,
                #dh_group=None,
                sa_life_time=ikepolicy['lifetime']['value'])
        except Exception as e:
            # TODO(asarfaty): fix exception handling
            msg = _("Failed to create ike profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return profile['id']

    def _delete_ike_profile(self, context, ikeprofile_id):
        pass

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        LOG.debug('Creating ipsec site connection %(conn_info)s.',
                  {"conn_info": ipsec_site_connection})

        # create the ike profile to match the ike policy of the connection
        ikeprofile_id = self._create_ike_profile(
            context, ipsec_site_connection)
        LOG.debug("Created ike profile %s", ikeprofile_id)

        #new_ipsec = self._convert_ipsec_conn(context, ipsec_site_connection)
        # DEBUG ADIT todo: update the backend
        vpnservice_id = ipsec_site_connection['vpnservice_id']
        ipsec_id = ipsec_site_connection["id"]
        self._update_status(context, vpnservice_id, ipsec_id, "ACTIVE")

    def delete_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Deleting ipsec site connection %(site)s.',
                  {"site": ipsec_site_conn})

        # get all data from the nsx based on the id in the DB
        # delete the connection amnd all related profiles/endpoints
        #ipsec_id = ipsec_site_conn['id']
        # DEBUG ADIT todo delete from backend
        self._update_firewall_rules(context,
                                    ipsec_site_conn['vpnservice_id'])

    def update_ipsec_site_connection(self, context, old_ipsec_conn,
                                     ipsec_site_connection):
        LOG.debug('Updating ipsec site connection %(site)s.',
                  {"site": ipsec_site_connection})
        vpnservice_id = old_ipsec_conn['vpnservice_id']
        #ipsec_id = old_ipsec_conn['id']
        # DEBUG ADIT update backend !

        if 'peer_cidrs' in ipsec_site_connection:
            # Update firewall
            self._update_firewall_rules(context, vpnservice_id)

    def _get_gateway_ips(self, router):
        """Obtain the IPv4 and/or IPv6 GW IP for the router.

        If there are multiples, (arbitrarily) use the first one.
        """
        v4_ip = v6_ip = None
        for fixed_ip in router.gw_port['fixed_ips']:
            addr = fixed_ip['ip_address']
            vers = netaddr.IPAddress(addr).version
            if vers == 4:
                if v4_ip is None:
                    v4_ip = addr
            elif v6_ip is None:
                v6_ip = addr
        return v4_ip, v6_ip

    def create_vpnservice(self, context, vpnservice):
        # DEBUG ADIT do not allow subnet here?
        LOG.debug('Creating VPN service %(vpn)s', {'vpn': vpnservice})
        #router_id = vpnservice['router_id']
        #router = self._core_plugin.get_router(context, router_id)
        vpnservice_id = vpnservice['id']
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        v4_ip, v6_ip = self._get_gateway_ips(vpnservice.router)
        if v4_ip:
            vpnservice['external_v4_ip'] = v4_ip
        if v6_ip:
            vpnservice['external_v6_ip'] = v6_ip
        self.service_plugin.set_external_tunnel_ips(context,
                                                    vpnservice_id,
                                                    v4_ip=v4_ip, v6_ip=v6_ip)

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        pass

    def delete_vpnservice(self, context, vpnservice):
        pass
