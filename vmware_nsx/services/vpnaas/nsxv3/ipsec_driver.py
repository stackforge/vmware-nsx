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
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn import service_drivers

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_validator
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import vpn_ipsec

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

    def _convert_ipsec_conn(self, context, ipsec_site_conn):
        #ipsec_id = ipsec_site_conn['ipsecpolicy_id']
        vpnservice_id = ipsec_site_conn['vpnservice_id']
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
            'name': ipsec_site_conn.get('name'),
            'description': ipsec_site_conn.get('description'),
            'localId': local_addr,
            'localIp': local_addr,
            'peerId': ipsec_site_conn['peer_id'],
            'peerIp': ipsec_site_conn.get('peer_address'),
            'localSubnets': {
                'subnets': [local_cidr]},
            'peerSubnets': {
                'subnets': ipsec_site_conn.get('peer_cidrs')},
            'authenticationMode': ipsec_site_conn.get('auth_mode'),
            'psk': ipsec_site_conn.get('psk'),
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
                dh_group=ipsec_utils.PFS_MAP[ikepolicy['pfs']],
                pfs=True,
                sa_life_time=ikepolicy['lifetime']['value'])
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create an ike profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return profile['id']

    def _delete_ike_profile(self, ikeprofile_id):
        self._nsx_vpn.ike_profile.delete(ikeprofile_id)

    def _create_ipsec_profile(self, context, connection):
        ipsec_policy_id = connection['ipsecpolicy_id']
        ipsecpolicy = self.vpn_plugin.get_ipsecpolicy(
            context, ipsec_policy_id)

        try:
            profile = self._nsx_vpn.tunnel_profile.create(
                ipsecpolicy['name'],
                description=ipsecpolicy['description'],
                encryption_algorithm=ipsec_utils.ENCRYPTION_ALGORITHM_MAP[
                    ipsecpolicy['encryption_algorithm']],
                digest_algorithm=ipsec_utils.AUTH_ALGORITHM_MAP[
                    ipsecpolicy['auth_algorithm']],
                dh_group=ipsec_utils.PFS_MAP[ipsecpolicy['pfs']],
                pfs=True,
                sa_life_time=ipsecpolicy['lifetime']['value'])
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a tunnel profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return profile['id']

    def _delete_ipsec_profile(self, ipsecprofile_id):
        self._nsx_vpn.tunnel_profile.delete(ipsecprofile_id)

    def _create_dpd_profile(self, connection):
        dpd_info = connection['dpd']
        try:
            profile = self._nsx_vpn.dpd_profile.create(
                connection['name'][:240] + '-dpd-profile',
                description='neutron dpd profile',
                timeout=dpd_info.get('timeout'),
                enabled=True if dpd_info.get('action') == 'hold' else False)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a DPD profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return profile['id']

    def _delete_dpd_profile(self, dpdprofile_id):
        self._nsx_vpn.dpd_profile.delete(dpdprofile_id)

    def _update_dpd_profile(self, connection, dpdprofile_id):
        dpd_info = connection['dpd']
        self._nsx_vpn.dpd_profile.update(dpdprofile_id,
                timeout=dpd_info.get('timeout'),
                enabled=True if dpd_info.get('action') == 'hold' else False)

    def _create_peer_endpoint(self, connection, ikeprofile_id,
                              ipsecprofile_id, dpdprofile_id):
        default_auth = vpn_ipsec.AuthenticationModeTypes.AUTH_MODE_PSK
        try:
            peer_endpoint = self._nsx_vpn.peer_endpoint.create(
                connection['name'],
                connection['peer_address'],
                connection['peer_id'],
                description=connection['description'],
                authentication_mode=default_auth,
                dpd_profile_id=dpdprofile_id,
                ike_profile_id=ikeprofile_id,
                ipsec_tunnel_profile_id=ipsecprofile_id,
                connection_initiation_mode=ipsec_utils.INITIATION_MODE_MAP[
                    connection['initiator']],
                psk=connection['psk'])
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a peer endpoint: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return peer_endpoint['id']

    def _delete_peer_endpoint(self, peer_ep_id):
        self._nsx_vpn.peer_endpoint.delete(peer_ep_id)

    def _get_profiles_from_peer_endpoint(self, peer_ep_id):
        peer_ep = self._nsx_vpn.peer_endpoint.get(peer_ep_id)
        return (
            peer_ep['ike_profile_id'],
            peer_ep['ipsec_tunnel_profile_id'],
            peer_ep['dpd_profile_id'])

    def _create_local_endpoint(self, context, connection, vpnservice_id):
        #TODO(asarfaty): support certificate in local endpoints?
        # use the service subnet as the local ip or the connection peer-address
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)
        local_addr = self._get_router_ext_gw(context, vpnservice['router'])
        nsx_service_id = self._get_nsx_vpn_service(context, vpnservice_id)
        try:
            local_endpoint = self._nsx_vpn.local_endpoint.create(
                connection['name'],
                local_addr,
                nsx_service_id,
                description=connection['description'])
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a local endpoint: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return local_endpoint['id']

    def _delete_local_endpoint(self, local_ep_id):
        self._nsx_vpn.local_endpoint.delete(local_ep_id)

    def create_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Creating ipsec site connection %(conn_info)s.',
                  {"conn_info": ipsec_site_conn})
        # Note(asarfaty) the plugin already calls the validator
        # which also validated the policies and service

        ikeprofile_id = None
        ipsecprofile_id = None
        dpdprofile_id = None
        peer_ep_id = None
        local_ep_id = None
        vpnservice_id = ipsec_site_conn['vpnservice_id']
        ipsec_id = ipsec_site_conn["id"]

        try:
            # create the ike profile
            ikeprofile_id = self._create_ike_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX ike profile %s", ikeprofile_id)

            # create the ipsec profile
            ipsecprofile_id = self._create_ipsec_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX ipsec profile %s", ipsecprofile_id)

            # create the dpd profile
            dpdprofile_id = self._create_dpd_profile(
                ipsec_site_conn)
            LOG.debug("Created NSX dpd profile %s", dpdprofile_id)

            # create the peer endpoint and add to the DB
            peer_ep_id = self._create_peer_endpoint(
                ipsec_site_conn,
                ikeprofile_id, ipsecprofile_id, dpdprofile_id)
            LOG.debug("Created NSX peer endpoint %s", peer_ep_id)

            # DEBUG ADIT - the session should be in the DB, not the connection
            db.add_nsx_vpn_connection_mapping(
                context.session, ipsec_site_conn['id'], peer_ep_id)

            # create a local endpoint using the vpn service
            local_ep_id = self._create_local_endpoint(
                context, ipsec_site_conn, vpnservice_id)

            # Finally: create the session with policy rules
            # DEBUG ADIT not yet

            # create a IPSecVPNSession using both endpoints
            # (or PolicyBasedIPSecVPNSession with rules)

            self._update_status(context, vpnservice_id, ipsec_id, "ACTIVE")

        except nsx_exc.NsxPluginException:
            with excutils.save_and_reraise_exception():
                self._update_status(context, vpnservice_id, ipsec_id, "ERROR")

                # delete the NSX objects that were already created
                if local_ep_id:
                    self._delete_local_endpoint(local_ep_id)
                if peer_ep_id:
                    self._delete_peer_endpoint(peer_ep_id)
                if dpdprofile_id:
                    self._delete_dpd_profile(dpdprofile_id)
                if ipsecprofile_id:
                    self._delete_ipsec_profile(ipsecprofile_id)
                if ikeprofile_id:
                    self._delete_ike_profile(ikeprofile_id)

    def delete_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Deleting ipsec site connection %(site)s.',
                  {"site": ipsec_site_conn})

        # get all data from the nsx based on the id in the DB
        peer_ep_id = db.get_nsx_vpn_connection_mapping(
            context.session, ipsec_site_conn['id'])
        if not peer_ep_id:
            LOG.error("Couldn't find nsx-id for vpn connection %s",
                      ipsec_site_conn['id'])
            ipsec_id = ipsec_site_conn['id']
            vpnservice_id = ipsec_site_conn['vpnservice_id']
            self._update_status(context, vpnservice_id, ipsec_id, "ERROR")
            raise nsx_exc.NsxIPsecVpnMappingNotFound(conn=ipsec_id)

        (ikeprofile_id,
         ipsecprofile_id,
         dpdprofile_id) = self._get_profiles_from_peer_endpoint(peer_ep_id)

        # TODO(asarfaty) deattach router/subnet?

        # delete the connection and all related profiles/endpoints
        self._delete_peer_endpoint(peer_ep_id)
        if dpdprofile_id:
            self._delete_dpd_profile(dpdprofile_id)
        if ipsecprofile_id:
            self._delete_ipsec_profile(ipsecprofile_id)
        if ikeprofile_id:
            self._delete_ike_profile(ikeprofile_id)

        db.delete_nsx_vpn_connection_mapping(context.session,
                                             ipsec_site_conn['id'])
        # update router firewall rules
        self._update_firewall_rules(context,
                                    ipsec_site_conn['vpnservice_id'])

    def update_ipsec_site_connection(self, context, old_ipsec_conn,
                                     ipsec_site_conn):
        LOG.debug('Updating ipsec site connection new %(site)s.',
                  {"site": ipsec_site_conn})
        LOG.debug('Updating ipsec site connection old %(site)s.',
                  {"site": old_ipsec_conn})

        # Note(asarfaty) the plugin already calls the validator
        # which also validated the policies and service

        ipsec_id = old_ipsec_conn['id']
        vpnservice_id = old_ipsec_conn['vpnservice_id']
        peer_ep_id = db.get_nsx_vpn_connection_mapping(
            context.session, ipsec_site_conn['id'])
        if not peer_ep_id:
            LOG.error("Couldn't find nsx-id for vpn connection %s",
                      ipsec_site_conn['id'])
            self._update_status(context, vpnservice_id, ipsec_id, "ERROR")
            raise nsx_exc.NsxIPsecVpnMappingNotFound(conn=ipsec_id)

        # check if the dpd configuration changed
        old_dpd = old_ipsec_conn['dpd']
        new_dpd = ipsec_site_conn['dpd']
        if (old_dpd['action'] != new_dpd['action'] or
            old_dpd['timeout'] != new_dpd['timeout']):
            (dum1, dum2,
             dpd_profile_id) = self._get_profiles_from_peer_endpoint(
                peer_ep_id)
            self._update_dpd_profile(ipsec_site_conn, dpd_profile_id)

        # update endpoint with all the parameters that could be modified
        try:
            self._nsx_vpn.peer_endpoint.update(
                peer_ep_id,
                name=ipsec_site_conn['name'],
                description=ipsec_site_conn['description'],
                peer_address=ipsec_site_conn['peer_address'],
                peer_id=ipsec_site_conn['peer_id'],
                connection_initiation_mode=ipsec_utils.INITIATION_MODE_MAP[
                    ipsec_site_conn['initiator']],
                psk=ipsec_site_conn['psk'])
        except nsx_lib_exc.ManagerError as e:
            self._update_status(context, vpnservice_id, ipsec_id, "ERROR")
            msg = _("Failed to update peer endpoint: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        vpnservice_id = old_ipsec_conn['vpnservice_id']
        if 'peer_cidrs' in ipsec_site_conn:
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

    def _create_vpn_service(self, tier0_uuid):
        try:
            service = self._nsx_vpn.service.create(
                'Neutron VPN service for router ' + tier0_uuid,
                tier0_uuid,
                enabled=True,
                ike_log_level=ipsec_utils.DEFAULT_LOG_LEVEL)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create vpn service: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return service['id']

    def _get_tier0_uuid(self, context, router_id):
        router_db = self._core_plugin._get_router(context, router_id)
        return self._core_plugin._get_tier0_uuid_by_router(context, router_db)

    def _get_router_ext_gw(self, context, router_id):
        router_db = self._core_plugin._get_router(context, router_id)
        gw = router_db['external_gateway_info']
        return gw['external_fixed_ips'][0]["ip_address"]

    def _create_vpn_service_if_needed(self, context, vpnservice):
        # The service is created on the TIER0 router attached to the router GW
        # The NSX can keep only one service per tier0 router so we reuse it
        router_id = vpnservice['router_id']
        tier0_uuid = self._get_tier0_uuid(context, router_id)
        # check the DB if it already exists
        if db.get_nsx_vpn_service_mapping(context.session, tier0_uuid):
            return

        # create a new one and add to the DB
        service_id = self._create_vpn_service(tier0_uuid)
        db.add_nsx_vpn_service_mapping(context.session, tier0_uuid, service_id)

    def _get_nsx_vpn_service(self, context, vpnservice_id):
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        router_id = vpnservice['router_id']
        tier0_uuid = self._get_tier0_uuid(context, router_id)
        return db.get_nsx_vpn_service_mapping(context.session, tier0_uuid)

    def create_vpnservice(self, context, vpnservice):
        # DEBUG ADIT only support service with subnet here?
        LOG.debug('Creating VPN service %(vpn)s', {'vpn': vpnservice})
        self.validator.validate_vpnservice(context, vpnservice)
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
        self._create_vpn_service_if_needed(context, vpnservice)

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        # No meaningful field can change here
        pass

    def delete_vpnservice(self, context, vpnservice):
        # Do not delete the NSX service or DB entry as those will be reused.
        pass
