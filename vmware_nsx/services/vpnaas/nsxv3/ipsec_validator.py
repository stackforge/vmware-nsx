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

from neutron_vpnaas.db.vpn import vpn_validator

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils
from vmware_nsxlib.v3 import nsx_constants as consts
from vmware_nsxlib.v3 import vpn_ipsec

LOG = logging.getLogger(__name__)


class IPsecV3Validator(vpn_validator.VpnReferenceValidator):

    """Validator methods for Vmware NSX-V3 VPN support"""
    def __init__(self, service_plugin):
        super(IPsecV3Validator, self).__init__()
        self.vpn_plugin = service_plugin
        self.nsxlib = self.core_plugin.nsxlib
        self.check_backend_version()

    def check_backend_version(self):
        if not self.nsxlib.feature_supported(consts.FEATURE_IPSEC_VPN):
            # ipsec vpn is not supported
            LOG.warning("VPNaaS is not supported by the NSX backend (version "
                        "%s)",
                        self.nsxlib.get_version())
            self.backend_support = False
        else:
            self.backend_support = True

    def _validate_backend_version(self):
        if not self.backend_support:
            msg = (_("VPNaaS is not supported by the NSX backend "
                     "(version %s)") % self.nsxlib.get_version())
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def _validate_policy_lifetime(self, policy_info, policy_type):
        """NSX supports only units=seconds"""
        lifetime = policy_info.get('lifetime')
        if lifetime and lifetime.get('units') != 'seconds':
            msg = _("Unsupported policy lifetime %(val)s in %(pol)s policy. "
                    "Only seconds lifetime is supported.") % {
                        'val': lifetime, 'pol': policy_type}
            raise nsx_exc.NsxVpnValidationError(details=msg)
        value = lifetime.get('value')
        if (value and (value < vpn_ipsec.SALifetimeLimits.SA_LIFETIME_MIN or
            value > vpn_ipsec.SALifetimeLimits.SA_LIFETIME_MAX)):
            msg = _("Unsupported policy lifetime %(value)s in %(pol)s policy. "
                    "Value range is [%(min)s-%(max)s].") % {
                        'value': value,
                        'pol': policy_type,
                        'min': vpn_ipsec.SALifetimeLimits.SA_LIFETIME_MIN,
                        'max': vpn_ipsec.SALifetimeLimits.SA_LIFETIME_MAX}
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def _validate_policy_auth_algorithm(self, policy_info, policy_type):
        """NSX supports only SHA1 and SHA256"""
        auth = policy_info['auth_algorithm']
        if auth and auth not in ipsec_utils.AUTH_ALGORITHM_MAP:
            msg = _("Unsupported auth_algorithm: %(algo)s in %(pol)s policy. "
                    "Please select one of the following supported algorithms: "
                    "%(supported_algos)s") % {
                        'pol': policy_type,
                        'algo': auth,
                        'supported_algos':
                        ipsec_utils.AUTH_ALGORITHM_MAP.keys()}
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def _validate_policy_encryption_algorithm(self, policy_info, policy_type):
        encryption = policy_info['encryption_algorithm']
        if encryption not in ipsec_utils.ENCRYPTION_ALGORITHM_MAP:
            msg = _("Unsupported encryption_algorithm: %(algo)s in %(pol)s "
                    "policy. Please select one of the following supported "
                    "algorithms: %(supported_algos)s") % {
                        'algo': encryption,
                        'pol': policy_type,
                        'supported_algos':
                        ipsec_utils.ENCRYPTION_ALGORITHM_MAP.keys()}
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def _validate_policy_pfs(self, policy_info, policy_type):
        pfs = policy_info['pfs']
        if pfs not in ipsec_utils.PFS_MAP:
            msg = _("Unsupported pfs: %(pfs)s in %(pol)s policy. Please "
                    "select one of the following pfs: "
                    "%(supported_pfs)s") % {
                        'pfs': pfs,
                        'pol': policy_type,
                        'supported_pfs':
                        ipsec_utils.PFS_MAP.keys()}
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def _validate_dpd(self, connection):
        dpd_info = connection.get('dpd')
        if not dpd_info:
            return
        action = dpd_info.get('action')
        if action not in ipsec_utils.DPD_ACTION_MAP.keys():
            msg = _("Unsupported DPD action: %(action)s! Currently only "
                    "%(supported)s is supported.") % {
                    'action': action,
                    'supported': ipsec_utils.DPD_ACTION_MAP.keys()}
            raise nsx_exc.NsxVpnValidationError(details=msg)
        timeout = dpd_info.get('timeout')
        if (timeout < vpn_ipsec.DpdProfileTimeoutLimits.DPD_TIMEOUT_MIN or
            timeout > vpn_ipsec.DpdProfileTimeoutLimits.DPD_TIMEOUT_MAX):
            msg = _("Unsupported DPD timeout: %(timeout)s. Value range is "
                    "[%(min)s-%(max)s].") % {
                    'timeout': timeout,
                    'min': vpn_ipsec.DpdProfileTimeoutLimits.DPD_TIMEOUT_MIN,
                    'max': vpn_ipsec.DpdProfileTimeoutLimits.DPD_TIMEOUT_MAX}
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def _validate_psk(self, connection):
        if 'psk' in connection and not connection['psk']:
            msg = _("'psk' cannot be empty or null when authentication "
                    "mode is psk")
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def _check_policy_rules_overlap(self, context, ipsec_site_conn):
        """validate no overlapping policy rules

        The nsx does not support overlapping policy rules cross
        all tenants, and tier0 routers
        """
        connections = self.vpn_plugin.get_ipsec_site_connections(
            context.elevated())
        if not connections:
            return
        vpnservice_id = ipsec_site_conn.get('vpnservice_id')
        vpnservice = self.vpn_plugin._get_vpnservice(context, vpnservice_id)
        local_cidrs = [vpnservice['subnet']['cidr']]
        peer_cidrs = ipsec_site_conn['peer_cidrs']
        for conn in connections:
            if conn['id'] == ipsec_site_conn.get('id'):
                continue
            # TODO(asarfaty): support peer groups too
            # check if it overlaps with the peer cidrs
            conn_peer_cidrs = conn['peer_cidrs']
            if netaddr.IPSet(conn_peer_cidrs) & netaddr.IPSet(peer_cidrs):
                # check if the local cidr also overlaps
                con_service_id = conn.get('vpnservice_id')
                con_service = self.vpn_plugin._get_vpnservice(
                    context.elevated(), con_service_id)
                conn_local_cidr = [con_service['subnet']['cidr']]
                if netaddr.IPSet(conn_local_cidr) & netaddr.IPSet(local_cidrs):
                    msg = (_("Cannot create a connection with overlapping "
                             "local and peer cidrs (%(local)s and %(peer)s) "
                             "as connection %(id)s") % {'local': local_cidrs,
                                                        'peer': peer_cidrs,
                                                        'id': conn['id']})
                raise nsx_exc.NsxVpnValidationError(details=msg)

    def _check_unique_addresses(self, context, ipsec_site_conn):
        """Validate no repeating local & peer addresses (of all tenants)

        The nsx does not support it cross all tenants, and tier0 routers
        """
        vpnservice_id = ipsec_site_conn.get('vpnservice_id')
        local_addr = self._get_service_local_address(context, vpnservice_id)
        peer_address = ipsec_site_conn.get('peer_address')
        filters = {'peer_address': [peer_address]}
        connections = self.vpn_plugin.get_ipsec_site_connections(
            context.elevated(), filters=filters)
        for conn in connections:
            if conn['id'] == ipsec_site_conn.get('id'):
                continue
            # this connection has the same peer addr as ours.
            # check the service local address
            srv_id = conn.get('vpnservice_id')
            srv_local = self._get_service_local_address(
                context.elevated(), srv_id)
            if srv_local == local_addr:
                msg = (_("Cannot create another connection with the same "
                         "local address %(local)s and peer address %(peer)s "
                         "as connection %(id)s") % {'local': local_addr,
                                                    'peer': peer_address,
                                                    'id': conn['id']})
                raise nsx_exc.NsxVpnValidationError(details=msg)

    def validate_ipsec_site_connection(self, context, ipsec_site_conn):
        """Called upon create/update of a connection"""

        self._validate_backend_version()

        self._validate_dpd(ipsec_site_conn)
        self._validate_psk(ipsec_site_conn)

        ike_policy_id = ipsec_site_conn.get('ikepolicy_id')
        if ike_policy_id:
            ikepolicy = self.vpn_plugin.get_ikepolicy(context,
                                                      ike_policy_id)
            self.validate_ike_policy(context, ikepolicy)

        ipsec_policy_id = ipsec_site_conn.get('ipsecpolicy_id')
        if ipsec_policy_id:
            ipsecpolicy = self.vpn_plugin.get_ipsecpolicy(context,
                                                      ipsec_policy_id)
            self.validate_ipsec_policy(context, ipsecpolicy)

        # TODO(asarfaty): Network attached to Tier 1 router needs to be
        # advertised to Tier0 router to access remote networks. However
        #overlapping networks are not supported. All advertised network
        #must be non overlapping and also must not overlap with other networks
        #reachable via TIER0 .

        self._check_unique_addresses(context, ipsec_site_conn)
        self._check_policy_rules_overlap(context, ipsec_site_conn)

        #TODO(asarfaty): IPv6 is not yet supported. add validation

    def _get_service_local_address(self, context, vpnservice_id):
        vpnservice = self.vpn_plugin._get_vpnservice(context,
                                                     vpnservice_id)
        router_id = vpnservice['router_id']
        router_db = self.core_plugin.get_router(context, router_id)
        gw = router_db['external_gateway_info']
        return gw['external_fixed_ips'][0]["ip_address"]

    def _validate_router(self, context, router_id):
        # Verify that the router gw network is connected to an active-standby
        # Tier0 router
        router_db = self.core_plugin._get_router(context, router_id)
        tier0_uuid = self.core_plugin._get_tier0_uuid_by_router(context,
            router_db)
        # TODO(asarfaty): cache this result
        tier0_router = self.nsxlib.logical_router.get(tier0_uuid)
        if (not tier0_router or
            tier0_router.get('high_availability_mode') != 'ACTIVE_STANDBY'):
            msg = _("The router GW should be connected to a TIER-0 router "
                    "with ACTIVE_STANDBY HA mode")
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def validate_vpnservice(self, context, vpnservice):
        """Called upon create/update of a service"""

        self._validate_backend_version()

        # Call general validations
        super(IPsecV3Validator, self).validate_vpnservice(
            context, vpnservice)

        # Call specific NSX validations
        self._validate_router(context, vpnservice['router_id'])

        if not vpnservice['subnet_id']:
            # we currently do not support multiple subnets so a subnet must
            # be defined
            msg = _("Subnet must be defined in  a service")
            raise nsx_exc.NsxVpnValidationError(details=msg)

        #TODO(asarfaty): IPv6 is not yet supported. add validation

    def validate_ipsec_policy(self, context, ipsec_policy):
        # Call general validations
        super(IPsecV3Validator, self).validate_ipsec_policy(
            context, ipsec_policy)

        # Call specific NSX validations
        self._validate_policy_lifetime(ipsec_policy, "IPSec")
        self._validate_policy_auth_algorithm(ipsec_policy, "IPSec")
        self._validate_policy_encryption_algorithm(ipsec_policy, "IPSec")
        self._validate_policy_pfs(ipsec_policy, "IPSec")

        # Ensure IPSec policy encap mode is tunnel
        mode = ipsec_policy['encapsulation_mode']
        if mode not in ipsec_utils.ENCAPSULATION_MODE_MAP.keys():
            msg = _("Unsupported encapsulation mode: %s. Only 'tunnel' mode "
                    "is supported.") % mode
            raise nsx_exc.NsxVpnValidationError(details=msg)

        # Ensure IPSec policy transform protocol is esp
        prot = ipsec_policy['transform_protocol']
        if prot not in ipsec_utils.TRANSFORM_PROTOCOL_MAP.keys():
            msg = _("Unsupported transform protocol: %s. Only 'esp' protocol "
                    "is supported.") % prot
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def validate_ike_policy(self, context, ike_policy):
        # Call general validations
        super(IPsecV3Validator, self).validate_ike_policy(
            context, ike_policy)

        # Call specific NSX validations
        self._validate_policy_lifetime(ike_policy, "IKE")
        self._validate_policy_auth_algorithm(ike_policy, "IKE")
        self._validate_policy_encryption_algorithm(ike_policy, "IKE")
        self._validate_policy_pfs(ike_policy, "IKE")

        # aggressive phase1-negotiation-mode is not supported
        if ike_policy['phase1-negotiation-mode'] != 'main':
            msg = _("Unsupported phase1-negotiation-mode: %s! Only 'main' is "
                    "supported.") % ike_policy['phase1-negotiation-mode']
            raise nsx_exc.NsxVpnValidationError(details=msg)
