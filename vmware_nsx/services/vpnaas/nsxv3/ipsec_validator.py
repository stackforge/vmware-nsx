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

from neutron_vpnaas.db.vpn import vpn_validator

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils
from vmware_nsxlib.v3 import vpn_ipsec


class IPsecV3Validator(vpn_validator.VpnReferenceValidator):

    """Validator methods for Vmware NSX-V3 VPN support"""
    def __init__(self, service_plugin):
        super(IPsecV3Validator, self).__init__()
        self.vpn_plugin = service_plugin

    def _validate_policy_lifetime(self, policy_info, policy_type):
        """NSX supports only units=seconds"""
        lifetime = policy_info.get('lifetime')
        if lifetime and lifetime.get('units') != 'seconds':
            msg = _("Unsupported policy lifetime %(val)s in %(pol)s policy. "
                    "Only seconds lifetime is supported right now.") % {
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
            msg = _("Unsupported DPD timeout: %(timeout)s! Value range is "
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

    def validate_ipsec_site_connection(self, context, ipsec_site_conn):
        """Called upon create/update of a connection"""
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
        # TODO(asarfaty) validate no overlapping subnets (of all tenants)
        # using the same vpn service (=TIER0) as the nsx does not support it

    def _validate_router(self, context, router_id):
        # Verify that the router gw network is connected to an active-standby
        # Tier0 router
        router_db = self.core_plugin._get_router(context, router_id)
        tier0_uuid = self.core_plugin._get_tier0_uuid_by_router(context,
            router_db)
        tier0_router = self.core_plugin.nsxlib.logical_router.get(tier0_uuid)
        if (not tier0_router or
            tier0_router.get('high_availability_mode') != 'ACTIVE_STANDBY'):
            msg = _("The router GW should be connected to a TIER-0 router "
                    "with ACTIVE_STANDBY HA mode")
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def validate_vpnservice(self, context, vpnservice):
        """Called upon create/update of a service"""
        # Call general validations
        super(IPsecV3Validator, self).validate_vpnservice(
            context, vpnservice)

        # Call specific NSX validations
        self._validate_router(context, vpnservice['router_id'])

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
            msg = _("Unsupported encapsulation mode: %s! Currently only"
                    "'tunnel' mode is supported.") % mode
            raise nsx_exc.NsxVpnValidationError(details=msg)

        # Ensure IPSec policy transform protocol is esp
        prot = ipsec_policy['transform_protocol']
        if prot not in ipsec_utils.TRANSFORM_PROTOCOL_MAP.keys():
            msg = _("Unsupported transform protocol: %s! Currently only"
                    "'esp' protocol is supported.") % prot
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
        # TODO(asarfaty): support neutron parameter phase1-negotiation-mode
