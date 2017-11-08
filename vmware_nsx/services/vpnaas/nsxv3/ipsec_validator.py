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
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import nsxv_constants
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils

LOG = logging.getLogger(__name__)


class IPsecV3Validator(vpn_validator.VpnReferenceValidator):

    """Validator methods for Vmware NSX-V3 VPN support"""
    def __init__(self, service_plugin):
        super(IPsecV3Validator, self).__init__()
        self.vpn_plugin = service_plugin

    def validate_ikepolicy_lifetime(self, policy_info):
        """NSX supports only units=seconds"""
        lifetime = policy_info.get('lifetime')
        if lifetime and lifetime.get('units') != 'seconds':
            msg = _("Unsupported ike policy lifetime %s! only seconds "
                    "lifetime is supported right now.") % lifetime
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def validate_ikepolicy_auth_algorithm(self, policy_info):
        """NSX supports only SHA1 and SHA256"""
        auth = policy_info['auth_algorithm']
        if auth and auth not in ipsec_utils.AUTH_ALGORITHM_MAP:
            msg = _("Unsupported auth_algorithm: %(algo)s! please "
                    "select one of the following supported algorithms: "
                    "%(supported_algos)s") % {
                        'algo': auth,
                        'supported_algos':
                        ipsec_utils.AUTH_ALGORITHM_MAP.keys()}
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def validate_ikepolicy_encryption_algorithm(self, policy_info):
        encryption = policy_info['encryption_algorithm']
        if encryption not in ipsec_utils.ENCRYPTION_ALGORITHM_MAP:
            msg = _("Unsupported encryption_algorithm: %(algo)s! please "
                    "select one of the following supported algorithms: "
                    "%(supported_algos)s") % {
                        'algo': encryption,
                        'supported_algos':
                        ipsec_utils.ENCRYPTION_ALGORITHM_MAP.keys()}
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def validate_ikepolicy_pfs(self, policy_info):
        pfs = policy_info['pfs']
        if pfs not in ipsec_utils.PFS_MAP:
            msg = _("Unsupported pfs: %(pfs)s! please "
                    "select one of the following pfs: "
                    "%(supported_pfs)s") % {
                        'pfs': pfs,
                        'supported_pfs':
                        ipsec_utils.PFS_MAP.keys()}
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def validate_ike_policy(self, policy_info):
        LOG.error("DEBUG ADIT validate_ike_policy %s", policy_info)
        self.validate_ikepolicy_lifetime(policy_info)
        self.validate_ikepolicy_auth_algorithm(policy_info)
        self.validate_ikepolicy_encryption_algorithm(policy_info)
        self.validate_ikepolicy_pfs(policy_info)
        # TODO asarfaty): what about this neutron parameter
        # phase1-negotiation-mode: Phase1 negotiation mode for IKE
        # either 'Main' or 'Aggressive'.


    # TODO(asarfaty): check which validation we really need
    def validate_ipsec_policy(self, context, policy_info):
        """Ensure IPSec policy encap mode is tunnel for current REST API."""
        mode = policy_info['encapsulation_mode']
        if mode not in nsxv_constants.ENCAPSULATION_MODE_ALLOWED:
            msg = _("Unsupported encapsulation mode: %s! currently only"
                    "'tunnel' mode is supported.") % mode
            raise nsx_exc.NsxVpnValidationError(details=msg)

    def validate_policies_matching_algorithms(self, ikepolicy, ipsecpolicy):
        # In VSE, Phase 1 and Phase 2 share the same encryption_algorithm
        # and authentication algorithms setting. At present, just record the
        # discrepancy error in log and take ipsecpolicy to do configuration.
        keys = ('auth_algorithm', 'encryption_algorithm', 'pfs')
        for key in keys:
            if ikepolicy[key] != ipsecpolicy[key]:
                LOG.warning("IKEPolicy and IPsecPolicy should have consistent "
                            "auth_algorithm, encryption_algorithm and pfs for "
                            "VSE!")
                break

    def validate_ipsec_site_connection(self, context, ipsec_site_conn):
        ike_policy_id = ipsec_site_conn['ikepolicy_id']
        ipsec_policy_id = ipsec_site_conn['ipsecpolicy_id']
        ipsecpolicy = self.vpn_plugin.get_ipsecpolicy(context,
                                                      ipsec_policy_id)
        ikepolicy = self.vpn_plugin.get_ikepolicy(context,
                                                  ike_policy_id)
        self.validate_ike_policy(ikepolicy)
        self.validate_ipsec_policy(context, ipsecpolicy)
        self.validate_policies_matching_algorithms(ikepolicy, ipsecpolicy)
