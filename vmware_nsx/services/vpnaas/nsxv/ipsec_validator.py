# Copyright 2016 VMware, Inc.
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

from vmware_nsx.common import exceptions as nsxv_exc
from vmware_nsx.common import nsxv_constants

LOG = logging.getLogger(__name__)


class IPsecValidator(vpn_validator.VpnReferenceValidator):

    """Validator methods for Vmware VPN support"""

    def __init__(self, service_plugin):
        super(IPsecValidator, self).__init__()
        self.vpn_plugin = service_plugin

    def validate_ikepolicy_version(self, policy_info):
        """NSX Edge provides IKEv1"""
        version = policy_info.get('ike_version')
        if version != 'v1':
            msg = ("Unsupported ike policy %s! only v1"
                   " is supported right now." % version)
            raise nsxv_exc.NsxIPsecVpnFaliure(details=msg)

    def validate_ikepolicy_pfs(self, policy_info):
        # Check whether pfs is allowed.
        if not nsxv_constants.PFS_MAP.get(policy_info['pfs']):
            msg = ("Unsupported pfs: %s! 'group2' and 'group5' "
                   "are supported on VSE right now.") % policy_info['pfs']
            raise nsxv_exc.NsxVpnValidationFaliure(details=msg)

    def validate_encryption_algorithm(self, policy_info):
        encryption = policy_info['encryption_algorithm']
        if encryption not in nsxv_constants.ENCRYPTION_ALGORITHM_MAP:
            msg = ("Unsupported encryption_algorithm: %s! '3des', "
                   "'aes-128' and 'aes-256' are supported right now."
                   % encryption)
            raise nsxv_exc.NsxVpnValidationFaliure(details=msg)

    def validate_ipsec_policy(self, context, policy_info):
        """Ensure IPSec policy encap mode is tunnel for current REST API."""
        mode = policy_info['encapsulation_mode']
        if mode not in nsxv_constants.ENCAPSULATION_MODE_ALLOWED:
            msg = ("Unsupported encapsulation mode: %s! 'tunnel' is "
                   "supported right now." % mode)
            raise nsxv_exc.NsxVpnValidationFaliure(details=msg)

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

    def validate_ipsec_conn(self, context, ipsec_site_conn):
        ike_policy_id = ipsec_site_conn['ikepolicy_id']
        ipsec_policy_id = ipsec_site_conn['ipsecpolicy_id']
        ipsecpolicy = self.vpn_plugin.get_ipsecpolicy(context,
                                                      ipsec_policy_id)
        ikepolicy = self.vpn_plugin.get_ikepolicy(context,
                                                  ike_policy_id)
        self.validate_ikepolicy_version(ikepolicy)
        self.validate_ikepolicy_pfs(ikepolicy)
        self.validate_encryption_algorithm(ikepolicy)
        self.validate_ipsec_policy(context, ipsecpolicy)
        self.validate_policies_matching_algorithms(ikepolicy, ipsecpolicy)
