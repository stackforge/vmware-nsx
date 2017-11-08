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

from vmware_nsxlib.v3 import ipsec_vpn

# TODO(asarfaty): NSX also supports ENCRYPTION_ALGORITHM_GCM. can we use it?
ENCRYPTION_ALGORITHM_MAP = {
    'aes-128': ipsec_vpn.IkeEncryptionAlgorithTypes.ENCRYPTION_ALGORITHM_128,
    'aes-256': ipsec_vpn.IkeEncryptionAlgorithTypes.ENCRYPTION_ALGORITHM_256,
}

AUTH_ALGORITHM_MAP = {
    'sha1': ipsec_vpn.IkeDigestAlgorithTypes.SHA1,
    'sha256': ipsec_vpn.IkeDigestAlgorithTypes.SHA2,
}

PFS_MAP = {
    'group2': ipsec_vpn.IkeDHGroupTypes.DG_GROUP_2,
    'group5': ipsec_vpn.IkeDHGroupTypes.DG_GROUP_5,
    'group14': ipsec_vpn.IkeDHGroupTypes.DG_GROUP_14
}
