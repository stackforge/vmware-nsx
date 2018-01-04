#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.


import itertools

from vmware_nsx.policies import dynamic_routing
from vmware_nsx.policies import networking_l2gw
from vmware_nsx.policies import ports
from vmware_nsx.policies import security_groups

# Setting policies for vmware-nsx extensions in-code and out of policy.json


def list_rules():
    return itertools.chain(
        ports.list_rules(),
        security_groups.list_rules(),
        networking_l2gw.list_rules(),
        dynamic_routing.list_rules(),
    )
