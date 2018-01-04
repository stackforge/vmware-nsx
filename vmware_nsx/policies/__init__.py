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
import os

from vmware_nsx.policies import dynamic_routing
from vmware_nsx.policies import flow_classifier
from vmware_nsx.policies import ports
from vmware_nsx.policies import security_groups


def list_rules():
    return itertools.chain(
        dynamic_routing.list_rules(),
        flow_classifier.list_rules(),
        ports.list_rules(),
        security_groups.list_rules(),
    )
