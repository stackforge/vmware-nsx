# Copyright 2018 VMware, Inc.  All rights reserved.
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
#    under the License.

from neutron_lib.callbacks import registry

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.nsxv3.resources import fwaas as v3_fwaas
import vmware_nsx.shell.resources as shell


# The same migration code of nSX-V3 can be used for NSX-V
registry.subscribe(v3_fwaas.migrate_fwaas_v1_to_v2,
                   constants.FWAAS,
                   shell.Operations.MIGRATE_V1_TO_V2.value)
