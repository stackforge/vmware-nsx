# Copyright 2015 VMware, Inc
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

from neutron.db.migration.models import head

from vmware_nsx.neutron.plugins.vmware.dbexts import nsx_models  # noqa
from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_models  # noqa
from vmware_nsx.neutron.plugins.vmware.dbexts import vcns_models  # noqa


def get_metadata():
    return head.model_base.BASEV2.metadata
