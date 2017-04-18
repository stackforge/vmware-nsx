# Copyright 2014 VMware, Inc.  All rights reserved.
#
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
#

from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import (
    distributedrouter as dist_rtr)
from vmware_nsx.extensions import routertype as rt_rtr


class RouterType_mixin(dist_rtr.DistributedRouter_mixin):
    """Mixin class to enable Router type support."""

    nsx_attributes = (
        dist_rtr.DistributedRouter_mixin.nsx_attributes + [{
            'name': rt_rtr.ROUTER_TYPE,
            'default': nsxv_constants.SHARED
        }])
