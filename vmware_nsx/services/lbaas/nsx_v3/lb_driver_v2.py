# Copyright 2017 VMware, Inc.
# All Rights Reserved
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


from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from neutron_lib import constants as lib_const
from neutron_lib.plugins import directory

from vmware_nsx.common import utils
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsx.services.lbaas.nsx_v3 import healthmonitor_mgr as hm_mgr
from vmware_nsx.services.lbaas.nsx_v3 import listener_mgr
from vmware_nsx.services.lbaas.nsx_v3 import loadbalancer_mgr as lb_mgr
from vmware_nsx.services.lbaas.nsx_v3 import member_mgr
from vmware_nsx.services.lbaas.nsx_v3 import pool_mgr

LOG = logging.getLogger(__name__)


class EdgeLoadbalancerDriverV2(object):
    @log_helpers.log_method_call
    def __init__(self, nsx_version=None):
        nsx_version = nsx_version if nsx_version else self._get_nsx_version()
        if not utils.is_nsx_version_2_1_0(nsx_version):
            LOG.error('Loadbalancer feature is not available on NSX '
                      'version %s', nsx_version)
            raise nsx_exc.InvalidVersion(version=nsx_version)

        super(EdgeLoadbalancerDriverV2, self).__init__()
        self.loadbalancer = lb_mgr.EdgeLoadBalancerManager()
        self.listener = listener_mgr.EdgeListenerManager()
        self.pool = pool_mgr.EdgePoolManager()
        self.member = member_mgr.EdgeMemberManager()
        self.healthmonitor = hm_mgr.EdgeHealthMonitorManager()

    def _get_nsx_version(self):
        nsxlib = v3_utils.get_nsxlib_wrapper()
        return nsxlib.get_version()
