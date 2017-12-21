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

from neutron_lib import constants
from oslo_log import log

from vmware_nsx.common import locking
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.common.housekeeper import base_job
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vcns_const

LOG = log.getLogger(__name__)


class ErrorBackupEdgeJob(base_job.BaseJob):
    def get_name(self):
        return 'error_backup_edge'

    def get_description(self):
        return 'revalidate backup Edge appliances in ERROR state'

    def run(self, context):
        super(ErrorBackupEdgeJob, self).run(context)

        # Gather ERROR state backup edges into dict
        filters = {'status': [constants.ERROR]}
        error_edge_bindings = nsxv_db.get_nsxv_router_bindings(
            context.session, filters=filters)

        if not error_edge_bindings:
            LOG.debug('Housekeeping: no backup edges in ERROR state detected')
            return

        # Keep list of current broken backup edges - as it may change while
        # HK is running
        with locking.LockManager.get_lock('nsx-edge-backup-pool'):
            edge_bindings = [
                binding for binding in error_edge_bindings
                if binding['router_id'].startswith(
                    vcns_const.BACKUP_ROUTER_PREFIX)]

        for binding in edge_bindings:
            LOG.warning('Housekeeping: Backup Edge appliance %s is in ERROR'
                        'state', binding['edge_id'])

            if not self.readonly:
                dist = (binding['edge_type'] == nsxv_constants.VDR_EDGE)
                update_result = self.plugin.nsx_v.update_edge(
                    context, binding['router_id'], binding['edge_id'],
                    binding['router_id'], None,
                    appliance_size=binding['appliance_size'], dist=dist,
                    availability_zone=binding['availability_zone'])

                if update_result:
                    nsxv_db.update_nsxv_router_binding(
                        context.session, binding['router_id'],
                        status=constants.ACTIVE)
                else:
                    LOG.warning('Housekeeping: failed to recover Edge '
                                'appliance %s', binding['edge_id'])
