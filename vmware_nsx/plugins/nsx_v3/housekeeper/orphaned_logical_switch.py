# Copyright 2018 VMware, Inc.
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

from oslo_config import cfg
from oslo_log import log

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.common.housekeeper import base_job
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils

LOG = log.getLogger(__name__)


class OrphanedLogicalSwitchJob(base_job.BaseJob):

    def __init__(self, readonly):
        super(OrphanedLogicalSwitchJob, self).__init__(
            readonly, cfg.CONF.nsx_v3.housekeeping_readonly_jobs)

    def get_project_plugin(self, plugin):
        return plugin.get_plugin_by_type(projectpluginmap.NsxPlugins.NSX_T)

    def get_name(self):
        return 'orphaned_logical_switch'

    def get_description(self):
        return 'Detect orphaned logical switches'

    def run(self, context):
        super(OrphanedLogicalSwitchJob, self).run(context)

        # get all orphaned DHCP servers
        orphaned_swithces = v3_utils.get_orphaned_networks(
            self.plugin, self.plugin.nsxlib)

        if not orphaned_swithces:
            LOG.debug('Housekeeping: no orphaned logical switches detected')
            return

        LOG.warning("Housekeeping: Found %s orphaned logical switches:",
            len(orphaned_swithces))
        for switch in orphaned_swithces:
            LOG.warning("Housekeeping: Logical switch %(name)s [id: %(id)s] "
                        "(neutron network: %(net)s)",
                {'name': switch['display_name'],
                 'id': switch['id'],
                 'net': switch['neutron_net_id'] if switch['neutron_net_id']
                        else 'Unknown'})
            if not self.readonly:
                try:
                    self.plugin.nsxlib.logical_switch.delete(switch['id'])
                except Exception as e:
                    LOG.error("Housekeeping: Failed to remove: %s.", e)
                else:
                    LOG.warning("Housekeeping: Removed.")
