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


class MismatchLogicalportJob(base_job.BaseJob):

    def __init__(self, readonly):
        super(MismatchLogicalportJob, self).__init__(
            readonly, cfg.CONF.nsx_v3.housekeeping_readonly_jobs)

    def get_project_plugin(self, plugin):
        return plugin.get_plugin_by_type(projectpluginmap.NsxPlugins.NSX_T)

    def get_name(self):
        return 'mismatch_logical_port'

    def get_description(self):
        return 'Detect mismatched configuration on NSX logical ports'

    def run(self, context):
        super(MismatchLogicalportJob, self).run(context)

        # get all orphaned DHCP servers
        mismatch_ports = v3_utils.get_mismatch_logical_ports(
            context, self.plugin.nsxlib, self.plugin)
        info = ""
        if not mismatch_ports:
            info = base_job.housekeeper_log(
                'No mismatched logical ports detected.',
                info, is_error=False)
            return {'error_count': 0, 'error_info': info}

        info = base_job.housekeeper_log(
            "Found %s mismatched logical ports:" % len(mismatch_ports),
            info)

        for port_problem in mismatch_ports:
            msg = ("Logical port %(nsx_id)s "
                   "[neutron id: %(id)s] error: %(err)s" %
                   {'nsx_id': port_problem['nsx_id'],
                    'id': port_problem['neutron_id'],
                    'err': port_problem['error']})
            info = base_job.housekeeper_log(msg, info)
            if not self.readonly:
                # currently we mitigate only address bindings mismatches
                if port_problem['error_type'] == v3_utils.PORT_ERROR_TYPE_BINDINGS:
                    msg = "Fixing logical port address bindings"
                    info = base_job.housekeeper_log(msg, info)
                    # TODO
                else:
                    msg = ("Cannot fix logical port mismatch %s "
                           "automatically" % port_problem['error'])
                    info = base_job.housekeeper_log(msg, info)

        return {'error_count': len(mismatch_ports),
                'error_info': info}
