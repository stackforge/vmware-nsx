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

import time

from neutron_lbaas.db.loadbalancer import models
from neutron_lib import constants
from oslo_log import log

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.plugins.common.housekeeper import base_job

LOG = log.getLogger(__name__)

ELEMENT_LIFETIME = 3 * 60 * 60 # Three hours lifetime


class LbaasPendingJob(base_job.BaseJob):
    lbaas_objects = {}
    lbaas_models = [models.LoadBalancer,
                    models.Listener,
                    models.L7Policy,
                    models.L7Rule,
                    models.PoolV2,
                    models.MemberV2,
                    models.HealthMonitorV2]

    def get_project_plugin(self, plugin):
        return plugin.get_plugin_by_type(projectpluginmap.NsxPlugins.NSX_V)

    def get_name(self):
        return 'lbaas_pending'

    def get_description(self):
        return 'Monitor LBaaS objects in pending states'

    def run(self, context):
        super(LbaasPendingJob, self).run(context)
        age = time.time()

        for model in self.lbaas_models:
            sess = context.session
            elements = sess.query(model).filter_by(
                provisioning_status=constants.PENDING_CREATE).all()

            for element in elements:
                if self.lbaas_objects.has_key(element['id']):
                    lifetime = time.time() - self.lbaas_objects['timestamp']
                    if lifetime > ELEMENT_LIFETIME:
                        element['provisioning_status'] = constants.ERROR
                    else:
                        self.lbaas_objects[element.id]['age'] = age
                else:
                    self.lbaas_objects[element.id] = {
                        'model': model,
                        'timestamp': time.time(),
                        'age': age}

        for obj_id in self.lbaas_objects.keys():
            if self.lbaas_objects[obj_id]['age'] != age:
                del self.lbaas_objects[obj_id]
