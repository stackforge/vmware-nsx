# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 VMware, Inc
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

from oslo.config import cfg

from neutron.openstack.common import log as logging
from vmware_nsx.neutron.plugins.vmware.common import config  # noqa
from vmware_nsx.neutron.plugins.vmware.vshield import edge_appliance_driver
from vmware_nsx.neutron.plugins.vmware.vshield import edge_firewall_driver
from vmware_nsx.neutron.plugins.vmware.vshield.tasks import tasks
from vmware_nsx.neutron.plugins.vmware.vshield import vcns

LOG = logging.getLogger(__name__)


class VcnsDriver(edge_appliance_driver.EdgeApplianceDriver,
                 edge_firewall_driver.EdgeFirewallDriver):

    def __init__(self, callbacks):
        super(VcnsDriver, self).__init__()

        self.callbacks = callbacks
        self.vcns_uri = cfg.CONF.nsxv.manager_uri
        self.vcns_user = cfg.CONF.nsxv.user
        self.vcns_passwd = cfg.CONF.nsxv.password
        self.datacenter_moid = cfg.CONF.nsxv.datacenter_moid
        self.deployment_container_id = cfg.CONF.nsxv.deployment_container_id
        self.resource_pool_id = cfg.CONF.nsxv.resource_pool_id
        self.datastore_id = cfg.CONF.nsxv.datastore_id
        self.external_network = cfg.CONF.nsxv.external_network
        interval = cfg.CONF.nsxv.task_status_check_interval
        self.task_manager = tasks.TaskManager(interval)
        self.task_manager.start()
        self.vcns = vcns.Vcns(self.vcns_uri, self.vcns_user, self.vcns_passwd)
