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

from oslo_log import log as logging

from neutron_lbaas.db.loadbalancer import models
from neutron_lbaas.services.loadbalancer import constants
from neutron_lbaas.services.loadbalancer import plugin

LOG = logging.getLogger(__name__)


class LoadBalancerNSXPluginV2(plugin.LoadBalancerPluginv2):
    """NSX Plugin for LBaaS V2.

    This plugin overrides the statuses call to issue the DB update before displaying the results
    """

    def nsx_update_operational_statuses(self, context, loadbalancer_id):
        driver = self._get_driver_for_loadbalancer(
            context, loadbalancer_id)
        driver_obj = driver.load_balancer.lbv2_driver
        LOG.error("DEBUG ADIT nsx_update_operational_statuses %s", driver)
        lb = self.db.get_loadbalancer(context, loadbalancer_id)
        self._call_driver_operation(
            context, driver.load_balancer.refresh, lb)

        # TEST
        self.db.update_status(context, models.LoadBalancer, loadbalancer_id,
                              operating_status=constants.ONLINE)

        lb_status = driver_obj.loadbalancer.implementor.get_operating_status(context, loadbalancer_id)
        if lb_status:
            self.db.update_status(context, models.LoadBalancer, loadbalancer_id,
                                  operating_status=lb_status)
        # DEBUG ADIT - do the same for the pools
        for curr_listener in lb.listeners:
            status = driver_obj.listener.implementor.get_operating_status(context, curr_listener.id)
            if status:
                self.db.update_status(context, models.Listener, curr_listener.id,
                                      operating_status=status)
        for curr_pool in lb.pools:
            status = driver_obj.pool.implementor.get_operating_status(context, curr_pool.id)
            if status:
                self.db.update_status(context, models.Pool, curr_pool.id,
                                      operating_status=status)

            members = curr_pool.members
            for curr_member in members:
                status = driver_obj.member.implementor.get_operating_status(context, curr_member.id)
                if status:
                    self.db.update_status(context, models.Member, curr_member.id,
                                          operating_status=status)

    def statuses(self, context, loadbalancer_id):
        # Get the driver and manually call the refresh api
        #self.nsx_update_operational_statuses(context, loadbalancer_id)

        # use super code to get the updated statuses
        return super(LoadBalancerNSXPluginV2, self).statuses(context, loadbalancer_id)

    def get_loadbalancer(self, context, loadbalancer_id, fields=None):
        # Get the driver and manually call the refresh api
        self.nsx_update_operational_statuses(context, loadbalancer_id)

        return super(LoadBalancerNSXPluginV2, self).get_loadbalancer(
            context, loadbalancer_id, fields=fields)

    # TODO(asarfaty) : do this for the rest of the get apis
    # TODO(asarfaty) : do the implementation for V objects as well
