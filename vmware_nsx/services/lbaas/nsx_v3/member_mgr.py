# Copyright 2015 VMware, Inc.
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
from oslo_utils import excutils

from vmware_nsx.services.lbaas import base_mgr
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeMemberManager(base_mgr.LoadbalancerBaseManager):
    def __init__(self):
        super(EdgeMemberManager, self).__init__()

    def _get_pool_lb_id(self, member):
        listener = member.pool.listener
        if listener:
            lb_id = listener.loadbalancer_id
        else:
            lb_id = member.pool.loadbalancer.id
        return lb_id

    def create(self, context, member):
        pool_id = member.pool.id
        try:
            pool_client = self.core_plugin.nsxlib.load_balancer.pool
            pool = self.lbv2_driver.plugin.get_pool(context, pool_id)
            lb_pool_name = utils.get_name_and_uuid(pool['name'], pool['id'])
            lb_pools = pool_client.find_by_display_name(lb_pool_name)
            if lb_pools:
                lb_pool_id = lb_pools[0]['id']
                lb_pool = pool_client.get(lb_pool_id)
                old_m = lb_pool.get('members', None)
                new_m = [{'display_name': member.name,
                          'ip_address': member.address,
                          'port': member.protocol_port,
                          'weight': member.weight}]
                members = (old_m + new_m) if old_m else new_m
                pool_client.update_pool_with_members(lb_pools[0]['id'], members)
            self.lbv2_driver.member.successful_completion(context, member)

        except Exception:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.member.failed_completion(context, member)

    def update(self, context, old_member, new_member):
        lb_id = self._get_pool_lb_id(new_member)
        try:
            self.lbv2_driver.member.successful_completion(
                context, new_member)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.member.failed_completion(
                    context, new_member)

    def delete(self, context, member):
        lb_id = self._get_pool_lb_id(member)
        try:
            self.lbv2_driver.member.successful_completion(
                context, member, delete=True)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.member.failed_completion(context, member)
