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
from oslo_utils import excutils

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3 import lb_common
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgePoolManager(base_mgr.LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgePoolManager, self).__init__()

    @log_helpers.log_method_call
    def create(self, context, pool):
        listener_id = pool.listener.id
        loadbalancer_id = pool.loadbalancer_id
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        pool_name = utils.get_name_and_uuid(pool.name, pool.id)
        tags = lb_common.get_tags(self.core_plugin, pool.id,
                                  lb_const.LB_POOL_TYPE, pool.tenant_id,
                                  context.project_name)
        try:
            lb_pool = pool_client.create(display_name=pool_name,
                                         tags=tags,
                                         algorithm=pool.lb_algorithm)
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.pool.failed_completion(context, pool)
                LOG.error('Failed to create pool on NSX backend: %s', pool.id)

        binding = nsx_db.get_nsx_lbaas_listener_binding(
            context.session, loadbalancer_id, listener_id)
        if binding:
            vs_id = binding['lb_vs_id']
            try:
                vs_client.update(vs_id, pool_id=lb_pool['id'])
            except nsxlib_exc.ManagerError:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.pool.failed_completion(context, pool)
                    LOG.error('Failed to attach pool %s to virtual server %s',
                              lb_pool.id, vs_id)
            nsx_db.add_nsx_lbaas_pool_binding(
                context.session, loadbalancer_id, pool.id, lb_pool['id'],
                vs_id)
        else:
            msg = ("Couldn't find binding on the listener: %s" %
                   listener_id)
            raise nsx_exc.NsxPluginException(err_msg=msg)
        self.lbv2_driver.pool.successful_completion(context, pool)

    @log_helpers.log_method_call
    def update(self, context, old_pool, new_pool):
        try:
            self.lbv2_driver.pool.successful_completion(context, new_pool)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.pool.failed_completion(context, new_pool)

    @log_helpers.log_method_call
    def delete(self, context, pool):
        loadbalancer_id = pool.loadbalancer_id
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server

        binding = nsx_db.get_nsx_lbaas_pool_binding(
            context.session, loadbalancer_id, pool.id)
        if binding:
            vs_id = binding['lb_vs_id']
            lb_pool_id = binding['lb_pool_id']
            try:
                vs_client.update(vs_id, pool_id='')
            except nsxlib_exc.ManagerError:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.pool.failed_completion(context, pool)
                    LOG.error('Failed to remove lb pool %s from virtual '
                              'server %s', lb_pool_id, vs_id)
            try:
                pool_client.delete(lb_pool_id)
            except nsxlib_exc.ManagerError:
                with excutils.save_and_reraise_exception():
                    self.lbv2_driver.pool.failed_completion(context, pool)
                    LOG.error('Failed to delete lb pool from nsx: %s',
                              lb_pool_id)
            nsx_db.delete_nsx_lbaas_pool_binding(
                context.session, loadbalancer_id, pool.id)

        self.lbv2_driver.pool.successful_completion(
            context, pool, delete=True)
