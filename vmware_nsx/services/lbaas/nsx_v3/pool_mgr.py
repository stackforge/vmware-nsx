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

from neutron_lib import exceptions as n_exc

from vmware_nsx.common import locking
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas.nsx_v3 import listener_mgr
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgePoolManager(base_mgr.LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgePoolManager, self).__init__()

    @log_helpers.log_method_call
    def create(self, context, pool):
        listener_id = pool.listener.id
        pool_client = self.core_plugin.nsxlib.load_balancer.pool
        vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
        try:
            pool_name = utils.get_name_and_uuid(pool.name, pool.id)
            resource = {'project_id': pool.tenant_id,
                        'id': pool.id}
            tags = self.core_plugin.nsxlib.build_v3_tags_payload(
                resource, resource_type='os-lbaas-pool-id',
                project_name=context.project_name)
            lb_pool = pool_client.create(display_name=pool_name,
                                         tags=tags,
                                         algorithm=pool.lb_algorithm)
          
            listener = self.lbv2_driver.plugin.get_listener(context,
                                                            listener_id)
            vs_name = utils.get_name_and_uuid(listener['name'], listener['id'])
            vs_list = vs_client.find_by_display_name(vs_name)
            if vs_list:
                vs_id = vs_list[0]['id']
                vs_client.update(vs_id, pool_id=lb_pool['id'])
            else:
                msg = ('Failed to get virtual server to attach pool %s' %
                       pool_name)
                raise nsx_exc.NsxPluginException(err_msg=msg)
            self.lbv2_driver.pool.successful_completion(context, pool)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.pool.failed_completion(context, pool)

    @log_helpers.log_method_call
    def update(self, context, old_pool, new_pool):
        try:
            self.lbv2_driver.pool.successful_completion(context, new_pool)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.pool.failed_completion(context, new_pool)

    @log_helpers.log_method_call
    def delete(self, context, pool):
        listener_id = pool.listener.id
        try:
            pool_client = self.core_plugin.nsxlib.load_balancer.pool
            vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
            listener = self.lbv2_driver.plugin.get_listener(context,
                                                            listener_id)
            vs_name = utils.get_name_and_uuid(listener['name'],
                                              listener['id']) 
            vs_list = vs_client.find_by_display_name(vs_name)
            if vs_list:
                vs_id = vs_list[0]['id']
                vs_client.update(vs_id, pool_id='')
            pool_name = utils.get_name_and_uuid(pool.name, pool.id)
            pools = pool_client.find_by_display_name(pool_name)
            if pools:
                pool_client.delete(pools[0]['id'])
            self.lbv2_driver.pool.successful_completion(
                context, pool, delete=True)
        except Exception:
            self.lbv2_driver.pool.failed_completion(context, pool)
