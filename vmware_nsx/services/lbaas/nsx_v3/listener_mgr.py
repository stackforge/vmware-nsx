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

from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeListenerManager(base_mgr.LoadbalancerBaseManager):
    def __init__(self):
        super(EdgeListenerManager, self).__init__()

    def create(self, context, listener, certificate=None):
        lb_id = listener.loadbalancer_id
        load_balancer = self.core_plugin.nsxlib.load_balancer
        try:
            vs_client = self.core_plugin.nsxlib.load_balancer.virtual_server
            service_client = load_balancer.service 
            app_client = load_balancer.application_profile
            lb = self.lbv2_driver.plugin.get_loadbalancer(context, lb_id)
            vip_address = lb['vip_address']
            vs_name = utils.get_name_and_uuid(listener.name, listener.id)
            resource = {'project_id': listener.tenant_id,
                        'id': listener.id}
            tags = self.core_plugin.nsxlib.build_v3_tags_payload(
                resource, resource_type='os-lbaas-listener-id',
                project_name=context.project_name)
            if listener.protocol == 'HTTP':
                http_profile = app_client.create(
                    display_name=vs_name, resource_type='LbHttpProfile',
                    tags=tags, x_forwarded_for='INSERT')
                http_profile_id = http_profile['id']
                vs = vs_client.create(display_name=vs_name,
                                      tags=tags,
                                      enabled=listener.admin_state_up,
                                      ip_address=vip_address,
                                      port=listener.protocol_port,
                                      application_profile_id=http_profile_id)
            lb_name = utils.get_name_and_uuid(lb['name'], lb['id'])
            lb_services = service_client.find_by_display_name(lb_name)
            if lb_services:
                service_id = lb_services[0]['id']
                service_client.update(service_id,
                                      virtual_server_ids=[vs['id']])
            else:
                msg = ('Failed to get LB service for virtual server %s' %
                       vs_name)
                raise nsx_exc.NsxPluginException(err_msg=msg)
            self.lbv2_driver.listener.successful_completion(
                context, listener)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.listener.failed_completion(context, listener)
                LOG.error('Failed to create listener %s', listener.id)

    def update(self, context, old_listener, new_listener, certificate=None):
        pass

    def delete(self, context, listener):
        lb_id = listener.loadbalancer_id
        load_balancer = self.core_plugin.nsxlib.load_balancer
        try:
            vs_client = load_balancer.virtual_server
            service_client = load_balancer.service 
            app_client = load_balancer.application_profile
            lb = self.lbv2_driver.plugin.get_loadbalancer(context, lb_id)
            # Update LB service to remove virtual server
            lb_name = utils.get_name_and_uuid(lb['name'], lb['id'])
            lb_services = service_client.find_by_display_name(lb_name)
            if lb_services:
                service_id = lb_services[0]['id']
                service_client.update(service_id,
                                      virtual_server_ids=[])
            # Delete virtual server
            vs_name = utils.get_name_and_uuid(listener.name, listener.id)
            vs_list = vs_client.find_by_display_name(vs_name)
            if vs_list:
                vs_client.delete(vs_list[0]['id'])
            # Delete application profile
            app_profiles = app_client.find_by_display_name(vs_name)
            if app_profiles:
                app_client.delete(app_profiles[0]['id']) 
            self.lbv2_driver.listener.successful_completion(
                context, listener, delete=True)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.listener.failed_completion(context, listener)
                LOG.error('Failed to delete listener %s', listener.id)
