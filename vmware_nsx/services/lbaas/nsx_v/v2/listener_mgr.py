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

from vmware_nsx.services.lbaas import lb_translators
from vmware_nsx.services.lbaas.nsx_v.common import listener_mgr

LOG = logging.getLogger(__name__)


class EdgeListenerManager(listener_mgr.EdgeListenerManagerFromDict):
    """Wrapper class for NSX-V LBaaS V2

    This class will call the actual NSX-V LBaaS logic after translating
    the LB object into a dictionary, and will also handle success/failure cases
    """
    @log_helpers.log_method_call
    def create(self, context, listener, certificate=None):
        listener_dict = lb_translators.lb_listener_obj_to_dict(listener)
        super(EdgeListenerManager, self).create(
            context, listener_dict, certificate=certificate,
            listener_obj=listener)

    @log_helpers.log_method_call
    def update(self, context, old_listener, new_listener, certificate=None):
        old_listener_dict = lb_translators.lb_listener_obj_to_dict(
            old_listener)
        new_listener_dict = lb_translators.lb_listener_obj_to_dict(
            new_listener)
        super(EdgeListenerManager, self).update(
            context, old_listener_dict, new_listener_dict,
            certificate=certificate, listener_obj=new_listener)

    @log_helpers.log_method_call
    def delete(self, context, listener):
        listener_dict = lb_translators.lb_listener_obj_to_dict(listener)
        super(EdgeListenerManager, self).delete(
            context, listener_dict, listener_obj=listener)

    def successful_completion(self, context, listener_obj, delete=False,
                              lb_create=False):
        self.lbv2_driver.listener.successful_completion(
            context, listener_obj, delete=delete, lb_create=lb_create)

    def failed_completion(self, context, listener_obj):
        self.lbv2_driver.listener.failed_completion(context, listener_obj)
