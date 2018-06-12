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

from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory


class LBaaSNSXObjectManagerWrapper(object):
    """Wrapper class to connect the LB api with the NSX-V/V3 implementations

    This class will call the actual NSX-V LBaaS logic after translating
    the LB object into a dictionary, and will also handle success/failure cases
    """
    _core_plugin = None

    @log_helpers.log_method_call
    def __init__(self, object_type, implementor, translator, get_completor):
        super(LBaaSNSXObjectManagerWrapper, self).__init__()
        self.object_type = object_type
        self.implementor = implementor
        self.translator = translator
        self.get_completor = get_completor

    def _get_plugin(self, plugin_type):
        return directory.get_plugin(plugin_type)

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = (
                self._get_plugin(plugin_const.CORE))

        return self._core_plugin

    def get_completor_func(self, context, obj, delete=False):
        # return a method that will be called on success/failure completion
        def completor_func(success=True):
            completor = self.get_completor()
            if completor:
                if success:
                    return completor.successful_completion(
                        context, obj, delete=delete)
                else:
                    return completor.failed_completion(
                        context, obj)

        return completor_func

    @log_helpers.log_method_call
    def create(self, context, obj, **args):
        obj_dict = self.translator(obj)
        completor_func = self.get_completor_func(context, obj)
        self.implementor.create(context, obj_dict, completor_func, **args)

    @log_helpers.log_method_call
    def update(self, context, old_obj, new_obj, **args):
        old_obj_dict = self.translator(old_obj)
        new_obj_dict = self.translator(new_obj)
        completor_func = self.get_completor_func(context, new_obj)
        self.implementor.update(context, old_obj_dict, new_obj_dict,
                                completor_func, **args)

    @log_helpers.log_method_call
    def delete(self, context, obj, **args):
        obj_dict = self.translator(obj)
        completor_func = self.get_completor_func(context, obj, delete=True)
        self.implementor.delete(context, obj_dict, completor_func, **args)

    @log_helpers.log_method_call
    def refresh(self, context, obj):
        # verify that this api exists (supported only for loadbalancer)
        if not hasattr(self.implementor, 'refresh'):
            msg = (_("LBaaS object %s does not support refresh api") %
                   self.object_type)
            raise n_exc.BadRequest(resource='edge', msg=msg)
        obj_dict = self.translator(obj)
        self.implementor.refresh(context, obj_dict)

    @log_helpers.log_method_call
    def stats(self, context, obj):
        # verify that this api exists (supported only for loadbalancer)
        if not hasattr(self.implementor, 'stats'):
            msg = (_("LBaaS object %s does not support stats api") %
                   self.object_type)
            raise n_exc.BadRequest(resource='edge', msg=msg)
        obj_dict = self.translator(obj)
        self.implementor.stats(context, obj_dict)
