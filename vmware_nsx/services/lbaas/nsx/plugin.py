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

from neutron_lbaas.services.loadbalancer import plugin

from vmware_nsx.plugins.nsx import utils as tvd_utils


class LoadBalancerTVDPluginv2(plugin.LoadBalancerPluginv2,
                              tvd_utils.TVDServicePluginBase):

    def get_loadbalancers(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(LoadBalancerTVDPluginv2, self).get_loadbalancers,
            context, filters=filters, fields=fields)

    def get_listeners(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(LoadBalancerTVDPluginv2, self).get_listeners,
            context, filters=filters, fields=fields)

    def get_pools(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(LoadBalancerTVDPluginv2, self).get_pools,
            context, filters=filters, fields=fields)

    def get_healthmonitors(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(LoadBalancerTVDPluginv2, self).get_healthmonitors,
            context, filters=filters, fields=fields)

    def get_l7policies(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(LoadBalancerTVDPluginv2, self).get_l7policies,
            context, filters=filters, fields=fields)
