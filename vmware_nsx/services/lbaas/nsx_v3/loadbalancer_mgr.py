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


from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas.nsx_v3 import lb_utils
from vmware_nsxlib.v3 import exceptions as nsxlib_exc

LOG = logging.getLogger(__name__)


class EdgeLoadBalancerManager(base_mgr.LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeLoadBalancerManager, self).__init__()
        registry.subscribe(
            self._handle_subnet_gw_change,
            resources.SUBNET, events.AFTER_UPDATE)

    @log_helpers.log_method_call
    def create(self, context, lb):

        if lb_utils.validate_lb_subnet(context, self.core_plugin,
                                        lb.vip_subnet_id):
            self.lbv2_driver.load_balancer.successful_completion(context, lb)
        else:
            msg = _('Cannot create lb on subnet %(sub)s for '
                    'loadbalancer %(lb)s as it does not connect '
                    'to router') % {'sub': lb.vip_subnet_id,
                                    'lb': lb.id}
            raise n_exc.BadRequest(resource='lbaas-subnet', msg=msg)

    @log_helpers.log_method_call
    def update(self, context, old_lb, new_lb):
        self.lbv2_driver.load_balancer.successful_completion(context, new_lb)

    @log_helpers.log_method_call
    def delete(self, context, lb):
        # Discard any ports which are associated with LB
        self.lbv2_driver.load_balancer.successful_completion(
            context, lb, delete=True)

    @log_helpers.log_method_call
    def refresh(self, context, lb):
        # TODO(tongl): implememnt
        pass

    @log_helpers.log_method_call
    def stats(self, context, lb):
        service_client = self.core_plugin.nsxlib.load_balancer.service
        lb_service_id = lb_utils.get_nsx_resource_binding(service_client,
                                                          lb.name, lb.id)
        try:
            resp = service_client.get(lb_service_id)
            if resp:
                return resp['virtual_servers']['statistics']

        except nsxlib_exc.ManagerError:
            LOG.error('Failed to retrieve stats from LB service %s', lb.id)

    @log_helpers.log_method_call
    def _handle_subnet_gw_change(self, *args, **kwargs):
        # As the Edge appliance doesn't use DHCP, we should change the
        # default gateway here when the subnet GW changes.
        context = kwargs.get('context')
        orig = kwargs['original_subnet']
        updated = kwargs['subnet']
        if orig['gateway_ip'] == updated['gateway_ip']:
            return
