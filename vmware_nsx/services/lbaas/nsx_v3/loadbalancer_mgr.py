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

from neutron.services.flavors import flavors_plugin
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3 import lb_common
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeLoadBalancerManager(base_mgr.LoadbalancerBaseManager):
    def __init__(self):
        super(EdgeLoadBalancerManager, self).__init__()
        registry.subscribe(
            self._handle_subnet_gw_change,
            resources.SUBNET, events.AFTER_UPDATE)

    def create(self, context, lb):
        lb_router = lb_common.get_lb_router_id(context, self.core_plugin,
                                               lb)
        if not lb_router:
            msg = _('Failed to create router on subnet %(sub)s for '
                    'loadbalancer %(lb)s') % {'sub': lb.vip_subnet_id,
                                              'lb': lb.id}
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)

        attachment = {'target_id': lb_router['id'],
                      'target_type': 'LogicalRouter'}
        name = utils.get_name_and_uuid(lb.name, lb.id)
        tags = lb_common.get_tags(self.core_plugin, lb.id,
                                  lb_const.LB_RESOURCE_TYPE,
                                  lb.tenant_id, context.project_name)
        flavor_size = self._get_lb_flavor_size(context, lb.flavor_id)

        try:
            self.core_plugin.nsxlib.load_balancer.service.create(
                display_name=name, tags=tags, enabled=True,
                attachment=attachment, size=flavor_size)
            self.lbv2_driver.load_balancer.successful_completion(context, lb)
        except nsxlib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                self.lbv2_driver.load_balancer.failed_completion(context, lb)
                LOG.error('Failed to create loadbalancer %s', lb.id)

    def update(self, context, old_lb, new_lb):
        self.lbv2_driver.load_balancer.successful_completion(context, new_lb)

    def delete(self, context, lb):
        # Delete LB service from backend
        service_client = self.core_plugin.nsxlib.load_balancer.service
        router_client = self.core_plugin.nsxlib.logical_router
        port_client = self.core_plugin.nsxlib.logical_port
        lb_service_id = lb_common.get_nsx_resource_binding(service_client,
                                                           lb.name, lb.id)
        if lb_service_id:
            try:
                service_client.delete(lb_service_id)
            except nsxlib_exc.ManagerError:
                LOG.error("Backend LB service %s deletion failed",
                          lb_service_id)
        else:
            LOG.warning("Cannot find LB service on backend for LB %s-%s",
                        lb.name, lb.id)
        lb_router_id = lb_common.get_nsx_resource_binding(router_client,
                                                          lb.name, lb.id)
        if lb_router_id:
            try:
                router_client.delete(lb_router_id)
            except nsxlib_exc.ManagerError:
                LOG.error("Backend LB service router %s deletion failed",
                          lb_router_id)
        lb_inf_port = port_client.find_by_display_name('lb_if-' + lb.id)
        if lb_inf_port:
            try:
                port_client.delete(lb_inf_port[0]['id'])
            except nsxlib_exc.ManagerError:
                LOG.error("Backend lb interface port %s deletion failed",
                          lb_inf_port[0]['id'])

        # Discard any ports which are associated with LB
        self.lbv2_driver.load_balancer.successful_completion(
            context, lb, delete=True)

    def refresh(self, context, lb):
        # TODO(tongl): implememnt
        pass

    def stats(self, context, lb):
        service_client = self.core_plugin.nsxlib.load_balancer.service
        lb_service_id = lb_common.get_nsx_resource_binding(service_client,
                                                           lb.name, lb.id)
        try:
            resp = service_client.get(lb_service_id)
            if resp:
                return resp['virtual_servers']['statistics']

        except nsxlib_exc.ManagerError:
            LOG.error('Failed to retrieve stats from LB service %s' % lb.id)

    def _get_lb_flavor_size(self, context, flavor_id):
        if not flavor_id:
            return lb_const.DEFAULT_LB_SIZE
        else:
            flavor = flavors_plugin.FlavorsPlugin.get_flavor(
                self.flavor_plugin, context, flavor_id)
            flavor_size = flavor['name']
            if flavor_size in lb_const.LB_FLAVOR_SIZES:
                return flavor_size.upper()
            else:
                err_msg = (_("Invalid flavor name %(flavor)s, only 'small', "
                             "'medium', or 'large' are supported") %
                           {'flavor': flavor_size})
                raise n_exc.InvalidInput(error_message=err_msg)

    def _handle_subnet_gw_change(self, *args, **kwargs):
        # As the Edge appliance doesn't use DHCP, we should change the
        # default gateway here when the subnet GW changes.
        context = kwargs.get('context')
        orig = kwargs['original_subnet']
        updated = kwargs['subnet']
        if orig['gateway_ip'] == updated['gateway_ip']:
            return
