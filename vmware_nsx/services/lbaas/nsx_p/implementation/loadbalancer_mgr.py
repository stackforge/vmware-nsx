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

from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas import lb_const
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils
from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)


class EdgeLoadBalancerManagerFromDict(base_mgr.NsxpLoadbalancerBaseManager):

    @log_helpers.log_method_call
    def _validate_lb_network(self, context, lb, network):
        if network.get('router:external'):
            return True

        router_id = lb_utils.get_router_from_network(
            context, self.core_plugin, lb['vip_subnet_id'])

        if router_id:
            return True

        return False

    @log_helpers.log_method_call
    def _get_info_from_fip(self, context, fip):
        filters = {'floating_ip_address': [fip]}
        floating_ips = self.core_plugin.get_floatingips(context,
                                                        filters=filters)
        if floating_ips:
            return (floating_ips[0]['fixed_ip_address'],
                    floating_ips[0]['router_id'])
        else:
            msg = (_('Member IP %(fip)s is an external IP, and is expected to '
                     'be a floating IP') % {'fip': fip})
            raise n_exc.BadRequest(resource='lbaas-vip', msg=msg)

    @log_helpers.log_method_call
    def create(self, context, lb, completor):
        lb_id = lb['id']

        network = lb_utils.get_network_from_subnet(
            context, self.core_plugin, lb['vip_subnet_id'])

        if not self._validate_lb_network(context, lb, network):
            completor(success=False)
            msg = (_('Cannot create a loadbalancer %(lb_id)s member subnet '
                     '%(subnet)s is neither public nor connected to the LB '
                     'router') %
                   {'lb_id': lb_id, 'subnet': lb['vip_subnet_id']})
            raise n_exc.BadRequest(resource='lbaas-subnet', msg=msg)

        router_id = lb_utils.get_router_from_network(
            context, self.core_plugin, lb['vip_subnet_id'])

        lb_name = utils.get_name_and_uuid(lb['name'] or 'lb',
                                          lb_id)

        tags = lb_utils.get_tags(self.core_plugin, lb['id'],
                                 lb_const.LB_LB_TYPE,
                                 lb['tenant_id'], context.project_name)

        lb_size = lb_utils.get_lb_flavor_size(self.flavor_plugin, context,
                                              lb.get('flavor_id'))

        service_client = self.core_plugin.nsxpolicy.load_balancer.lb_service
        try:
            service_client.create_or_overwrite(
                lb_name, lb_service_id=lb['id'], description=lb['description'],
                tags=tags, size=lb_size)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to create loadbalancer %(lb)s for lb with '
                          'exception %(e)s', {'lb': lb['id'], 'e': e})

        completor(success=True)

    @log_helpers.log_method_call
    def update(self, context, old_lb, new_lb, completor):
        completor(success=True)

    @log_helpers.log_method_call
    def delete(self, context, lb, completor):
        service_client = self.core_plugin.nsxpolicy.load_balancer.lb_service
        router_id = lb_utils.get_router_from_network(
            context, self.core_plugin, lb['vip_subnet_id'])

        if router_id:
            try:
                service_client.delete(lb['id'])

                if not self.core_plugin.service_router_has_services(context,
                                                                    router_id):
                    self.core_plugin.delete_service_router(router_id)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    completor(success=False)
                    LOG.error('Failed to delete loadbalancer %s for lb ',
                              lb['id'])
        else:
            LOG.warning('Router not found for loadbalancer %s', lb['id'])
        completor(success=True)

    @log_helpers.log_method_call
    def refresh(self, context, lb):
        # TODO(kobis): implement
        pass

    @log_helpers.log_method_call
    def stats(self, context, lb):
        # TODO(kobis): implement
        pass

    @log_helpers.log_method_call
    def get_operating_status(self, context, id, with_members=False):
        # TODO(kobis): implement
        pass
