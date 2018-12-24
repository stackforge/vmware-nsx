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
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils

LOG = logging.getLogger(__name__)


class EdgeMemberManagerFromDict(base_mgr.NsxpLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def _get_info_from_fip(self, context, fip):
        filters = {'floating_ip_address': [fip]}
        floating_ips = self.core_plugin.get_floatingips(context,
                                                        filters=filters)
        if floating_ips:
            return floating_ips[0]['fixed_ip_address']
        else:
            msg = (_('Member IP %(fip)s is an external IP, and is expected to '
                     'be a floating IP') % {'fip': fip})
            raise n_exc.BadRequest(resource='lbaas-vip', msg=msg)

    @log_helpers.log_method_call
    def create(self, context, member, completor):
        pool_client = self.core_plugin.nsxpolicy.load_balancer.lb_pool
        network = lb_utils.get_network_from_subnet(
            context, self.core_plugin, member['subnet_id'])
        if network.get('router:external'):
            fixed_ip = self._get_info_from_fip(context, member['address'])
        else:
            fixed_ip = member['address']
        pool_id = member['pool']['id']
        try:
            pool_client.create_pool_member_and_add_to_pool(
                pool_id, fixed_ip,
                port=member['protocol_port'],
                display_name=member['name'][:219] + '_' + member['id'],
                weight=member['weight'])
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to create member %(member)s on pool %(pool)s'
                          ': %(err)s',
                          {'member': member['id'],
                           'pool': pool_id, 'err': e})
        completor(success=True)

    @log_helpers.log_method_call
    def update(self, context, old_member, new_member, completor):
        network = lb_utils.get_network_from_subnet(
            context, self.core_plugin, new_member['subnet_id'])
        if network.get('router:external'):
            fixed_ip = self._get_info_from_fip(context, new_member['address'])
        else:
            fixed_ip = new_member['address']
        pool_id = new_member['pool']['id']
        pool_client = self.core_plugin.nsxpolicy.load_balancer.lb_pool
        try:
            pool_client.update_pool_member(
                pool_id, fixed_ip, port=new_member['protocol_port'],
                display_name=new_member['name'][:219] + '_' + new_member['id'],
                weight=new_member['weight'])

        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to update member %(member)s on pool %(pool)s'
                          ': %(err)s',
                          {'member': new_member['id'],
                           'pool': pool_id, 'err': e})
        completor(success=True)

    @log_helpers.log_method_call
    def delete(self, context, member, completor):
        network = lb_utils.get_network_from_subnet(
            context, self.core_plugin, member['subnet_id'])
        if network.get('router:external'):
            fixed_ip = self._get_info_from_fip(context, member['address'])
        else:
            fixed_ip = member['address']
        pool_id = member['pool']['id']
        pool_client = self.core_plugin.nsxpolicy.load_balancer.lb_pool
        try:
            pool_client.remove_pool_member(
                pool_id, fixed_ip, port=member['protocol_port'])
        except Exception as e:
            with excutils.save_and_reraise_exception():
                completor(success=False)
                LOG.error('Failed to create member %(member)s on pool %(pool)s'
                          ': %(err)s',
                          {'member': member['id'],
                           'pool': pool_id, 'err': e})
        completor(success=True)

    @log_helpers.log_method_call
    def delete_cascade(self, context, member, completor):
        # No action should be taken on members delete cascade
        pass
