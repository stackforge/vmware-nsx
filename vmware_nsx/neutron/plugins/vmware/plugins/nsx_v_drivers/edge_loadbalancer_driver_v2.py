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

from neutron import manager
from neutron.plugins.common import constants
from oslo_log.helpers import log_method_call as call_log
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx.neutron.plugins.vmware.common import locking
from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_db
from vmware_nsx.neutron.plugins.vmware.plugins.nsx_v_drivers import (
    lbaas_common as lb_common)
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    exceptions as nsxv_exc)
from neutron.i18n import _, _LE

LOG = logging.getLogger(__name__)

LB_SESSION_PERSISTENCE_SOURCE_IP = 'SOURCE_IP'
LB_SESSION_PERSISTENCE_HTTP_COOKIE = 'HTTP_COOKIE'
LB_SESSION_PERSISTENCE_APP_COOKIE = 'APP_COOKIE'

LB_METHOD_ROUND_ROBIN = 'ROUND_ROBIN'
LB_METHOD_LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
LB_METHOD_SOURCE_IP = 'SOURCE_IP'

SESSION_PERSISTENCE_METHOD_MAP = {
    LB_SESSION_PERSISTENCE_SOURCE_IP: 'sourceip',
    LB_SESSION_PERSISTENCE_APP_COOKIE: 'cookie',
    LB_SESSION_PERSISTENCE_HTTP_COOKIE: 'cookie'}

SESSION_PERSISTENCE_COOKIE_MAP = {
    LB_SESSION_PERSISTENCE_APP_COOKIE: 'app',
    LB_SESSION_PERSISTENCE_HTTP_COOKIE: 'insert'}

BALANCE_MAP = {
    LB_METHOD_ROUND_ROBIN: 'round-robin',
    LB_METHOD_LEAST_CONNECTIONS: 'leastconn',
    LB_METHOD_SOURCE_IP: 'source'}

def listener_to_edge_vse(listener, vip_address, default_pool, app_profile_id):
    return {
        'name': 'vip_' + listener.id,
        'description': listener.description,
        'ipAddress': vip_address,
        'protocol': listener.protocol,
        'port': listener.protocol_port,
        'connectionLimit': max(0, listener.connection_limit),
        'defaultPoolId': default_pool,
        'applicationProfileId': app_profile_id}


def listener_to_edge_app_profile(listener):
    edge_app_profile = {
        'insertXForwardedFor': False,
        'name': listener.id,
        'serverSslEnabled': False,
        'sslPassthrough': False,
        'template': listener.protocol,
    }

    if listener.default_pool:
        if listener.protocol == 'HTTPS':
            edge_app_profile['sslPassthrough'] = True

        persistence = None
        if listener.pool.sessionpersistence:
            persistence = {
                'method':
                    SESSION_PERSISTENCE_METHOD_MAP.get(
                        listener.pool.sessionpersistence.type)}

        if (listener.pool.sessionpersistence.type in
                SESSION_PERSISTENCE_COOKIE_MAP):
            persistence.update({
                'cookieName': getattr(listener.pool.sessionpersistence,
                                      'cookie_name',
                                      'default_cookie_name'),
                'cookieMode': SESSION_PERSISTENCE_COOKIE_MAP[
                    listener.pool.sessionpersistence.type]})

            edge_app_profile['persistence'] = persistence

    return edge_app_profile


class EdgeLoadbalancerBaseManager(object):
    _lb_driver = None
    _core_plugin = None

    def __init__(self, vcns):
        super(EdgeLoadbalancerBaseManager, self).__init__()
        self.vcns = vcns

    @staticmethod
    def _get_plugin(plugin_type):
        loaded_plugins = manager.NeutronManager().get_service_plugins()
        return loaded_plugins[plugin_type]

    @property
    def lb_driver(self):
        if not EdgeLoadbalancerBaseManager._lb_driver:
            plugin = EdgeLoadbalancerBaseManager._get_plugin(
                constants.LOADBALANCERV2)
            EdgeLoadbalancerBaseManager._lb_driver = (
                plugin.drivers['vmwareedge'])

        return EdgeLoadbalancerBaseManager._lb_driver

    @property
    def core_plugin(self):
        if not EdgeLoadbalancerBaseManager._core_plugin:
            EdgeLoadbalancerBaseManager._core_plugin = (
                EdgeLoadbalancerBaseManager._get_plugin(constants.CORE))

        return EdgeLoadbalancerBaseManager._core_plugin


class EdgeLoadbalancerDriverV2(object):
    @call_log
    def __init__(self):
        self.loadbalancer = EdgeLoadBalancerManager(self.vcns)
        self.listener = EdgeListenerManager(self.vcns)
        self.pool = EdgePoolManager(self.vcns)
        self.member = EdgeMemberManager(self.vcns)
        self.healthmonitor = EdgeHealthMonitorManager(self.vcns)


class EdgeLoadBalancerManager(EdgeLoadbalancerBaseManager):
    @call_log
    def __init__(self, vcns):
        super(EdgeLoadBalancerManager, self).__init__(vcns)

    @call_log
    def create(self, context, lb):
        try:
            edge_id = lb_common.get_lbaas_edge_id_for_subnet(
                context, self.core_plugin, lb.vip_subnet_id)

            with locking.LockManager.get_lock(edge_id, external=True):
                lb_common.add_vip_as_secondary_ip(self.vcns, edge_id,
                                                  lb.vip_address)
            edge_fw_rule_id = lb_common.add_vip_fw_rule(
                self.vcns, edge_id, lb.id, lb.vip_address)

            nsxv_db.add_nsxv_lbaas_loadbalancer_binding(
                context.session, lb.id, edge_id, edge_fw_rule_id,
                lb.vip_address)
            self.lb_driver.load_balancer.successful_completion(context, lb)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.load_balancer.failed_completion(context, lb)
                LOG.error(_LE('Failed to create pool %s'), lb.id)

    @call_log
    def update(self, context, old_lb, new_lb):
        self.lb_driver.load_balancer.successful_completion(context, new_lb)

    @call_log
    def delete(self, context, lb):
        try:
            binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                context.session, lb.id)
            lb_common.del_vip_fw_rule(self.vcns, binding['edge_id'],
                                      binding['edge_fw_rule_id'])
            lb_common.del_vip_as_secondary_ip(self.vcns, binding['edge_id'],
                                              lb.vip_address)
            nsxv_db.del_nsxv_lbaas_loadbalancer_binding(context.session, lb.id)
            self.lb_driver.load_balancer.successful_completion(
                context, lb, delete=True)
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.load_balancer.failed_completion(context, lb)
                LOG.error(_LE('Failed to delete pool %s'), lb.id)

    @call_log
    def refresh(self, context, lb):
        pass

    @call_log
    def stats(self, context, lb):
        pass


class EdgeListenerManager(EdgeLoadbalancerBaseManager):
    @call_log
    def __init__(self, vcns):
        super(EdgeListenerManager, self).__init__(vcns)

    @call_log
    def create(self, context, listener):
        default_pool = None

        for lb_id in listener.loadbalancers:

            if listener.default_pool.id:
                pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                    context.session, lb_id, listener.id,
                    listener.default_pool.id)
                if pool_binding:
                    default_pool = pool_binding['edge_pool_id']

            app_profile = listener_to_edge_app_profile(listener)
            app_profile_id = None

            lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                context.session, lb_id)
            edge_id = lb_binding['edge_id']
            try:
                h = (self.vcns.create_app_profile(edge_id,
                                                  app_profile))[0]
                app_profile_id = lb_common.extract_resource_id(h['location'])
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lb_driver.load_balancer.failed_completion(context,
                                                                   listener)
                    LOG.error(_LE('Failed to create app profile on edge: %s'),
                              lb_binding['edge_id'])

            vse = listener_to_edge_vse(listener, default_pool,
                                       lb_binding['vip_address'],
                                       app_profile_id)

            try:
                h = self.vcns.create_vip(edge_id, vse)[0]
                edge_vse_id = lb_common.extract_resource_id(h['location'])

                nsxv_db.add_nsxv_lbaas_listener_binding(context.session,
                                                        lb_id,
                                                        listener.id,
                                                        app_profile_id,
                                                        edge_vse_id)
                self.lb_driver.load_balancer.successful_completion(context,
                                                                   listener)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lb_driver.load_balancer.failed_completion(context,
                                                                   listener)
                    LOG.error(_LE('Failed to create vip on Edge: %s'), edge_id)
                    self.vcns.delete_app_profile(edge_id, app_profile_id)

    @call_log
    def update(self, context, old_listener, new_listener):

        default_pool = None
        if new_listener.default_pool.id:
            pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                context.session, new_listener.default_pool.id)
            if pool_binding:
                default_pool = pool_binding['edge_pool_id']

        for lb_id in new_listener.loadbalancers:
            listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
                context.session, lb_id, new_listener.id)
            lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                context.session, lb_id)
            edge_id = lb_binding['edge_id']

            app_profile_id = listener_binding['app_profile_id']
            app_profile = listener_to_edge_app_profile(new_listener)

            try:
                self.vcns.update_app_profile(edge_id, app_profile_id,
                                             app_profile)

                vse = listener_to_edge_vse(new_listener, default_pool,
                                           lb_binding['vip_address'],
                                           app_profile_id)

                self.vcns.update_vip(
                    edge_id, listener_binding['edge_vse_id'], vse)

                self.lb_driver.load_balancer.successful_completion(
                    context, new_listener)
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lb_driver.load_balancer.failed_completion(
                        context, new_listener)
                    LOG.error(_LE('Failed to update app profile on edge: %s'),
                              edge_id)

    @call_log
    def delete(self, context, listener):
        for lb_id in listener.loadbalancers:
            listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
                context.session, lb_id, listener.id)
            lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                context.session, lb_id)

            edge_id = lb_binding['edge_id']
            edge_vse_id = listener_binding['edge_vse_id']
            app_profile_id = listener_binding['app_profile_id']

            try:
                self.vcns.delete_vip(edge_id, edge_vse_id)

            except nsxv_exc.ResourceNotFound:
                LOG.error(_LE('vip not found on edge: %s'), edge_id)
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lb_driver.load_balancer.failed_completion(
                        context, listener)
                    LOG.error(
                        _LE('Failed to delete vip on edge: %s'), edge_id)

            try:
                self.vcns.delete_app_profile(edge_id, app_profile_id)
            except nsxv_exc.ResourceNotFound:
                LOG.error(_LE('app profile not found on edge: %s'), edge_id)
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lb_driver.load_balancer.failed_completion(
                        context, listener)
                    LOG.error(
                        _LE('Failed to delete app profile on Edge: %s'),
                        edge_id)

            nsxv_db.del_nsxv_lbaas_listener_binding(context.session,
                                                    lb_id,
                                                    listener.id)

            self.lb_driver.load_balancer.successful_completion(
                context, listener)


class EdgePoolManager(EdgeLoadbalancerBaseManager):
    @call_log
    def __init__(self, vcns):
        super(EdgePoolManager, self).__init__(vcns)

    @call_log
    def create(self, context, pool):

        edge_pool = {
            'name': 'pool_' + pool.id,
            'description': getattr(pool, 'description', getattr(pool, 'name')),
            'algorithm': BALANCE_MAP.get(pool.lb_method, 'round-robin'),
            'transparent': False
        }

        for listener in pool.listeners:
            for lb_id in listener.loadbalancers:
                lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                    context.session, lb_id)

                edge_id = lb_binding['edge_id']

                try:
                    h = self.vcns.create_pool(edge_id, edge_pool)[0]
                    edge_pool_id = lb_common.extract_resource_id(h['location'])
                    nsxv_db.add_nsxv_lbaas_pool_binding(context.session,
                                                        lb_id, listener.id,
                                                        pool.id,
                                                        edge_pool_id)

                    self.lb_driver.load_balancer.successful_completion(
                        context, pool)

                except nsxv_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        self.lb_driver.load_balancer.failed_completion(
                            context, pool)
                        LOG.error(_LE('Failed to create pool %s'), pool['id'])

    @call_log
    def update(self, context, old_pool, new_pool):
        edge_pool = {
            'name': 'pool_' + new_pool.id,
            'description': getattr(new_pool, 'description',
                                   getattr(new_pool, 'name')),
            'algorithm': BALANCE_MAP.get(new_pool.lb_method, 'round-robin'),
            'transparent': False
        }

        for listener in new_pool.listeners:
            for lb_id in listener.loadbalancers:
                lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                    context.session, lb_id)
                pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                    context.session, lb_id, listener.id, new_pool.id)

                edge_id = lb_binding['edge_id']
                edge_pool_id = pool_binding['edge_pool_id']

                try:
                    self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

                    self.lb_driver.load_balancer.successful_completion(
                        context, new_pool)

                except nsxv_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        self.lb_driver.load_balancer.failed_completion(
                            context, new_pool)
                        LOG.error(_LE('Failed to update pool %s'),
                                  new_pool['id'])

    @call_log
    def delete(self, context, pool):
        for listener in pool.listeners:
            for lb_id in listener.loadbalancers:
                lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                    context.session, lb_id)
                pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                    context.session, lb_id, listener.id, pool.id)

                edge_id = lb_binding['edge_id']
                edge_pool_id = pool_binding['edge_pool_id']

                try:
                    self.vcns.delete_pool(edge_id,
                                          edge_pool_id)

                    self.lb_driver.load_balancer.successful_completion(
                        context, pool)

                except nsxv_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        self.lb_driver.load_balancer.failed_completion(
                            context, pool)
                        LOG.error(_LE('Failed to update pool %s'), pool['id'])


class EdgeMemberManager(EdgeLoadbalancerBaseManager):
    @call_log
    def __init__(self, vcns):
        super(EdgeMemberManager, self).__init__(vcns)
        self._fw_section_id = None

    def _get_pool_member_ips(self, pool, operation, address):
        member_ips = [member.address for member in pool.members]
        if operation == 'add' and address not in member_ips:
            member_ips.append(address)
        elif operation == 'del' and address in member_ips:
            member_ips.remove(address)
        return member_ips

    def _get_lbaas_fw_section_id(self):
        if not self._fw_section_id:
                self._fw_section_id = lb_common.get_lbaas_fw_section_id(
                    self.vcns)
        return self._fw_section_id

    @call_log
    def create(self, context, member):
        for listener in member.pool.listeners:
            for lb_id in listener.loadbalancers:
                lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
                    context.session, lb_id)
                pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                    context.session, lb_id, listener.id, member.pool_id)

                edge_id = lb_binding['edge_id']
                edge_pool_id = pool_binding['edge_pool_id']
                edge_pool = self.vcns.get_pool(edge_id,
                                               edge_pool_id)[1]
                edge_member = {
                    'ipAddress': member.address,
                    'weight': member.weight,
                    'port': member.protocol_port,
                    'monitorPort': member.protocol_port,
                    'name': lb_common.get_member_id(member.id),
                    'condition':
                        'enabled' if member.admin_state_up else 'disabled'}

                if edge_pool['member']:
                    edge_pool['member'].append(edge_member)
                else:
                    edge_pool['member'] = [edge_member]

                try:
                    self.vcns.update_pool(
                        edge_id,
                        edge_pool_id,
                        edge_pool)

                    member_ips = self._get_pool_member_ips(
                        member.pool, 'add', member.address)
                    lb_common.update_pool_fw_rule(
                        self.vcns, member['pool_id'], edge_id,
                        self._get_lbaas_fw_section_id(), member_ips)

                    self.lb_driver.load_balancer.successful_completion(
                        context, member)

                except nsxv_exc.VcnsApiException:
                    with excutils.save_and_reraise_exception():
                        self._lb_driver.member_failed(context, member)
                        LOG.error(_LE('Failed to create member on edge: %s'),
                                  edge_id)

    @call_log
    def update(self, context, old_member, new_member):
        pass

    @call_log
    def delete(self, context, member):
        pass


class EdgeHealthMonitorManager(EdgeLoadbalancerBaseManager):
    @call_log
    def __init__(self, vcns):
        super(EdgeHealthMonitorManager, self).__init__(vcns)

    @call_log
    def create(self, context, hm):
        pass

    @call_log
    def update(self, context, old_hm, new_hm):
        pass

    @call_log
    def delete(self, context, hm):
        pass
