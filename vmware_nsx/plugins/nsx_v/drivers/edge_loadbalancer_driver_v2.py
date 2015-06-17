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

from neutron.i18n import _LE
from neutron import manager
from neutron.plugins.common import constants
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.drivers import lbaas_common as lb_common
from vmware_nsx.plugins.nsx_v.vshield.common import exceptions as nsxv_exc

LOG = logging.getLogger(__name__)

LB_SESSION_PERSISTENCE_SOURCE_IP = 'SOURCE_IP'
LB_SESSION_PERSISTENCE_HTTP_COOKIE = 'HTTP_COOKIE'
LB_SESSION_PERSISTENCE_APP_COOKIE = 'APP_COOKIE'

LB_METHOD_ROUND_ROBIN = 'ROUND_ROBIN'
LB_METHOD_LEAST_CONNECTIONS = 'LEAST_CONNECTIONS'
LB_METHOD_SOURCE_IP = 'SOURCE_IP'

LB_HEALTH_MONITOR_PING = 'PING'
LB_HEALTH_MONITOR_TCP = 'TCP'
LB_HEALTH_MONITOR_HTTP = 'HTTP'
LB_HEALTH_MONITOR_HTTPS = 'HTTPS'

SESSION_PERSISTENCE_METHOD_MAP = {
    LB_SESSION_PERSISTENCE_SOURCE_IP: 'sourceip',
    LB_SESSION_PERSISTENCE_APP_COOKIE: 'cookie',
    LB_SESSION_PERSISTENCE_HTTP_COOKIE: 'cookie'}

HEALTH_MONITOR_MAP = {
    LB_HEALTH_MONITOR_PING: 'icmp',
    LB_HEALTH_MONITOR_TCP: 'tcp',
    LB_HEALTH_MONITOR_HTTP: 'http',
    LB_HEALTH_MONITOR_HTTPS: 'tcp'}

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

    def __init__(self, vcns_driver):
        super(EdgeLoadbalancerBaseManager, self).__init__()
        self.vcns_driver = vcns_driver

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

    @property
    def vcns(self):
        return self.vcns_driver.vcns


class EdgeLoadbalancerDriverV2(object):
    @log_helpers.log_method_call
    def __init__(self):
        self.loadbalancer = EdgeLoadBalancerManager(self)
        self.listener = EdgeListenerManager(self)
        self.pool = EdgePoolManager(self)
        self.member = EdgeMemberManager(self)
        self.healthmonitor = EdgeHealthMonitorManager(self)


class EdgeLoadBalancerManager(EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeLoadBalancerManager, self).__init__(vcns_driver)

    @log_helpers.log_method_call
    def create(self, context, lb):
        try:
            edge_id = lb_common.get_lbaas_edge_id_for_subnet(
                context, self.core_plugin, lb.vip_subnet_id)

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

    @log_helpers.log_method_call
    def update(self, context, old_lb, new_lb):
        self.lb_driver.load_balancer.successful_completion(context, new_lb)

    @log_helpers.log_method_call
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

    @log_helpers.log_method_call
    def refresh(self, context, lb):
        pass

    @log_helpers.log_method_call
    def stats(self, context, lb):
        pass


class EdgeListenerManager(EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeListenerManager, self).__init__(vcns_driver)

    @log_helpers.log_method_call
    def create(self, context, listener):
        default_pool = None

        lb_id = listener.loadbalancer_id

        if listener.default_pool and listener.default_pool.id:
            pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                context.session, lb_id, listener.id, listener.default_pool.id)
            if pool_binding:
                default_pool = pool_binding['edge_pool_id']

        app_profile = listener_to_edge_app_profile(listener)
        app_profile_id = None

        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        edge_id = lb_binding['edge_id']
        try:
            h = (self.vcns.create_app_profile(edge_id, app_profile))[0]
            app_profile_id = lb_common.extract_resource_id(h['location'])
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.listener.failed_completion(context, listener)
                LOG.error(_LE('Failed to create app profile on edge: %s'),
                          lb_binding['edge_id'])

        vse = listener_to_edge_vse(listener, lb_binding['vip_address'],
                                   default_pool,
                                   app_profile_id)

        try:
            h = self.vcns.create_vip(edge_id, vse)[0]
            edge_vse_id = lb_common.extract_resource_id(h['location'])

            nsxv_db.add_nsxv_lbaas_listener_binding(context.session,
                                                    lb_id,
                                                    listener.id,
                                                    app_profile_id,
                                                    edge_vse_id)
            self.lb_driver.listener.successful_completion(context, listener)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.listener.failed_completion(context, listener)
                LOG.error(_LE('Failed to create vip on Edge: %s'), edge_id)
                self.vcns.delete_app_profile(edge_id, app_profile_id)

    @log_helpers.log_method_call
    def update(self, context, old_listener, new_listener):

        default_pool = None
        if new_listener.default_pool.id:
            pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
                context.session, new_listener.default_pool.id)
            if pool_binding:
                default_pool = pool_binding['edge_pool_id']

        lb_id = new_listener.loadbalancer_id
        listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
            context.session, lb_id, new_listener.id)
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        edge_id = lb_binding['edge_id']

        app_profile_id = listener_binding['app_profile_id']
        app_profile = listener_to_edge_app_profile(new_listener)

        try:
            self.vcns.update_app_profile(edge_id, app_profile_id, app_profile)

            vse = listener_to_edge_vse(new_listener,
                                       lb_binding['vip_address'],
                                       default_pool,
                                       app_profile_id)

            self.vcns.update_vip(edge_id, listener_binding['vse_id'], vse)

            self.lb_driver.listener.successful_completion(context,
                                                          new_listener)
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.listener.failed_completion(context,
                                                          new_listener)
                LOG.error(_LE('Failed to update app profile on edge: %s'),
                          edge_id)

    @log_helpers.log_method_call
    def delete(self, context, listener):
        lb_id = listener.loadbalancer_id
        listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
            context.session, lb_id, listener.id)
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)

        edge_id = lb_binding['edge_id']
        edge_vse_id = listener_binding['vse_id']
        app_profile_id = listener_binding['app_profile_id']

        try:
            self.vcns.delete_vip(edge_id, edge_vse_id)

        except nsxv_exc.ResourceNotFound:
            LOG.error(_LE('vip not found on edge: %s'), edge_id)
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.listener.failed_completion(context, listener)
                LOG.error(
                    _LE('Failed to delete vip on edge: %s'), edge_id)

        try:
            self.vcns.delete_app_profile(edge_id, app_profile_id)
        except nsxv_exc.ResourceNotFound:
            LOG.error(_LE('app profile not found on edge: %s'), edge_id)
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.listener.failed_completion(context, listener)
                LOG.error(
                    _LE('Failed to delete app profile on Edge: %s'), edge_id)

        nsxv_db.del_nsxv_lbaas_listener_binding(context.session, lb_id,
                                                listener.id)

        self.lb_driver.listener.successful_completion(
            context, listener, delete=True)


class EdgePoolManager(EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgePoolManager, self).__init__(vcns_driver)

    @log_helpers.log_method_call
    def create(self, context, pool):

        edge_pool = {
            'name': 'pool_' + pool.id,
            'description': getattr(pool, 'description', getattr(pool, 'name')),
            'algorithm': BALANCE_MAP.get(pool.lb_algorithm, 'round-robin'),
            'transparent': False
        }

        listener = pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
            context.session, lb_id, listener.id)

        edge_id = lb_binding['edge_id']

        try:
            h = self.vcns.create_pool(edge_id, edge_pool)[0]
            edge_pool_id = lb_common.extract_resource_id(h['location'])
            nsxv_db.add_nsxv_lbaas_pool_binding(context.session, lb_id,
                                                listener.id,
                                                pool.id,
                                                edge_pool_id)

            # Associate listener with pool
            vse = listener_to_edge_vse(listener,
                                       lb_binding['vip_address'],
                                       edge_pool_id,
                                       listener_binding['app_profile_id'])
            self.vcns.update_vip(edge_id, listener_binding['vse_id'], vse)

            self.lb_driver.pool.successful_completion(context, pool)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.pool.failed_completion(context, pool)
                LOG.error(_LE('Failed to create pool %s'), pool['id'])

    @log_helpers.log_method_call
    def update(self, context, old_pool, new_pool):
        edge_pool = {
            'name': 'pool_' + new_pool.id,
            'description': getattr(new_pool, 'description',
                                   getattr(new_pool, 'name')),
            'algorithm': BALANCE_MAP.get(new_pool.lb_method, 'round-robin'),
            'transparent': False
        }

        listener = new_pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, listener.id, new_pool.id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        try:
            self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

            self.lb_driver.pool.successful_completion(context, new_pool)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.pool.failed_completion(context, new_pool)
                LOG.error(_LE('Failed to update pool %s'), new_pool['id'])

    @log_helpers.log_method_call
    def delete(self, context, pool):
        listener = pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, listener.id, pool.id)
        listener_binding = nsxv_db.get_nsxv_lbaas_listener_binding(
            context.session, lb_id, listener.id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        try:
            vse = listener_to_edge_vse(listener,
                                       lb_binding['vip_address'],
                                       None,
                                       listener_binding['app_profile_id'])
            self.vcns.update_vip(edge_id, listener_binding['vse_id'], vse)
            self.vcns.delete_pool(edge_id, edge_pool_id)
            self.lb_driver.pool.successful_completion(
                context, pool, delete=True)

        except nsxv_exc.VcnsApiException:
            self.lb_driver.pool.failed_completion(context, pool)
            LOG.error(_LE('Failed to delete pool %s'), pool['id'])


class EdgeMemberManager(EdgeLoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeMemberManager, self).__init__(vcns_driver)
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

    @log_helpers.log_method_call
    def create(self, context, member):
        listener = member.pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, listener.id, member.pool_id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']
        edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]
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
            self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

            member_ips = self._get_pool_member_ips(member.pool, 'add',
                                                   member.address)
            lb_common.update_pool_fw_rule(self.vcns, member['pool_id'],
                                          edge_id,
                                          self._get_lbaas_fw_section_id(),
                                          member_ips)

            self.lb_driver.member.successful_completion(context, member)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.member.failed_completion(context, member)
                LOG.error(_LE('Failed to create member on edge: %s'), edge_id)

    @log_helpers.log_method_call
    def update(self, context, old_member, new_member):
        listener = new_member.pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(context.session,
                                                           lb_id, listener.id,
                                                           new_member.pool_id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        edge_member = {
            'ipAddress': new_member.address,
            'weight': new_member.weight,
            'port': new_member.protocol_port,
            'monitorPort': new_member.protocol_port,
            'name': lb_common.get_member_id(new_member.id),
            'condition':
                'enabled' if new_member.admin_state_up else 'disabled'}

        edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]

        for i, m in enumerate(edge_pool['member']):
            if m['name'] == lb_common.get_member_id(new_member.id):
                edge_pool['member'][i] = edge_member
                break

        try:
            self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

            self.lb_driver.member.successful_completion(context, new_member)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.member.failed_completion(context, new_member)
                LOG.error(_LE('Failed to update member on edge: %s'), edge_id)

    @log_helpers.log_method_call
    def delete(self, context, member):
        listener = member.pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, listener.id, member.pool_id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]

        for i, m in enumerate(edge_pool['member']):
            if m['name'] == lb_common.get_member_id(member['id']):
                edge_pool['member'].pop(i)
                break

        try:
            self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

            self.lb_driver.member.successful_completion(
                context, member, delete=True)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.member.failed_completion(context, member)
                LOG.error(_LE('Failed to delete member on edge: %s'), edge_id)


class EdgeHealthMonitorManager(EdgeLoadbalancerBaseManager):

    def _convert_lbaas_monitor(self, hm):
        """
        Transform OpenStack health monitor dict to NSXv health monitor dict.
        """
        mon = {
            'type': HEALTH_MONITOR_MAP.get(
                hm.type, 'icmp'),
            'interval': hm.delay,
            'timeout': hm.timeout,
            'maxRetries': hm.max_retries,
            'name': hm.id}

        if hm.http_method:
            mon['method'] = hm.http_method

        if hm.url_path:
            mon['url'] = hm.url_path
        return mon

    @log_helpers.log_method_call
    def __init__(self, vcns_driver):
        super(EdgeHealthMonitorManager, self).__init__(vcns_driver)

    @log_helpers.log_method_call
    def create(self, context, hm):
        listener = hm.pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, listener.id, hm.pool.id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        hm_binding = nsxv_db.get_nsxv_lbaas_monitor_binding(
            context.session, lb_id, listener.id, hm.pool.id, hm.id, edge_id)
        edge_mon_id = None

        if hm_binding:
            edge_mon_id = hm_binding['edge_monitor_id']
        else:
            edge_monitor = self._convert_lbaas_monitor(hm)
            try:
                h = self.vcns.create_health_monitor(edge_id, edge_monitor)[0]
                edge_mon_id = lb_common.extract_resource_id(h['location'])

                nsxv_db.add_nsxv_lbaas_monitor_binding(
                    context.session, lb_id, listener.id, hm.pool.id, hm.id,
                    edge_id, edge_mon_id)

            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lb_driver.health_monitor.failed_completion(
                        context, hm)
                    LOG.error(_LE('Failed to create health monitor on edge: %s'
                                  ), edge_id)

        try:
            # Associate monitor with Edge pool
            edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]
            if edge_pool['monitorId']:
                edge_pool['monitorId'].append(edge_mon_id)
            else:
                edge_pool['monitorId'] = [edge_mon_id]

            self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.health_monitor.failed_completion(context, hm)
                LOG.error(
                    _LE('Failed to create health monitor on edge: %s'),
                    edge_id)

        self.lb_driver.health_monitor.successful_completion(context, hm)

    @log_helpers.log_method_call
    def update(self, context, old_hm, new_hm):
        listener = new_hm.pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)

        edge_id = lb_binding['edge_id']

        hm_binding = nsxv_db.get_nsxv_lbaas_monitor_binding(
            context.session, lb_id, listener.id, new_hm.pool.id, new_hm.id,
            edge_id)

        edge_monitor = self._convert_lbaas_monitor(new_hm)

        try:
            self.vcns.update_health_monitor(edge_id,
                                            hm_binding['edge_monitor_id'],
                                            edge_monitor)

        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.health_monitor.failed_completion(context,
                                                                new_hm)
                LOG.error(
                    _LE('Failed to update monitor on edge: %s'), edge_id)

        self.lb_driver.health_monitor.successful_completion(context, new_hm)

    @log_helpers.log_method_call
    def delete(self, context, hm):
        listener = hm.pool.listener
        lb_id = listener.loadbalancer_id
        lb_binding = nsxv_db.get_nsxv_lbaas_loadbalancer_binding(
            context.session, lb_id)
        pool_binding = nsxv_db.get_nsxv_lbaas_pool_binding(
            context.session, lb_id, listener.id, hm.pool.id)

        edge_id = lb_binding['edge_id']
        edge_pool_id = pool_binding['edge_pool_id']

        hm_binding = nsxv_db.get_nsxv_lbaas_monitor_binding(
            context.session, lb_id, listener.id, hm.pool.id, hm.id, edge_id)

        edge_pool = self.vcns.get_pool(edge_id, edge_pool_id)[1]
        edge_pool['monitorId'].remove(hm_binding['edge_monitor_id'])

        try:
            self.vcns.update_pool(edge_id, edge_pool_id, edge_pool)
        except nsxv_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                self.lb_driver.health_monitor.failed_completion(context, hm)
                LOG.error(
                    _LE('Failed to delete monitor mapping on edge: %s'),
                    edge_id)

        # If this monitor is not used on this edge anymore, delete it
        if not edge_pool['monitorId']:
            try:
                self.vcns.delete_health_monitor(hm_binding['edge_id'],
                                                hm_binding['edge_monitor_id'])
            except nsxv_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    self.lb_driver.health_monitor.failed_completion(context,
                                                                    hm)
                    LOG.error(
                        _LE('Failed to delete monitor on edge: %s'), edge_id)

        nsxv_db.del_nsxv_lbaas_monitor_binding(
            context.session, lb_id, listener.id, hm.pool.id, hm.id, edge_id)
        self.lb_driver.health_monitor.successful_completion(
            context, hm, delete=True)
