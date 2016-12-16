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

import abc
import six
import socket

from neutron_lib import context as neutron_context
from oslo_config import cfg
from oslo_log import helpers as log_helpers
import oslo_messaging as messaging
from oslo_messaging.rpc import dispatcher

from vmware_nsx.services.lbaas.nsx_v.common import base_mgr
from vmware_nsx.services.lbaas.nsx_v.common import healthmon_mgr as hm_mgr
from vmware_nsx.services.lbaas.nsx_v.common import l7policy_mgr
from vmware_nsx.services.lbaas.nsx_v.common import l7rule_mgr
from vmware_nsx.services.lbaas.nsx_v.common import listener_mgr
from vmware_nsx.services.lbaas.nsx_v.common import loadbalancer_mgr as lb_mgr
from vmware_nsx.services.lbaas.nsx_v.common import member_mgr
from vmware_nsx.services.lbaas.nsx_v.common import pool_mgr


class EdgeMQLoadbalancerDriver(object):
    @log_helpers.log_method_call
    def __init__(self):
        # Initialize RPC listener
        topic = 'vmware_nsxv_edge_lb'
        server = socket.gethostname()
        transport = messaging.get_transport(cfg.CONF)
        target = messaging.Target(topic=topic, server=server,
                                  exchange="common", fanout=False)
        endpoints = [EdgeMQLoadbalancerDriverEndpoint()]
        access_policy = dispatcher.DefaultRPCAccessPolicy
        self.octavia_server = messaging.get_rpc_server(
            transport, target, endpoints, executor='eventlet',
            access_policy=access_policy)
        self.octavia_server.start()


@six.add_metaclass(abc.ABCMeta)
class EdgeMQBaseManager(base_mgr.EdgeLoadbalancerBaseManager):
    def complete_success(self, context, obj, *args, **kwargs):
        pass

    def complete_failed(self, context, obj):
        pass


class EdgeMQLoadBalancerManager(EdgeMQBaseManager,
                                lb_mgr.EdgeLoadBalancerManager):
    def __init__(self, vcns_driver):
        super(EdgeMQLoadBalancerManager, self).__init__(vcns_driver)

    def create(self, context, lb):
        ctx = neutron_context.Context(None, lb['project_id'])
        self.base_create(ctx, lb, lb['id'], lb['vip']['ip_address'],
                         lb['vip']['subnet_id'], lb['project_id'])

    def update(self, context, old_lb, new_lb):
        ctx = neutron_context.Context(None, new_lb['project_id'])
        self.base_update(ctx, old_lb, new_lb)

    def delete(self, context, lb):
        ctx = neutron_context.Context(None, lb['project_id'])
        self.base_delete(ctx, lb, lb['id'])


class EdgeMQListenerManager(EdgeMQBaseManager,
                            listener_mgr.EdgeListenerManager):
    def __init__(self, vcns_driver):
        super(EdgeMQListenerManager, self).__init__(vcns_driver)


class EdgeMQPoolManager(EdgeMQBaseManager,
                        pool_mgr.EdgePoolManager):
    def __init__(self, vcns_driver):
        super(EdgeMQPoolManager, self).__init__(vcns_driver)


class EdgeMQMemberManager(EdgeMQBaseManager,
                          member_mgr.EdgeMemberManager):
    def __init__(self, vcns_driver):
        super(EdgeMQMemberManager, self).__init__(vcns_driver)


class EdgeMQHealthMonitorManager(EdgeMQBaseManager,
                                 hm_mgr.EdgeHealthMonitorManager):
    def __init__(self, vcns_driver):
        super(EdgeMQHealthMonitorManager, self).__init__(vcns_driver)


class EdgeMQL7PolicyManager(EdgeMQBaseManager,
                            l7policy_mgr.EdgeL7PolicyManager):
    def __init__(self, vcns_driver):
        super(EdgeMQL7PolicyManager, self).__init__(vcns_driver)


class EdgeMQL7RuleManager(EdgeMQBaseManager,
                          l7rule_mgr.EdgeL7RuleManager):
    def __init__(self, vcns_driver):
        super(EdgeMQL7RuleManager, self).__init__(vcns_driver)


class EdgeMQLoadbalancerDriverEndpoint(object):
    target = messaging.Target(namespace="control", version='1.0')

    def __init__(self):
        super(EdgeMQLoadbalancerDriverEndpoint, self).__init__()
        self.loadbalancer = EdgeMQLoadBalancerManager(self)
        self.listener = EdgeMQListenerManager(self)
        self.pool = EdgeMQPoolManager(self)
        self.member = EdgeMQMemberManager(self)
        self.healthmonitor = EdgeMQHealthMonitorManager(self)
        self.l7policy = EdgeMQL7PolicyManager(self)
        self.l7rule = EdgeMQL7RuleManager(self)

    @log_helpers.log_method_call
    def create_load_balancer(self, context, load_balancer):
        self.loadbalancer.create(context, load_balancer)

    @log_helpers.log_method_call
    def update_load_balancer(
            self, context, old_load_balancer, new_load_balancer):
        self.loadbalancer.update(context, old_load_balancer, new_load_balancer)

    @log_helpers.log_method_call
    def delete_load_balancer(self, context, load_balancer):
        self.loadbalancer.delete(context, load_balancer)

    @log_helpers.log_method_call
    def create_listener(self, context, listener):
        self.listener.create(context, listener)

    @log_helpers.log_method_call
    def update_listener(self, context, old_listener, new_listener):
        self.listener.update(context, old_listener, new_listener)

    @log_helpers.log_method_call
    def delete_listener(self, context, listener):
        self.listener.delete(context, listener)

    @log_helpers.log_method_call
    def create_pool(self, context, pool):
        self.pool.create(context, pool)

    @log_helpers.log_method_call
    def update_pool(self, context, old_pool, new_pool):
        self.pool.update(context, old_pool, new_pool)

    @log_helpers.log_method_call
    def delete_pool(self, context, pool):
        self.pool.delete(context, pool)

    @log_helpers.log_method_call
    def create_member(self, context, member):
        self.member.create(context, member)

    @log_helpers.log_method_call
    def update_member(self, context, old_member, new_member):
        self.member.update(context, old_member, new_member)

    @log_helpers.log_method_call
    def delete_member(self, context, member):
        self.member.delete(context, member)

    @log_helpers.log_method_call
    def create_health_monitor(self, context, health_monitor):
        self.healthmonitor.create(context, health_monitor)

    @log_helpers.log_method_call
    def update_health_monitor(
            self, context, old_health_monitor, new_health_monitor):
        self.healthmonitor.update(
            context, old_health_monitor, new_health_monitor)

    @log_helpers.log_method_call
    def delete_health_monitor(self, context, health_monitor):
        self.healthmonitor.delete(context, health_monitor)

    @log_helpers.log_method_call
    def create_l7policy(self, context, l7policy):
        self.l7policy.create(context, l7policy)

    @log_helpers.log_method_call
    def update_l7policy(self, context, old_l7policy, new_l7policy):
        self.l7policy.update(context, old_l7policy, new_l7policy)

    @log_helpers.log_method_call
    def delete_l7policy(self, context, l7policy):
        self.l7policy.delete(context, l7policy)

    @log_helpers.log_method_call
    def create_l7rule(self, context, l7rule):
        self.l7rule.create(context, l7rule)

    @log_helpers.log_method_call
    def update_l7rule(self, context, old_l7rule, new_l7rule):
        self.l7rule.update(context, old_l7rule, new_l7rule)

    @log_helpers.log_method_call
    def delete_l7rule(self, context, l7rule):
        self.l7rule.delete(context, l7rule)
