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
import socket

# TODO(kobis) Remove noqa
from octavia.common import data_models as lb_models  # noqa
from oslo_config import cfg
from oslo_log import helpers as log_helpers
import oslo_messaging as messaging
from oslo_messaging.rpc import dispatcher


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


class EdgeMQLoadbalancerDriverEndpoint(object):
    target = messaging.Target(namespace="control", version='1.0')

    @log_helpers.log_method_call
    def create_load_balancer(self, context, load_balancer):
        pass

    @log_helpers.log_method_call
    def update_load_balancer(
            self, context, old_load_balancer, new_load_balancer):
        pass

    @log_helpers.log_method_call
    def delete_load_balancer(self, context, load_balancer):
        pass

    @log_helpers.log_method_call
    def create_listener(self, context, listener):
        pass

    @log_helpers.log_method_call
    def update_listener(self, context, old_listener, new_listener):
        pass

    @log_helpers.log_method_call
    def delete_listener(self, context, listener):
        pass

    @log_helpers.log_method_call
    def create_pool(self, context, pool):
        pass

    @log_helpers.log_method_call
    def update_pool(self, context, old_pool, new_pool):
        pass

    @log_helpers.log_method_call
    def delete_pool(self, context, pool):
        pass

    @log_helpers.log_method_call
    def create_member(self, context, member):
        pass

    @log_helpers.log_method_call
    def update_member(self, context, old_member, new_member):
        pass

    @log_helpers.log_method_call
    def delete_member(self, context, member):
        pass

    @log_helpers.log_method_call
    def create_health_monitor(self, context, health_monitor):
        pass

    @log_helpers.log_method_call
    def update_health_monitor(
            self, context, old_health_monitor, new_health_monitor):
        pass

    @log_helpers.log_method_call
    def delete_health_monitor(self, context, health_monitor):
        pass

    @log_helpers.log_method_call
    def create_l7policy(self, context, l7policy):
        pass

    @log_helpers.log_method_call
    def update_l7policy(self, context, old_l7policy, new_l7policy):
        pass

    @log_helpers.log_method_call
    def delete_l7policy(self, context, l7policy):
        pass

    @log_helpers.log_method_call
    def create_l7rule(self, context, l7rule):
        pass

    @log_helpers.log_method_call
    def update_l7rule(self, old_l7rule, new_l7rule):
        pass

    @log_helpers.log_method_call
    def delete_l7rule(self, l7rule):
        pass
