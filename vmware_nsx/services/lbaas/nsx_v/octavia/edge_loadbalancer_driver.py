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

from oslo_config import cfg
from oslo_log import helpers as log_helpers
import oslo_messaging as messaging
from oslo_messaging.rpc import dispatcher


class EdgeLoadbalancerDriverV2(object):
    @log_helpers.log_method_call
    def __init__(self):
        topic = 'vmware_nsxv_edge_lb'
        server = socket.gethostname()
        transport = messaging.get_transport(cfg.CONF)
        target = messaging.Target(topic=topic, server=server,
                                  exchange="common", fanout=False)
        endpoints = [EdgeLoadbalancerDriverEndpoint()]
        access_policy = dispatcher.DefaultRPCAccessPolicy
        self.octavia_server = messaging.get_rpc_server(
            transport, target, endpoints, executor='eventlet',
            access_policy=access_policy)
        self.octavia_server.start()


class EdgeLoadbalancerDriverEndpoint(object):
    target = messaging.Target(namespace="control", version='1.0')

    @log_helpers.log_method_call
    def create_load_balancer(self, context, lb):
        pass

    @log_helpers.log_method_call
    def update_load_balancer(self, context, old_lb, new_lb):
        pass

    @log_helpers.log_method_call
    def delete_load_balancer(self, context, lb):
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
    def create_health_monitor(self, context, hm):
        pass

    @log_helpers.log_method_call
    def update_health_monitor(self, context, old_hm, new_hm):
        pass

    @log_helpers.log_method_call
    def delete_health_monitor(self, context, hm):
        pass
