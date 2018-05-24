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

import abc
import six
import socket

from neutron_lib import context as neutron_context
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging as messaging
from oslo_messaging.rpc import dispatcher

LOG = logging.getLogger(__name__)


class NSXOctaviaListener(object):
    @log_helpers.log_method_call
    def __init__(self):
        # Initialize RPC listener
        topic = 'vmware_nsxv_edge_lb'
        server = socket.gethostname()
        transport = messaging.get_transport(cfg.CONF)
        target = messaging.Target(topic=topic, server=server,
                                  exchange="common", fanout=False)
        endpoints = [NSXOctaviaEndpoint()]
        access_policy = dispatcher.DefaultRPCAccessPolicy
        self.octavia_server = messaging.get_rpc_server(
            transport, target, endpoints, executor='eventlet',
            access_policy=access_policy)
        self.octavia_server.start()


class NSXOctaviaEndpoint(object):
    target = messaging.Target(namespace="control", version='1.0')

    @log_helpers.log_method_call
    def loadbalancer_create(self, ctxt, loadbalancer):
        pass

    @log_helpers.log_method_call
    def loadbalancer_delete(self, ctxt, loadbalancer_id, cascade=False):
        pass

    @log_helpers.log_method_call
    def loadbalancer_update(self, ctxt, loadbalancer):
        pass

    # Listener
    @log_helpers.log_method_call
    def listener_create(self, ctxt, listener, cert):
        pass

    @log_helpers.log_method_call
    def listener_delete(self, ctxt, listener_id):
        pass

    @log_helpers.log_method_call
    def listener_update(self, ctxt, listener):
        pass

    # Pool
    @log_helpers.log_method_call
    def pool_create(self, ctxt, pool):
        pass

    @log_helpers.log_method_call
    def pool_delete(self, ctxt, pool_id):
        pass

    @log_helpers.log_method_call
    def pool_update(self, ctxt, pool):
        pass

    # Member
    @log_helpers.log_method_call
    def member_create(self, ctxt, member):
        pass

    @log_helpers.log_method_call
    def member_delete(self, ctxt, member_id):
        pass

    @log_helpers.log_method_call
    def member_update(self, ctxt, member):
        pass

    # Health Monitor
    @log_helpers.log_method_call
    def health_monitor_create(self, ctxt, healthmonitor):
        pass

    @log_helpers.log_method_call
    def health_monitor_delete(self, ctxt, healthmonitor_id):
        pass

    @log_helpers.log_method_call
    def health_monitor_update(self, ctxt, healthmonitor):
        pass

    # L7 Policy
    @log_helpers.log_method_call
    def l7policy_create(self, ctxt, l7policy):
        pass

    @log_helpers.log_method_call
    def l7policy_delete(self, ctxt, l7policy_id):
        pass

    @log_helpers.log_method_call
    def l7policy_update(self, ctxt, l7policy):
        pass

    # L7 Rule
    @log_helpers.log_method_call
    def l7rule_create(self, ctxt, l7rule):
        pass

    @log_helpers.log_method_call
    def l7rule_delete(self, ctxt, l7rule_id):
        pass

    @log_helpers.log_method_call
    def l7rule_update(self, ctxt, l7rule):
        pass
