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
    def __init__(self, loadbalancer=None, listener=None, pool=None,
                 member=None, healthmonitor=None, l7policy=None, l7rule=None):
        # Initialize RPC listener
        topic = 'vmware_nsxv_edge_lb'
        server = socket.gethostname()
        transport = messaging.get_transport(cfg.CONF)
        target = messaging.Target(topic=topic, server=server,
                                  exchange="common", fanout=False)
        endpoints = [NSXOctaviaEndpoint(loadbalancer=loadbalancer,
                                        listener=listener,
                                        pool=pool, member=member,
                                        healthmonitor=healthmonitor,
                                        l7policy=l7policy, l7rule=l7rule)]
        access_policy = dispatcher.DefaultRPCAccessPolicy
        self.octavia_server = messaging.get_rpc_server(
            transport, target, endpoints, executor='eventlet',
            access_policy=access_policy)
        self.octavia_server.start()


class NSXOctaviaEndpoint(object):
    target = messaging.Target(namespace="control", version='1.0')

    def __init__(self, loadbalancer=None, listener=None, pool=None,
                 member=None, healthmonitor=None, l7policy=None, l7rule=None):
        self.loadbalancer = loadbalancer
        self.listener = listener
        self.pool = pool
        self.member = member
        self.healthmonitor = healthmonitor
        self.l7policy = l7policy
        self.l7rule = l7rule
        # TODO(asarfaty) add completers to return status to Octavia

    @log_helpers.log_method_call
    def loadbalancer_create(self, ctxt, loadbalancer):
        ctx = neutron_context.Context(None, loadbalancer['project_id'])
        self.loadbalancer.create(ctx, loadbalancer)
        LOG.info("NSX load balancer creation ended")

    @log_helpers.log_method_call
    def loadbalancer_delete(self, ctxt, loadbalancer, cascade=False):
        ctx = neutron_context.Context(None, loadbalancer['project_id'])
        # TODO(asarfaty) add support for cascade
        self.loadbalancer.delete(ctx, loadbalancer)

    @log_helpers.log_method_call
    def loadbalancer_update(self, ctxt, old_loadbalancer, new_loadbalancer):
        ctx = neutron_context.Context(None, old_loadbalancer['project_id'])
        self.loadbalancer.update(ctx, old_loadbalancer, new_loadbalancer)

    # Listener
    @log_helpers.log_method_call
    def listener_create(self, ctxt, listener, cert):
        ctx = neutron_context.Context(None, listener['project_id'])
        self.listener.create(ctx, listener, certificate=cert)
        LOG.info("NSX listener creation ended")

    @log_helpers.log_method_call
    def listener_delete(self, ctxt, listener):
        ctx = neutron_context.Context(None, listener['project_id'])
        self.listener.delete(ctx, listener)

    @log_helpers.log_method_call
    def listener_update(self, ctxt, old_listener, new_listener, cert):
        ctx = neutron_context.Context(None, old_listener['project_id'])
        self.listener.update(ctx, old_listener, new_listener, certificate=cert)

    # Pool
    @log_helpers.log_method_call
    def pool_create(self, ctxt, pool):
        ctx = neutron_context.Context(None, pool['project_id'])
        self.pool.create(ctx, pool)
        LOG.info("NSX pool creation ended")

    @log_helpers.log_method_call
    def pool_delete(self, ctxt, pool):
        ctx = neutron_context.Context(None, pool['project_id'])
        self.pool.delete(ctx, pool)

    @log_helpers.log_method_call
    def pool_update(self, ctxt, old_pool, new_pool):
        ctx = neutron_context.Context(None, old_pool['project_id'])
        self.pool.update(ctx, old_pool, new_pool)

    # Member
    @log_helpers.log_method_call
    def member_create(self, ctxt, member):
        ctx = neutron_context.Context(None, member['project_id'])
        self.member.create(ctx, member)
        LOG.info("NSX member creation ended")

    @log_helpers.log_method_call
    def member_delete(self, ctxt, member):
        ctx = neutron_context.Context(None, member['project_id'])
        self.member.delete(ctx, member)

    @log_helpers.log_method_call
    def member_update(self, ctxt, old_member, new_member):
        ctx = neutron_context.Context(None, old_member['project_id'])
        self.member.update(ctx, old_member, new_member)

    # Health Monitor
    @log_helpers.log_method_call
    def healthmonitor_create(self, ctxt, healthmonitor):
        ctx = neutron_context.Context(None, healthmonitor['project_id'])
        self.healthmonitor.create(ctx, healthmonitor)
        LOG.info("NSX monitor creation ended")

    @log_helpers.log_method_call
    def healthmonitor_delete(self, ctxt, healthmonitor):
        ctx = neutron_context.Context(None, healthmonitor['project_id'])
        self.healthmonitor.delete(ctx, healthmonitor)

    @log_helpers.log_method_call
    def healthmonitor_update(self, ctxt, old_healthmonitor, new_healthmonitor):
        ctx = neutron_context.Context(None, old_healthmonitor['project_id'])
        self.healthmonitor.update(ctx, old_healthmonitor, new_healthmonitor)

    # L7 Policy
    @log_helpers.log_method_call
    def l7policy_create(self, ctxt, l7policy):
        ctx = neutron_context.Context(None, l7policy['project_id'])
        self.l7policy.create(ctx, l7policy)
        LOG.info("NSX L7 policy creation ended")

    @log_helpers.log_method_call
    def l7policy_delete(self, ctxt, l7policy):
        ctx = neutron_context.Context(None, l7policy['project_id'])
        self.l7policy.delete(ctx, l7policy)

    @log_helpers.log_method_call
    def l7policy_update(self, ctxt, old_l7policy, new_l7policy):
        ctx = neutron_context.Context(None, old_l7policy['project_id'])
        self.l7policy.update(ctx, old_l7policy, new_l7policy)

    # L7 Rule
    @log_helpers.log_method_call
    def l7rule_create(self, ctxt, l7rule):
        ctx = neutron_context.Context(None, l7rule['project_id'])
        self.l7rule.create(ctx, l7rule)
        LOG.info("NSX L7 rule creation ended")

    @log_helpers.log_method_call
    def l7rule_delete(self, ctxt, l7rule):
        ctx = neutron_context.Context(None, l7rule['project_id'])
        self.l7rule.delete(ctx, l7rule)

    @log_helpers.log_method_call
    def l7rule_update(self, ctxt, old_l7rule, new_l7rule):
        ctx = neutron_context.Context(None, old_l7rule['project_id'])
        self.l7rule.update(ctx, old_l7rule, new_l7rule)
