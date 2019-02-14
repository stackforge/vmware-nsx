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
import time

import eventlet

from neutron_lib import context as neutron_context
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging as messaging
from oslo_messaging.rpc import dispatcher

from vmware_nsx.services.lbaas.octavia import constants

try:
    from neutron_lbaas.db.loadbalancer import models
except ImportError:
    # LBaaS project not found.
    from vmware_nsx.services.lbaas import lbaas_mocks as models

LOG = logging.getLogger(__name__)


class NSXOctaviaListener(object):
    @log_helpers.log_method_call
    def __init__(self, loadbalancer=None, listener=None, pool=None,
                 member=None, healthmonitor=None, l7policy=None, l7rule=None):
        self._init_rpc_messaging()
        self._init_rpc_listener(healthmonitor, l7policy, l7rule, listener,
                                loadbalancer, member, pool)

    def _init_rpc_messaging(self):
        topic = constants.DRIVER_TO_OCTAVIA_TOPIC
        transport = messaging.get_rpc_transport(cfg.CONF)
        target = messaging.Target(topic=topic, exchange="common",
                                  namespace='control', fanout=False,
                                  version='1.0')
        self.client = messaging.RPCClient(transport, target)

    def _init_rpc_listener(self, healthmonitor, l7policy, l7rule, listener,
                           loadbalancer, member, pool):
        # Initialize RPC listener
        topic = constants.OCTAVIA_TO_DRIVER_TOPIC
        server = socket.gethostname()
        transport = messaging.get_rpc_transport(cfg.CONF)
        target = messaging.Target(topic=topic, server=server,
                                  exchange="common", fanout=False)
        self.endpoints = [NSXOctaviaListenerEndpoint(
            client=self.client, loadbalancer=loadbalancer, listener=listener,
            pool=pool, member=member, healthmonitor=healthmonitor,
            l7policy=l7policy, l7rule=l7rule)]
        access_policy = dispatcher.DefaultRPCAccessPolicy
        self.octavia_server = messaging.get_rpc_server(
            transport, target, self.endpoints, executor='eventlet',
            access_policy=access_policy)
        self.octavia_server.start()


class NSXOctaviaListenerEndpoint(object):
    target = messaging.Target(namespace="control", version='1.0')

    def __init__(self, client=None, loadbalancer=None, listener=None,
                 pool=None, member=None, healthmonitor=None, l7policy=None,
                 l7rule=None):

        self.client = client
        self.loadbalancer = loadbalancer
        self.listener = listener
        self.pool = pool
        self.member = member
        self.healthmonitor = healthmonitor
        self.l7policy = l7policy
        self.l7rule = l7rule

    def get_completor_func(self, obj_type, obj, delete=False):
        # return a method that will be called on success/failure completion
        def completor_func(success=True):
            LOG.debug("Octavia transaction completed. status %s",
                      'success' if success else 'failure')

            # calculate the provisioning and operating statuses
            main_prov_status = constants.ACTIVE
            parent_prov_status = constants.ACTIVE
            if not success:
                main_prov_status = constants.ERROR
                parent_prov_status = constants.ERROR
            elif delete:
                main_prov_status = constants.DELETED
            op_status = constants.ONLINE if success else constants.ERROR

            # add the status of the created/deleted/updated object
            status_dict = {
                obj_type: [{
                    'id': obj['id'],
                    constants.PROVISIONING_STATUS: main_prov_status,
                    constants.OPERATING_STATUS: op_status}]}

            # Get all its parents, and update their statuses as well
            loadbalancer_id = None
            listener_id = None
            pool_id = None
            policy_id = None
            if obj_type != constants.LOADBALANCERS:
                loadbalancer_id = None
                if obj.get('loadbalancer_id'):
                    loadbalancer_id = obj.get('loadbalancer_id')
                if obj.get('pool'):
                    pool_id = obj['pool']['id']
                    listener_id = obj['pool'].get('listener_id')
                    if not loadbalancer_id:
                        loadbalancer_id = obj['pool'].get('loadbalancer_id')
                elif obj.get('pool_id'):
                    pool_id = obj['pool_id']
                if obj.get('listener'):
                    listener_id = obj['listener']['id']
                    if not loadbalancer_id:
                        loadbalancer_id = obj['listener'].get(
                            'loadbalancer_id')
                elif obj.get('listener_id'):
                    listener_id = obj['listener_id']
                if obj.get('policy') and obj['policy'].get('listener'):
                    policy_id = obj['policy']['id']
                    if not listener_id:
                        listener_id = obj['policy']['listener']['id']
                        if not loadbalancer_id:
                            loadbalancer_id = obj['policy']['listener'].get(
                                'loadbalancer_id')

                if loadbalancer_id:
                    status_dict[constants.LOADBALANCERS] = [{
                        'id': loadbalancer_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]
                if listener_id:
                    status_dict[constants.LISTENERS] = [{
                        'id': listener_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]
                if pool_id:
                    status_dict[constants.POOLS] = [{
                        'id': pool_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]
                if policy_id:
                    status_dict[constants.L7POLICIES] = [{
                        'id': policy_id,
                        constants.PROVISIONING_STATUS: parent_prov_status,
                        constants.OPERATING_STATUS: op_status}]

            LOG.debug("Octavia transaction completed with statuses %s",
                      status_dict)
            kw = {'status': status_dict}
            self.client.cast({}, 'update_loadbalancer_status', **kw)

        return completor_func

    def update_listener_statistics(self, statistics):
        kw = {'statistics': statistics}
        self.client.cast({}, 'update_listener_statistics', **kw)

    @log_helpers.log_method_call
    def loadbalancer_create(self, ctxt, loadbalancer):
        ctx = neutron_context.Context(None, loadbalancer['project_id'])
        completor = self.get_completor_func(constants.LOADBALANCERS,
                                            loadbalancer)
        try:
            self.loadbalancer.create(ctx, loadbalancer, completor)
        except Exception as e:
            LOG.error('NSX driver loadbalancer_create failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def loadbalancer_delete(self, ctxt, loadbalancer, cascade=False):
        ctx = neutron_context.Context(None, loadbalancer['project_id'])
        completor = self.get_completor_func(constants.LOADBALANCERS,
                                            loadbalancer, delete=True)
        # TODO(asarfaty): No support for cascade. It is blocked by the driver
        try:
            self.loadbalancer.delete(ctx, loadbalancer, completor)
        except Exception as e:
            LOG.error('NSX driver loadbalancer_delete failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def loadbalancer_update(self, ctxt, old_loadbalancer, new_loadbalancer):
        ctx = neutron_context.Context(None, old_loadbalancer['project_id'])
        completor = self.get_completor_func(constants.LOADBALANCERS,
                                            new_loadbalancer)
        try:
            self.loadbalancer.update(ctx, old_loadbalancer, new_loadbalancer,
                                     completor)
        except Exception as e:
            LOG.error('NSX driver loadbalancer_update failed %s', e)
            completor(success=False)

    # Listener
    @log_helpers.log_method_call
    def listener_create(self, ctxt, listener, cert):
        ctx = neutron_context.Context(None, listener['project_id'])
        completor = self.get_completor_func(constants.LISTENERS,
                                            listener)
        try:
            self.listener.create(ctx, listener, completor,
                                 certificate=cert)
        except Exception as e:
            LOG.error('NSX driver listener_create failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def listener_delete(self, ctxt, listener):
        ctx = neutron_context.Context(None, listener['project_id'])
        completor = self.get_completor_func(constants.LISTENERS,
                                            listener, delete=True)
        try:
            self.listener.delete(ctx, listener, completor)
        except Exception as e:
            LOG.error('NSX driver listener_delete failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def listener_update(self, ctxt, old_listener, new_listener, cert):
        ctx = neutron_context.Context(None, old_listener['project_id'])
        completor = self.get_completor_func(constants.LISTENERS,
                                            new_listener)
        try:
            self.listener.update(ctx, old_listener, new_listener,
                                 completor, certificate=cert)
        except Exception as e:
            LOG.error('NSX driver listener_update failed %s', e)
            completor(success=False)

    # Pool
    @log_helpers.log_method_call
    def pool_create(self, ctxt, pool):
        ctx = neutron_context.Context(None, pool['project_id'])
        completor = self.get_completor_func(constants.POOLS,
                                            pool)
        try:
            self.pool.create(ctx, pool, completor)
        except Exception as e:
            LOG.error('NSX driver pool_create failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def pool_delete(self, ctxt, pool):
        ctx = neutron_context.Context(None, pool['project_id'])
        completor = self.get_completor_func(constants.POOLS,
                                            pool, delete=True)
        try:
            self.pool.delete(ctx, pool, completor)
        except Exception as e:
            LOG.error('NSX driver pool_delete failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def pool_update(self, ctxt, old_pool, new_pool):
        ctx = neutron_context.Context(None, old_pool['project_id'])
        completor = self.get_completor_func(constants.POOLS,
                                            new_pool)
        try:
            self.pool.update(ctx, old_pool, new_pool, completor)
        except Exception as e:
            LOG.error('NSX driver pool_update failed %s', e)
            completor(success=False)

    # Member
    @log_helpers.log_method_call
    def member_create(self, ctxt, member):
        ctx = neutron_context.Context(None, member['project_id'])
        completor = self.get_completor_func(constants.MEMBERS,
                                            member)
        try:
            self.member.create(ctx, member, completor)
        except Exception as e:
            LOG.error('NSX driver member_create failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def member_delete(self, ctxt, member):
        ctx = neutron_context.Context(None, member['project_id'])
        completor = self.get_completor_func(constants.MEMBERS,
                                            member, delete=True)
        try:
            self.member.delete(ctx, member, completor)
        except Exception as e:
            LOG.error('NSX driver member_delete failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def member_update(self, ctxt, old_member, new_member):
        ctx = neutron_context.Context(None, old_member['project_id'])
        completor = self.get_completor_func(constants.MEMBERS,
                                            new_member)
        try:
            self.member.update(ctx, old_member, new_member, completor)
        except Exception as e:
            LOG.error('NSX driver member_update failed %s', e)
            completor(success=False)

    # Health Monitor
    @log_helpers.log_method_call
    def healthmonitor_create(self, ctxt, healthmonitor):
        ctx = neutron_context.Context(None, healthmonitor['project_id'])
        completor = self.get_completor_func(constants.HEALTHMONITORS,
                                            healthmonitor)
        try:
            self.healthmonitor.create(ctx, healthmonitor, completor)
        except Exception as e:
            LOG.error('NSX driver healthmonitor_create failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def healthmonitor_delete(self, ctxt, healthmonitor):
        ctx = neutron_context.Context(None, healthmonitor['project_id'])
        completor = self.get_completor_func(constants.HEALTHMONITORS,
                                            healthmonitor, delete=True)
        try:
            self.healthmonitor.delete(ctx, healthmonitor, completor)
        except Exception as e:
            LOG.error('NSX driver healthmonitor_delete failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def healthmonitor_update(self, ctxt, old_healthmonitor, new_healthmonitor):
        ctx = neutron_context.Context(None, old_healthmonitor['project_id'])
        completor = self.get_completor_func(constants.HEALTHMONITORS,
                                            new_healthmonitor)
        try:
            self.healthmonitor.update(ctx, old_healthmonitor,
                                      new_healthmonitor, completor)
        except Exception as e:
            LOG.error('NSX driver healthmonitor_update failed %s', e)
            completor(success=False)

    # L7 Policy
    @log_helpers.log_method_call
    def l7policy_create(self, ctxt, l7policy):
        ctx = neutron_context.Context(None, l7policy['project_id'])
        completor = self.get_completor_func(constants.L7POLICIES,
                                            l7policy)
        try:
            self.l7policy.create(ctx, l7policy, completor)
        except Exception as e:
            LOG.error('NSX driver l7policy_create failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def l7policy_delete(self, ctxt, l7policy):
        ctx = neutron_context.Context(None, l7policy['project_id'])
        completor = self.get_completor_func(constants.L7POLICIES,
                                            l7policy, delete=True)
        try:
            self.l7policy.delete(ctx, l7policy, completor)
        except Exception as e:
            LOG.error('NSX driver l7policy_delete failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def l7policy_update(self, ctxt, old_l7policy, new_l7policy):
        ctx = neutron_context.Context(None, old_l7policy['project_id'])
        completor = self.get_completor_func(constants.L7POLICIES,
                                            new_l7policy)
        try:
            self.l7policy.update(ctx, old_l7policy, new_l7policy, completor)
        except Exception as e:
            LOG.error('NSX driver l7policy_update failed %s', e)
            completor(success=False)

    # L7 Rule
    @log_helpers.log_method_call
    def l7rule_create(self, ctxt, l7rule):
        ctx = neutron_context.Context(None, l7rule['project_id'])
        completor = self.get_completor_func(constants.L7RULES, l7rule)
        try:
            self.l7rule.create(ctx, l7rule, completor)
        except Exception as e:
            LOG.error('NSX driver l7rule_create failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def l7rule_delete(self, ctxt, l7rule):
        ctx = neutron_context.Context(None, l7rule['project_id'])
        completor = self.get_completor_func(constants.L7RULES, l7rule,
                                            delete=True)
        try:
            self.l7rule.delete(ctx, l7rule, completor)
        except Exception as e:
            LOG.error('NSX driver l7rule_delete failed %s', e)
            completor(success=False)

    @log_helpers.log_method_call
    def l7rule_update(self, ctxt, old_l7rule, new_l7rule):
        ctx = neutron_context.Context(None, old_l7rule['project_id'])
        completor = self.get_completor_func(constants.L7RULES, new_l7rule)
        try:
            self.l7rule.update(ctx, old_l7rule, new_l7rule, completor)
        except Exception as e:
            LOG.error('NSX driver l7rule_update failed %s', e)
            completor(success=False)


class NSXOctaviaStatisticsCollector(object):
    def __init__(self, core_plugin, listener_stats_getter):
        self.core_plugin = core_plugin
        self.listener_stats_getter = listener_stats_getter
        if cfg.CONF.octavia_stats_interval:
            eventlet.spawn_n(self.thread_runner,
                             cfg.CONF.octavia_stats_interval)

    def thread_runner(self, interval):
        while True:
            time.sleep(interval)
            self.collect()

    def _get_nl_loadbalancers(self, context):
        """Getting the list of neutron-lbaas loadbalancers

        This is done directly from the neutron-lbaas DB to also support the
        case that the plugin is currently unavailable, but entries already
        exist on the DB.
        """
        if not hasattr(models.LoadBalancer, '__tablename__'):
            # No neutron-lbaas on this deployment
            return []

        nl_loadbalancers = context.session.query(models.LoadBalancer).all()
        return [lb.id for lb in nl_loadbalancers]

    def collect(self):
        if not self.core_plugin.octavia_listener:
            return

        endpoint = self.core_plugin.octavia_listener.endpoints[0]
        context = neutron_context.get_admin_context()

        # get the statistics of all the Octavia loadbalancers/listeners while
        # ignoring the neutron-lbaas loadbalancers.
        # Note(asarfaty): The Octavia plugin/DB is unavailable from the
        # neutron context, so there is no option to query the Octavia DB for
        # the relevant loadbalancers.
        nl_loadbalancers = self._get_nl_loadbalancers(context)
        listeners_stats = self.listener_stats_getter(
            context, self.core_plugin, ignore_list=nl_loadbalancers)
        if not listeners_stats:
            # Avoid sending empty stats
            return
        stats = {'listeners': listeners_stats}
        endpoint.update_listener_statistics(stats)
