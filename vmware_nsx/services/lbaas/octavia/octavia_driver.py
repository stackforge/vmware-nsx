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

from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging as messaging
import pecan
from stevedore import driver as stevedore_driver


from octavia.api.drivers import provider_base as driver_base
from octavia.common import exceptions

LOG = logging.getLogger(__name__)
cfg.CONF.import_group('oslo_messaging', 'octavia.common.config')


class NSXOctaviaDriver(driver_base.ProviderDriver):
    @log_helpers.log_method_call
    def __init__(self):
        super(NSXOctaviaDriver, self).__init__()
        topic = 'vmware_nsxv_edge_lb'
        transport = messaging.get_transport(cfg.CONF)
        target = messaging.Target(topic=topic, exchange="common",
                                  namespace='control', fanout=False,
                                  version='1.0')
        self.client = messaging.RPCClient(transport, target)
        self.cert_manager = stevedore_driver.DriverManager(
            namespace='octavia.cert_manager',
            name=cfg.CONF.certificates.cert_manager,
            invoke_on_load=True).driver

    # Load Balancer
    @log_helpers.log_method_call
    def create_vip_port(self, loadbalancer_id, project_id, vip_dictionary):
        raise exceptions.ProviderNotImplementedError()

    @log_helpers.log_method_call
    def loadbalancer_create(self, loadbalancer):
        kw = {'loadbalancer': loadbalancer.to_dict(recourse=True)}
        self.client.cast({}, 'loadbalancer_create', **kw)

    @log_helpers.log_method_call
    def loadbalancer_delete(self, loadbalancer_id, cascade=False):
        kw = {'loadbalancer_id': loadbalancer_id, 'cascade': cascade}
        self.client.cast({}, 'loadbalancer_delete', **kw)

    @log_helpers.log_method_call
    def loadbalancer_failover(self, loadbalancer_id):
        LOG.error('Loadbalancer failover is handled by platform')
        raise exceptions.ProviderNotImplementedError()

    @log_helpers.log_method_call
    def loadbalancer_update(self, loadbalancer):
        kw = {'loadbalancer': loadbalancer.to_dict(recourse=True)}
        self.client.cast({}, 'loadbalancer_update', **kw)

    # Listener
    @log_helpers.log_method_call
    def listener_create(self, listener):
        cert = None
        if listener.tls_certificate_id:
            context = pecan.request.context.get('octavia_context')
            cert = self.cert_manager.get_cert(context,
                                              listener.tls_certificate_id)
        kw = {'listener': listener.to_dict(recourse=True), 'cert': cert}
        self.client.cast({}, 'listener_create', **kw)

    @log_helpers.log_method_call
    def listener_delete(self, listener_id):
        kw = {'listener_id': listener_id}
        self.client.cast({}, 'listener_delete', **kw)

    @log_helpers.log_method_call
    def listener_update(self, listener):
        kw = {'listener': listener.to_dict(recourse=True)}
        self.client.cast({}, 'listener_update', **kw)

    # Pool
    @log_helpers.log_method_call
    def pool_create(self, pool):
        kw = {'pool': pool.to_dict(recourse=True)}
        self.client.cast({}, 'pool_create', **kw)

    @log_helpers.log_method_call
    def pool_delete(self, pool_id):
        kw = {'pool_id': pool_id}
        self.client.cast({}, 'pool_delete', **kw)

    @log_helpers.log_method_call
    def pool_update(self, pool):
        kw = {'pool': pool.to_dict(recourse=True)}
        self.client.cast({}, 'pool_update', **kw)

    # Member
    @log_helpers.log_method_call
    def member_create(self, member):
        kw = {'member': member.to_dict(recourse=True)}
        self.client.cast({}, 'member_create', **kw)

    @log_helpers.log_method_call
    def member_delete(self, member_id):
        kw = {'member_id': member_id}
        self.client.cast({}, 'member_delete', **kw)

    @log_helpers.log_method_call
    def member_update(self, member):
        kw = {'pool': member.to_dict(recourse=True)}
        self.client.cast({}, 'member_update', **kw)

    @log_helpers.log_method_call
    def member_batch_update(self, members):
        raise NotImplementedError()

    # Health Monitor
    @log_helpers.log_method_call
    def health_monitor_create(self, healthmonitor):
        kw = {'healthmonitor': healthmonitor.to_dict(recourse=True)}
        self.client.cast({}, 'healthmonitor_create', **kw)

    @log_helpers.log_method_call
    def health_monitor_delete(self, healthmonitor_id):
        kw = {'healthmonitor_id': healthmonitor_id}
        self.client.cast({}, 'healthmonitor_delete', **kw)

    @log_helpers.log_method_call
    def health_monitor_update(self, healthmonitor):
        kw = {'healthmonitor': healthmonitor.to_dict(recourse=True)}
        self.client.cast({}, 'healthmonitor_update', **kw)

    # L7 Policy
    @log_helpers.log_method_call
    def l7policy_create(self, l7policy):
        kw = {'l7policy': l7policy.to_dict(recourse=True)}
        self.client.cast({}, 'l7policy_create', **kw)

    @log_helpers.log_method_call
    def l7policy_delete(self, l7policy_id):
        kw = {'l7policy_id': l7policy_id}
        self.client.cast({}, 'l7policy_delete', **kw)

    @log_helpers.log_method_call
    def l7policy_update(self, l7policy):
        kw = {'l7policy': l7policy.to_dict(recourse=True)}
        self.client.cast({}, 'l7policy_update', **kw)

    # L7 Rule
    @log_helpers.log_method_call
    def l7rule_create(self, l7rule):
        kw = {'l7rule': l7rule.to_dict(recourse=True)}
        self.client.cast({}, 'l7rule_create', **kw)

    @log_helpers.log_method_call
    def l7rule_delete(self, l7rule_id):
        kw = {'l7rule_id': l7rule_id}
        self.client.cast({}, 'l7rule_delete', **kw)

    @log_helpers.log_method_call
    def l7rule_update(self, l7rule):
        kw = {'l7rule': l7rule.to_dict(recourse=True)}
        self.client.cast({}, 'l7rule_update', **kw)

    # Flavor
    @log_helpers.log_method_call
    def get_supported_flavor_metadata(self):
        raise exceptions.ProviderNotImplementedError()

    @log_helpers.log_method_call
    def validate_flavor(self, flavor_metadata):
        raise exceptions.ProviderNotImplementedError()
