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


from octavia.api.drivers import exceptions
from octavia.api.drivers import provider_base as driver_base
from octavia.api.drivers import utils as oct_utils
from octavia.db import api as db_apis
from octavia.db import repositories

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
        self.repositories = repositories.Repositories()
        self.cert_manager = stevedore_driver.DriverManager(
            namespace='octavia.cert_manager',
            name=cfg.CONF.certificates.cert_manager,
            invoke_on_load=True).driver

    def obj_to_dict(self, obj):
        obj_type = obj.__class__.__name__
        # create a dictionary out of the object
        obj_dict = obj.to_dict(recourse=True, render_unsets=True)

        def _get_load_balancer_dict(loadbalancer_id):
            # TODO(asarfaty): Add api in Octavia for this
            db_lb = self.repositories.load_balancer.get(
                db_apis.get_session(), id=loadbalancer_id)
            lb_dict = {}
            if db_lb:
                lb_dict = {'name': db_lb.name, 'id': loadbalancer_id}
                if db_lb.vip:
                    lb_dict['vip_port_id'] = db_lb.vip.port_id
                    lb_dict['vip_address'] = db_lb.vip.ip_address
                    lb_dict['vip_port_id'] = db_lb.vip.port_id
                    lb_dict['vip_network_id'] = db_lb.vip.network_id
                    lb_dict['vip_subnet_id'] = db_lb.vip.subnet_id
            return lb_dict

        # Update the dictionary to match what the nsx driver expects
        if 'tenant_id' not in obj_dict:
            tenant_id = obj_dict.get('project_id')
            if not tenant_id:
                # Try to get it from the attached loadbalancer
                if obj_dict.get('loadbalancer_id'):
                    db_lb = self.repositories.load_balancer.get(
                        db_apis.get_session(), id=obj_dict['loadbalancer_id'])
                    if db_lb:
                        tenant_id = db_lb.project_id
                if not tenant_id and 'pool_id' in obj_dict:
                    # Try to get it from the loadbalancer attached to the pool
                    # attached to this object
                    db_pool = self.repositories.pool.get(
                        db_apis.get_session(), id=obj_dict['pool_id'])
                    if db_pool:
                        tenant_id = db_pool.load_balancer.project_id
            if tenant_id:
                obj_dict['tenant_id'] = tenant_id
                obj_dict['project_id'] = tenant_id
            else:
                LOG.warning("Could bot find the tenant id for %(type)s "
                            "%(obj)s", {'type': obj_type, 'obj': obj_dict})

        if 'id' not in obj_dict:
            obj_dict['id'] = obj_dict.get('%s_id' % obj_type.lower())

        if obj_type == 'Listener':
            if 'sni_container_refs' in obj_dict:
                # TODO(asarfaty): when sni_container_refs=Unset it breaks the
                # json translation. The nsx driver ignores this field anyway
                del obj_dict['sni_container_refs']
            if 'l7policies' in obj_dict:
                obj_dict['l7_policies'] = obj_dict['l7policies']
            if obj_dict.get('loadbalancer_id'):
                # Generate a loadbalancer object
                obj_dict['loadbalancer'] = _get_load_balancer_dict(
                    obj_dict['loadbalancer_id'])

        elif obj_type == 'Pool':
            # The NSX driver expects a single listener
            # DEBUG ADIT - where is the listener object??
            obj_dict['listener'] = None

        elif obj_type == 'Member':
            # Get the pool object
            pool_dict = None
            if obj_dict['pool_id']:
                db_pool = self.repositories.pool.get(
                    db_apis.get_session(), id=obj_dict['pool_id'])
                pool_obj = oct_utils.db_pool_to_provider_pool(db_pool)
                pool_dict = pool_obj.to_dict(recourse=True, render_unsets=True)
            obj_dict['pool'] = pool_dict
            obj_dict['pool']['id'] = obj_dict['pool_id']
            # Get the load balamcer object
            if obj_dict['pool'].get('loadbalancer_id'):
                # Generate a loadbalancer object
                obj_dict['pool']['loadbalancer'] = _get_load_balancer_dict(
                    obj_dict['pool']['loadbalancer_id'])

        LOG.debug("Translated %(type)s to dictionary: %(obj)s",
                  {'type': obj_type, 'obj': obj_dict})
        return obj_dict

    # Load Balancer
    @log_helpers.log_method_call
    def create_vip_port(self, loadbalancer_id, project_id, vip_dictionary):
        raise exceptions.NotImplementedError()

    @log_helpers.log_method_call
    def loadbalancer_create(self, loadbalancer):
        kw = {'loadbalancer': self.obj_to_dict(loadbalancer)}
        self.client.cast({}, 'loadbalancer_create', **kw)

    @log_helpers.log_method_call
    def loadbalancer_delete(self, loadbalancer_id, cascade=False):
        kw = {'loadbalancer_id': loadbalancer_id, 'cascade': cascade}
        self.client.cast({}, 'loadbalancer_delete', **kw)

    @log_helpers.log_method_call
    def loadbalancer_failover(self, loadbalancer_id):
        LOG.error('Loadbalancer failover is handled by platform')
        raise exceptions.NotImplementedError()

    @log_helpers.log_method_call
    def loadbalancer_update(self, loadbalancer):
        kw = {'loadbalancer': self.obj_to_dict(loadbalancer)}
        self.client.cast({}, 'loadbalancer_update', **kw)

    # Listener
    @log_helpers.log_method_call
    def listener_create(self, listener):
        cert = None
        dict_list = self.obj_to_dict(listener)
        if dict_list.get('tls_certificate_id'):
            context = pecan.request.context.get('octavia_context')
            cert = self.cert_manager.get_cert(context,
                                              dict_list['tls_certificate_id'])
        kw = {'listener': dict_list, 'cert': cert}
        self.client.cast({}, 'listener_create', **kw)

    @log_helpers.log_method_call
    def listener_delete(self, listener_id):
        kw = {'listener_id': listener_id}
        self.client.cast({}, 'listener_delete', **kw)

    @log_helpers.log_method_call
    def listener_update(self, listener):
        cert = None
        dict_list = self.obj_to_dict(listener)
        if dict_list.get('tls_certificate_id'):
            context = pecan.request.context.get('octavia_context')
            cert = self.cert_manager.get_cert(context,
                                              dict_list['tls_certificate_id'])
        kw = {'listener': listener.to_dict(recourse=True), 'cert': cert}
        self.client.cast({}, 'listener_update', **kw)

    # Pool
    @log_helpers.log_method_call
    def pool_create(self, pool):
        kw = {'pool': self.obj_to_dict(pool)}
        self.client.cast({}, 'pool_create', **kw)

    @log_helpers.log_method_call
    def pool_delete(self, pool_id):
        kw = {'pool_id': pool_id}
        self.client.cast({}, 'pool_delete', **kw)

    @log_helpers.log_method_call
    def pool_update(self, pool):
        kw = {'pool': self.obj_to_dict(pool)}
        self.client.cast({}, 'pool_update', **kw)

    # Member
    @log_helpers.log_method_call
    def member_create(self, member):
        kw = {'member': self.obj_to_dict(member)}
        self.client.cast({}, 'member_create', **kw)

    @log_helpers.log_method_call
    def member_delete(self, member_id):
        kw = {'member_id': member_id}
        self.client.cast({}, 'member_delete', **kw)

    @log_helpers.log_method_call
    def member_update(self, member):
        kw = {'pool': self.obj_to_dict(member)}
        self.client.cast({}, 'member_update', **kw)

    @log_helpers.log_method_call
    def member_batch_update(self, members):
        raise NotImplementedError()

    # Health Monitor
    @log_helpers.log_method_call
    def health_monitor_create(self, healthmonitor):
        kw = {'healthmonitor': self.obj_to_dict(healthmonitor)}
        self.client.cast({}, 'healthmonitor_create', **kw)

    @log_helpers.log_method_call
    def health_monitor_delete(self, healthmonitor_id):
        kw = {'healthmonitor_id': healthmonitor_id}
        self.client.cast({}, 'healthmonitor_delete', **kw)

    @log_helpers.log_method_call
    def health_monitor_update(self, healthmonitor):
        kw = {'healthmonitor': self.obj_to_dict(healthmonitor)}
        self.client.cast({}, 'healthmonitor_update', **kw)

    # L7 Policy
    @log_helpers.log_method_call
    def l7policy_create(self, l7policy):
        #TODO(asarfaty) currently the Octavia code does not get here
        kw = {'l7policy': self.obj_to_dict(l7policy)}
        self.client.cast({}, 'l7policy_create', **kw)

    @log_helpers.log_method_call
    def l7policy_delete(self, l7policy_id):
        kw = {'l7policy_id': l7policy_id}
        self.client.cast({}, 'l7policy_delete', **kw)

    @log_helpers.log_method_call
    def l7policy_update(self, l7policy):
        kw = {'l7policy': self.obj_to_dict(l7policy)}
        self.client.cast({}, 'l7policy_update', **kw)

    # L7 Rule
    @log_helpers.log_method_call
    def l7rule_create(self, l7rule):
        #TODO(asarfaty) currently the Octavia code does not get here
        kw = {'l7rule': self.obj_to_dict(l7rule)}
        self.client.cast({}, 'l7rule_create', **kw)

    @log_helpers.log_method_call
    def l7rule_delete(self, l7rule_id):
        kw = {'l7rule_id': l7rule_id}
        self.client.cast({}, 'l7rule_delete', **kw)

    @log_helpers.log_method_call
    def l7rule_update(self, l7rule):
        kw = {'l7rule': self.obj_to_dict(l7rule)}
        self.client.cast({}, 'l7rule_update', **kw)

    # Flavor
    @log_helpers.log_method_call
    def get_supported_flavor_metadata(self):
        raise exceptions.NotImplementedError()

    @log_helpers.log_method_call
    def validate_flavor(self, flavor_metadata):
        raise exceptions.NotImplementedError()
