# Copyright 2015 Rackspace
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
#
# 2016-02-01 (akang)
#    ported from neutron-lbaas to comply to tempest framework

import time

from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest import test

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from vmware_nsx_tempest._i18n import _
from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest.services.lbaas import health_monitors_client
from vmware_nsx_tempest.services.lbaas import listeners_client
from vmware_nsx_tempest.services.lbaas import load_balancers_client
from vmware_nsx_tempest.services.lbaas import members_client
from vmware_nsx_tempest.services.lbaas import pools_client

CONF = config.CONF
LOG = logging.getLogger(__name__)


class BaseTestCase(base.BaseNetworkTest):

    # This class picks non-admin credentials and run the tempest tests

    _lbs_to_delete = []
    _setup_core_network = True

    @classmethod
    def skip_checks(cls):
        super(BaseTestCase, cls).skip_checks()
        if not test.is_extension_enabled('lbaasv2', 'network'):
            msg = "lbaasv2 extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(BaseTestCase, cls).resource_setup()

        # credentials = cls.isolated_creds.get_primary_creds()
        # mgr = tempest_clients.Manager(credentials=credentials)
        mgr = cls.get_client_manager()
        cls.create_lbaas_clients(mgr)
        if cls._setup_core_network:
            cls.setup_lbaas_core_network()

    @classmethod
    def create_lbaas_clients(cls, mgr):
        cls.load_balancers_client = load_balancers_client.get_client(mgr)
        cls.listeners_client = listeners_client.get_client(mgr)
        cls.pools_client = pools_client.get_client(mgr)
        cls.members_client = members_client.get_client(mgr)
        cls.health_monitors_client = health_monitors_client.get_client(mgr)

    @classmethod
    def setup_lbaas_core_network(cls):
        rand_number = data_utils.rand_name()
        network_name = 'lbaas-network-' + rand_number
        router_name = 'lbaas-router-' + rand_number
        cls.network = cls.create_network(network_name)
        cls.subnet = cls.create_subnet(cls.network)
        cls.tenant_id = cls.subnet.get('tenant_id')
        cls.subnet_id = cls.subnet.get('id')
        # NSX-v: load-balancer's subnet need to attach to exclusive-router
        router_cfg = dict(router_name=router_name, router_type='exclusive')
        cls.router = cls.create_router(**router_cfg)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

    @classmethod
    def resource_cleanup(cls):
        for lb_id in cls._lbs_to_delete:
            try:
                statuses = cls._show_load_balancer_status_tree(lb_id)
                lb = statuses.get('loadbalancer')
            except exceptions.NotFound:
                continue
            for listener in lb.get('listeners', []):
                for pool in listener.get('pools'):
                    hm = pool.get('healthmonitor', None)
                    if hm:
                        cls._try_delete_resource(
                            cls.health_monitors_client.delete_health_monitor,
                            pool.get('healthmonitor').get('id'))
                        cls._wait_for_load_balancer_status(lb_id)
                    cls._try_delete_resource(cls.pools_client.delete_pool,
                                             pool.get('id'))
                    cls._wait_for_load_balancer_status(lb_id)
                    health_monitor = pool.get('healthmonitor', None)
                    if health_monitor:
                        cls._try_delete_resource(
                            cls.health_monitors_client.delete_health_monitor,
                            health_monitor.get('id'))
                    cls._wait_for_load_balancer_status(lb_id)
                cls._try_delete_resource(cls.listeners_client.delete_listener,
                                         listener.get('id'))
                cls._wait_for_load_balancer_status(lb_id)
            cls._try_delete_resource(cls._delete_load_balancer, lb_id)

        super(BaseTestCase, cls).resource_cleanup()

    @classmethod
    def setUpClass(cls):
        cls.LOG = logging.getLogger(cls._get_full_case_name())
        super(BaseTestCase, cls).setUpClass()

    def setUp(cls):
        cls.LOG.info(_LI('Starting: {0}').format(cls._testMethodName))
        super(BaseTestCase, cls).setUp()

    def tearDown(cls):
        super(BaseTestCase, cls).tearDown()
        cls.LOG.info(_LI('Finished: {0}\n').format(cls._testMethodName))

    @classmethod
    def _create_load_balancer(cls, wait=True, **lb_kwargs):
        lb = cls.load_balancers_client.create_load_balancer(**lb_kwargs)
        lb = lb.get('loadbalancer', lb)
        if wait:
            cls._wait_for_load_balancer_status(lb.get('id'))

        cls._lbs_to_delete.append(lb.get('id'))
        port = cls.ports_client.show_port(lb['vip_port_id'])
        cls.ports.append(port['port'])
        return lb

    @classmethod
    def _create_active_load_balancer(cls, **kwargs):
        lb = cls._create_load_balancer(**kwargs)
        lb = lb.get('loadbalancer', lb)
        lb = cls._wait_for_load_balancer_status(lb.get('id'))
        return lb

    @classmethod
    def _delete_load_balancer(cls, load_balancer_id, wait=True):
        cls.load_balancers_client.delete_load_balancer(load_balancer_id)
        if wait:
            cls._wait_for_load_balancer_status(
                load_balancer_id, delete=True)

    @classmethod
    def _update_load_balancer(cls, load_balancer_id, wait=True, **lb_kwargs):
        lb = cls.load_balancers_client.update_load_balancer(
            load_balancer_id, **lb_kwargs)
        lb = lb.get('loadbalancer', lb)
        if wait:
            cls._wait_for_load_balancer_status(
                load_balancer_id)
        return lb

    @classmethod
    def _show_load_balancer(cls, load_balancer_id):
        lb = cls.load_balancers_client.show_load_balancer(load_balancer_id)
        lb = lb.get('loadbalancer', lb)
        return lb

    @classmethod
    def _wait_for_load_balancer_status(cls, load_balancer_id,
                                       provisioning_status='ACTIVE',
                                       operating_status='ONLINE',
                                       delete=False):
        interval_time = 1
        timeout = 600
        end_time = time.time() + timeout
        lb = {}
        while time.time() < end_time:
            try:
                lb = cls.load_balancers_client.show_load_balancer(
                    load_balancer_id)
                if not lb:
                        # loadbalancer not found
                    if delete:
                        break
                    else:
                        raise Exception(
                            _("loadbalancer {lb_id} not"
                              " found").format(
                                  lb_id=load_balancer_id))
                lb = lb.get('loadbalancer', lb)
                if (lb.get('provisioning_status') == provisioning_status and
                        lb.get('operating_status') == operating_status):
                    break
                time.sleep(interval_time)
            except exceptions.NotFound as e:
                # if wait is for delete operation do break
                if delete:
                    break
                else:
                    # raise original exception
                    raise e
        else:
            if delete:
                raise exceptions.TimeoutException(
                    _("Waited for load balancer {lb_id} to be deleted for "
                      "{timeout} seconds but can still observe that it "
                      "exists.").format(
                          lb_id=load_balancer_id,
                          timeout=timeout))
            else:
                raise exceptions.TimeoutException(
                    _("Wait for load balancer ran for {timeout} seconds and "
                      "did not observe {lb_id} reach {provisioning_status} "
                      "provisioning status and {operating_status} "
                      "operating status.").format(
                          timeout=timeout,
                          lb_id=load_balancer_id,
                          provisioning_status=provisioning_status,
                          operating_status=operating_status))
        return lb

    @classmethod
    def _show_load_balancer_status_tree(cls, load_balancer_id):
        statuses = cls.load_balancers_client.show_load_balancer_status_tree(
            load_balancer_id=load_balancer_id)
        statuses = statuses.get('statuses', statuses)
        return statuses

    @classmethod
    def _create_listener(cls, wait=True, **listener_kwargs):
        listener = cls.listeners_client.create_listener(**listener_kwargs)
        listener = listener.get('listener', listener)
        if wait:
            cls._wait_for_load_balancer_status(cls.load_balancer.get('id'))
        return listener

    @classmethod
    def _delete_listener(cls, listener_id, wait=True):
        cls.listeners_client.delete_listener(listener_id)
        if wait:
            cls._wait_for_load_balancer_status(cls.load_balancer.get('id'))

    @classmethod
    def _update_listener(cls, listener_id, wait=True, **listener_kwargs):
        listener = cls.listeners_client.update_listener(
            listener_id, **listener_kwargs)
        listener = listener.get('listener', listener)
        if wait:
            cls._wait_for_load_balancer_status(
                cls.load_balancer.get('id'))
        return listener

    @classmethod
    def _show_listener(cls, listener_id):
        listener = cls.listeners_client.show_listener(listener_id)
        listener = listener.get('listener', listener)
        return listener

    @classmethod
    def _create_pool(cls, wait=True, **pool_kwargs):
        pool = cls.pools_client.create_pool(**pool_kwargs)
        pool = pool.get('pool', pool)
        if wait:
            cls._wait_for_load_balancer_status(cls.load_balancer.get('id'))
        return pool

    @classmethod
    def _delete_pool(cls, pool_id, wait=True):
        cls.pools_client.delete_pool(pool_id)
        if wait:
            cls._wait_for_load_balancer_status(cls.load_balancer.get('id'))

    @classmethod
    def _update_pool(cls, pool_id, wait=True, **pool_kwargs):
        pool = cls.pools_client.update_pool(pool_id, **pool_kwargs)
        pool = pool.get('pool', pool)
        if wait:
            cls._wait_for_load_balancer_status(
                cls.load_balancer.get('id'))
        return pool

    @classmethod
    def _show_pool(cls, pool_id):
        pool = cls.pools_client.show_pool(pool_id)
        pool = pool.get('pool', pool)
        return pool

    def _create_health_monitor(self, wait=True, cleanup=True,
                               **health_monitor_kwargs):
        hm = self.health_monitors_client.create_health_monitor(
            **health_monitor_kwargs)
        hm = hm.get('healthmonitor', hm)
        if cleanup:
            self.addCleanup(self._delete_health_monitor, hm.get('id'))
        if wait:
            self._wait_for_load_balancer_status(self.load_balancer.get('id'))
        return hm

    def _delete_health_monitor(self, health_monitor_id, wait=True):
        self.health_monitors_client.delete_health_monitor(health_monitor_id)
        if wait:
            self._wait_for_load_balancer_status(self.load_balancer.get('id'))

    def _update_health_monitor(self, health_monitor_id, wait=True,
                               **health_monitor_kwargs):
        health_monitor = self.health_monitors_client.update_health_monitor(
            health_monitor_id, **health_monitor_kwargs)
        if wait:
            self._wait_for_load_balancer_status(
                self.load_balancer.get('id'))
        return health_monitor

    def _show_health_monitor(self, health_monitor_id):
        hm = self.health_monitors_client.show_health_monitor(health_monitor_id)
        hm = hm.get('healthmonitor', hm)
        return hm

    @classmethod
    def _create_member(cls, pool_id, wait=True, **member_kwargs):
        member = cls.members_client.create_member(pool_id, **member_kwargs)
        member = member.get('member', member)
        if wait:
            cls._wait_for_load_balancer_status(cls.load_balancer.get('id'))
        return member

    @classmethod
    def _delete_member(cls, pool_id, member_id, wait=True):
        cls.members_client.delete_member(pool_id, member_id)
        if wait:
            cls._wait_for_load_balancer_status(cls.load_balancer.get('id'))

    @classmethod
    def _update_member(cls, pool_id, member_id, wait=True,
                       **member_kwargs):
        member = cls.members_client.update_member(
            pool_id, member_id, **member_kwargs)
        member = member.get('member', member)
        if wait:
            cls._wait_for_load_balancer_status(
                cls.load_balancer.get('id'))
        return member

    @classmethod
    def _show_member(cls, pool_id, member_id):
        member = cls.members_client.show_member(pool_id, member_id)
        member = member.get('member', member)
        return member

    @classmethod
    def _check_status_tree(cls, load_balancer_id, listener_ids=None,
                           pool_ids=None, health_monitor_id=None,
                           member_ids=None):
        statuses = cls._show_load_balancer_status_tree(load_balancer_id)
        load_balancer = statuses['loadbalancer']
        assert 'ONLINE' == load_balancer['operating_status']
        assert 'ACTIVE' == load_balancer['provisioning_status']

        if listener_ids:
            cls._check_status_tree_thing(listener_ids,
                                         load_balancer['listeners'])
        if pool_ids:
            cls._check_status_tree_thing(pool_ids,
                                         load_balancer['listeners']['pools'])
        if member_ids:
            cls._check_status_tree_thing(
                member_ids,
                load_balancer['listeners']['pools']['members'])
        if health_monitor_id:
            health_monitor = (
                load_balancer['listeners']['pools']['health_monitor'])
            assert health_monitor_id == health_monitor['id']
            assert 'ACTIVE' == health_monitor['provisioning_status']

    @classmethod
    def _check_status_tree_thing(cls, actual_thing_ids, status_tree_things):
        found_things = 0
        status_tree_things = status_tree_things
        assert len(actual_thing_ids) == len(status_tree_things)
        for actual_thing_id in actual_thing_ids:
            for status_tree_thing in status_tree_things:
                if status_tree_thing['id'] == actual_thing_id:
                    assert 'ONLINE' == (
                        status_tree_thing['operating_status'])
                    assert 'ACTIVE' == (
                        status_tree_thing['provisioning_status'])
                    found_things += 1
        assert len(actual_thing_ids) == found_things

    @classmethod
    def _get_full_case_name(cls):
        name = '{module}:{case_name}'.format(
            module=cls.__module__,
            case_name=cls.__name__
        )
        return name


class BaseAdminTestCase(BaseTestCase):

    # This class picks admin credentials and run the tempest tests
    _setup_core_network = False

    @classmethod
    def resource_setup(cls):

        super(BaseAdminTestCase, cls).resource_setup()

        # credentials = cls.isolated_creds.get_primary_creds()
        # mgr = tempest_clients.Manager(credentials=credentials)
        mgr = cls.get_client_manager(credential_type='admin')
        cls.create_lbaas_clients(mgr)
        cls.setup_lbaas_core_network()

    @classmethod
    def resource_cleanup(cls):
        super(BaseAdminTestCase, cls).resource_cleanup()
