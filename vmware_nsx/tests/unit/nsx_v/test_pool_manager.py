# Copyright 2016 VMware, Inc.
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

import mock
import uuid

from neutron import context
from neutron.tests import base
import neutron.tests.unit.db.test_db_base_plugin_v2 as test_plugin

from vmware_nsx.db import nsxv_db  # noqa
from vmware_nsx.plugins.nsx_v.drivers import pool_manager as pmgr

POOL_MIN = 2
POOL_MAX = 5
TEST_ITERATIONS = 20


class TestPoolRegistry(pmgr.PoolRegistryBase):
    registry = {}
    id_dict = {}

    def __init__(self, elem_size, elem_type, elem_zone):
        super(TestPoolRegistry, self).__init__(elem_size, elem_type, elem_zone)

    def add_member(self, context, id, owner,
                   state=pmgr.PoolMemberState.PM_CREATING):
        self.registry[owner] = {'id': id, 'state': state}
        if id:
            self.id_dict[id] = owner

    def use_member(self, context, id, owner):
        old_owner = self.id_dict[id]
        self.registry[owner] = self.registry[old_owner]
        self.registry[owner]['state'] = pmgr.PoolMemberState.PM_ALLOCATED
        del(self.registry[old_owner])
        self.id_dict[id] = owner

    def mark_for_deletion(self, context, id):
        owner = self.id_dict[id]
        self.registry[owner]['state'] = (
            pmgr.PoolMemberState.PM_DELETING)

    def mark_for_creation(self, context, id):
        owner = self.id_dict[id]
        self.registry[owner]['state'] = (
            pmgr.PoolMemberState.PM_CREATING)

    def mark_as_spare_by_owner(self, context, owner, id):
        self.registry[owner]['id'] = id
        self.id_dict[id] = owner
        self.registry[owner]['state'] = pmgr.PoolMemberState.PM_SPARE

    def mark_as_spare_by_id(self, context, id):
        owner = self.id_dict[id]
        new_owner = self.get_spare_id()
        self.registry[new_owner] = self.registry[owner]
        del (self.registry[owner])
        self.registry[new_owner]['state'] = pmgr.PoolMemberState.PM_SPARE
        self.id_dict[self.registry[new_owner]['id']] = new_owner

    def del_member(self, context, id):
        owner = self.id_dict[id]
        del(self.id_dict[id])
        del(self.registry[owner])

    def get_spare_members(self, context,
                          states=pmgr.PoolMemberState.PM_SPARE):
        if not isinstance(states, list):
            states = [states]

        return [m['id'] for m in self.registry.values()
                if m['state'] in states]

    def get_spare_id(self):
        return str(uuid.uuid4())


class TestPoolManager(pmgr.PoolManagerBase):
    def _create_member(self):
        return str(uuid.uuid4())[:4]

    def _delete_member(self, id):
        pass

    def _init_member(self, id):
        pass


class PoolManagerBaseTestCase(base.BaseTestCase):
    def _get_ctx(self):
        return

    def setUp(self):
        super(PoolManagerBaseTestCase, self).setUp()

    def _make_pool(self):
        registry = TestPoolRegistry('size', 'type', 'zone')
        pool = TestPoolManager(self._get_ctx(), 'size', 'type', 'zone',
                               POOL_MIN, POOL_MAX, registry)

        return registry, pool

    def _fake_e_spawn_n(self, method, *args):
        method(*args)

    def _get_reg_total_len(self, reg):
        return len(reg.registry)

    def _get_reg_ids(self, reg):
        return reg.id_dict.keys()

    def _get_reg_owner_by_id(self, reg, id):
        return reg.id_dict.get(id)

    def _get_reg_id_by_owner(self, reg, owner):
        return reg.registry.get(owner, {}).get('id')

    def _get_reg_used_len(self, reg):
        return len(reg.id_dict)

    def _get_elem_id(self, reg, owner):
        return reg.registry[owner]['id']

    def test_create_pool(self):
        with mock.patch.object(pmgr.eventlet, 'spawn_n',
                               side_effect=self._fake_e_spawn_n), \
             mock.patch.object(pmgr.eventlet.GreenPool, 'spawn_n',
                               side_effect=self._fake_e_spawn_n):
            reg, pool = self._make_pool()
            self.assertEqual(POOL_MIN, self._get_reg_used_len(reg))

    def test_expand_shrink_pool(self):
        with mock.patch.object(pmgr.eventlet, 'spawn_n',
                               side_effect=self._fake_e_spawn_n), \
             mock.patch.object(pmgr.eventlet.GreenPool, 'spawn_n',
                               side_effect=self._fake_e_spawn_n):
            reg, pool = self._make_pool()

            # Load pool
            received_id = {}
            for n in range(1, TEST_ITERATIONS):
                dummy_owner = 'dummy-id-%d' % n
                member_id = pool.get_member(self._get_ctx(), dummy_owner)
                received_id[dummy_owner] = member_id
                self.assertEqual(member_id, self._get_elem_id(reg,
                                                              dummy_owner))
                self.assertEqual(POOL_MIN + n, self._get_reg_used_len(reg))

            for n in range(TEST_ITERATIONS - 1, 0, -1):
                dummy_owner = 'dummy-id-%d' % n
                pool.reuse_member(self._get_ctx(), received_id[dummy_owner])
                spares = reg.get_spare_members(self._get_ctx())

                expected_spares = min(TEST_ITERATIONS + POOL_MIN - n, POOL_MAX)
                self.assertEqual(len(spares), expected_spares)

            # Validate that there are no leftovers in the registry
            self.assertTrue(self._get_reg_total_len(reg) == POOL_MAX)
            self.assertTrue(self._get_reg_used_len(reg) == POOL_MAX)

    def test_delete_synchronous(self):
        with mock.patch.object(pmgr.eventlet, 'spawn_n',
                               side_effect=self._fake_e_spawn_n), \
             mock.patch.object(pmgr.eventlet.GreenPool, 'spawn_n',
                               side_effect=self._fake_e_spawn_n):
            reg, pool = self._make_pool()
            # pick registry member for deletion
            id = self._get_reg_ids(reg)[0]
            owner = self._get_reg_owner_by_id(reg, id)

            self.assertIsNotNone(owner)
            self.assertIsNotNone(self._get_reg_id_by_owner(reg, owner))
            reg_len = self._get_reg_total_len(reg)
            id_dict_len = self._get_reg_used_len(reg)

            with mock.patch.object(pool, '_delete_member') as mock_del:
                pool.delete_member(self._get_ctx(), id)
                self.assertEqual(self._get_reg_total_len(reg), reg_len - 1)
                self.assertEqual(self._get_reg_used_len(reg), id_dict_len - 1)
                self.assertIsNone(self._get_reg_owner_by_id(reg, id))
                self.assertIsNone(self._get_reg_id_by_owner(reg, owner))
                mock_del.assert_called_once_with(id)

    def test_create_synchronous(self):
        with mock.patch.object(pmgr.eventlet, 'spawn_n',
                               side_effect=self._fake_e_spawn_n), \
             mock.patch.object(pmgr.eventlet.GreenPool, 'spawn_n',
                               side_effect=self._fake_e_spawn_n):
            reg, pool = self._make_pool()

            id = pool.create_member(
                self._get_ctx(), pmgr.PoolMemberState.PM_ALLOCATED, 'dummy')

            # pool should have minimum members plus dummy
            self.assertIsNotNone(id)
            self.assertEqual(self._get_reg_total_len(reg), POOL_MIN + 1)
            self.assertEqual(self._get_reg_used_len(reg), POOL_MIN + 1)

    def test_create_with_empty_pool(self):
        with mock.patch.object(pmgr.eventlet, 'spawn_n',
                               side_effect=self._fake_e_spawn_n), \
             mock.patch.object(pmgr.eventlet.GreenPool, 'spawn_n',
                               side_effect=self._fake_e_spawn_n):
            reg, pool = self._make_pool()

            # empty registry
            reg.registry = {}
            reg.id_dict = {}
            id = pool.get_member(self._get_ctx(), 'dummy')

            # pool should have minimum members plus dummy
            self.assertIsNotNone(id)
            self.assertEqual(self._get_reg_total_len(reg), POOL_MIN + 1)
            self.assertEqual(self._get_reg_used_len(reg), POOL_MIN + 1)


class PoolManagerNsxvEdgeRegistry(PoolManagerBaseTestCase,
                                  test_plugin.NeutronDbPluginV2TestCase):
    def _get_ctx(self):
        return context.get_admin_context()

    def _get_reg_used_len(self, reg):
        reg = nsxv_db.get_nsxv_router_bindings(self._get_ctx())
        n = 0
        for r in reg:
            if r['edge_id'] is not None:
                n += 1
        return n

    def _get_reg_total_len(self, reg):
        reg = nsxv_db.get_nsxv_router_bindings(self._get_ctx())
        return len(reg)

    def _get_elem_id(self, reg, owner):
        bind = nsxv_db.get_nsxv_router_binding(self._get_ctx().session,
                                               owner)
        return bind['edge_id']

    def _get_reg_ids(self, reg):
        binds = nsxv_db.get_nsxv_router_bindings(self._get_ctx().session)
        return [b['edge_id'] for b in binds]

    def _get_reg_owner_by_id(self, reg, id):
        bind = nsxv_db.get_nsxv_router_binding_by_edge(
            self._get_ctx().session, id)
        if bind:
            return bind.get('router_id')

    def _get_reg_id_by_owner(self, reg, owner):
        bind = nsxv_db.get_nsxv_router_binding(self._get_ctx().session, owner)
        if bind:
            return bind['edge_id']

    def _make_pool(self):
        registry = pmgr.NsxvEdgeRegistry('compact', 'service', 'zone')
        pool = TestPoolManager(self._get_ctx(), 'size', 'type',
                               'zone', POOL_MIN, POOL_MAX, registry)

        return registry, pool
