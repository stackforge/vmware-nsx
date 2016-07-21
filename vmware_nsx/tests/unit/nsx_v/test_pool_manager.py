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

from neutron.tests import base

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

    def reuse_member(self, context, owner, id=None):
        if self.registry[owner]['state'] == pmgr.PoolMemberState.PM_CREATING:
            if id:
                self.registry[owner]['id'] = id
                self.id_dict[id] = owner
            self.registry[owner]['state'] = pmgr.PoolMemberState.PM_SPARE
        else:
            new_owner = self.get_spare_id()
            self.registry[new_owner] = self.registry[owner]
            del(self.registry[owner])
            self.id_dict[self.registry[new_owner]['id']] = new_owner

    def mark_for_deletion(self, context, id):
        owner = self.id_dict[id]
        self.registry[owner]['state'] = (
            pmgr.PoolMemberState.PM_DELETING)

    def mark_for_creation(self, context, id):
        owner = self.id_dict[id]
        self.registry[owner]['state'] = (
            pmgr.PoolMemberState.PM_CREATING)

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
        return str(uuid.uuid4())

    def _delete_member(self, id):
        pass

    def _init_member(self, id):
        pass


class PoolManagerBaseTestCase(base.BaseTestCase):
    def setUp(self):
        super(PoolManagerBaseTestCase, self).setUp()

    def _make_pool(self):
        registry = TestPoolRegistry('size', 'type', 'zone')
        pool = TestPoolManager(
            None, 'size', 'type', 'zone', POOL_MIN, POOL_MAX, registry)

        return registry, pool

    def _fake_e_spawn_n(self, method, *args):
        method(*args)

    def test_create_pool(self):
        with mock.patch.object(pmgr.eventlet, 'spawn_n',
                                  side_effect=self._fake_e_spawn_n), \
                mock.patch.object(pmgr.eventlet.GreenPool, 'spawn_n',
                                  side_effect=self._fake_e_spawn_n):
            reg, pool = self._make_pool()
            self.assertEqual(POOL_MIN, len(reg.id_dict))

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
                member_id = pool.get_member(None, dummy_owner)
                received_id[dummy_owner] = member_id
                self.assertEqual(member_id, reg.registry[dummy_owner]['id'])
                self.assertEqual(POOL_MIN + n, len(reg.id_dict))

            for n in range(TEST_ITERATIONS - 1, 0, -1):
                dummy_owner = 'dummy-id-%d' % n
                pool.reuse_member(None, dummy_owner, received_id[dummy_owner])
                spares = reg.get_spare_members(None)

                expected_spares = min(TEST_ITERATIONS + POOL_MIN - n, POOL_MAX)
                self.assertTrue(len(spares) == expected_spares)

            # Validate that there are no leftovers in the registry
            self.assertTrue(len(reg.registry) == POOL_MAX)
            self.assertTrue(len(reg.id_dict) == POOL_MAX)

    def test_delete_synchronous(self):
        with mock.patch.object(pmgr.eventlet, 'spawn_n',
                               side_effect=self._fake_e_spawn_n), \
             mock.patch.object(pmgr.eventlet.GreenPool, 'spawn_n',
                               side_effect=self._fake_e_spawn_n):
            reg, pool = self._make_pool()
            # pick registry member for deletion
            id = reg.id_dict.keys()[0]
            owner = reg.id_dict[id]
            self.assertIsNotNone(reg.id_dict.get(id))
            self.assertIsNotNone(reg.registry.get(owner))
            reg_len = len(reg.registry)
            id_dict_len = len(reg.id_dict)

            with mock.patch.object(pool, '_delete_member') as mock_del:
                pool.delete_member(None, id)
                self.assertEqual(len(reg.registry), reg_len - 1)
                self.assertEqual(len(reg.id_dict), id_dict_len - 1)
                self.assertEqual(reg.id_dict.get(id), None)
                self.assertEqual(reg.registry.get(owner), None)
                mock_del.assert_called_once_with(id)

    def test_create_synchronous(self):
        with mock.patch.object(pmgr.eventlet, 'spawn_n',
                               side_effect=self._fake_e_spawn_n), \
             mock.patch.object(pmgr.eventlet.GreenPool, 'spawn_n',
                               side_effect=self._fake_e_spawn_n):
            reg, pool = self._make_pool()

            id = pool.create_member(
                None, pmgr.PoolMemberState.PM_ALLOCATED, 'dummy')

            # pool should have minimum members plus dummy
            self.assertIsNotNone(id)
            self.assertEqual(len(reg.registry), POOL_MIN + 1)
            self.assertEqual(len(reg.id_dict), POOL_MIN + 1)

    def test_create_with_empty_pool(self):
        with mock.patch.object(pmgr.eventlet, 'spawn_n',
                               side_effect=self._fake_e_spawn_n), \
             mock.patch.object(pmgr.eventlet.GreenPool, 'spawn_n',
                               side_effect=self._fake_e_spawn_n):
            reg, pool = self._make_pool()

            # empty registry
            reg.registry = {}
            reg.id_dict = {}
            id = pool.get_member(None, 'dummy')

            # pool should have minimum members plus dummy
            self.assertIsNotNone(id)
            self.assertEqual(len(reg.registry), POOL_MIN + 1)
            self.assertEqual(len(reg.id_dict), POOL_MIN + 1)
