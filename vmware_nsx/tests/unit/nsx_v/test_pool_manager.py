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
        self.registry[owner]['state'] = (
            pmgr.PoolMemberState.PM_ALLOCATED)
        self.id_dict = owner

    def reuse_member(self, context, owner):
        if self.registry[owner]['state'] == (
                pmgr.PoolMemberState.PM_CREATING):
            self.registry[owner]['state'] = (
                pmgr.PoolMemberState.PM_SPARE)
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
        pool = TestPoolManager(None, 'size', 'type', 'zone', 2, 5, registry)

        return registry, pool

    def _fake_e_spawn_n(self, method, *args):
        method(*args)

    def test_create_pool(self):
        with mock.patch.object(TestPoolManager, '_create_member') as c_m, \
                mock.patch.object(pmgr.eventlet, 'spawn_n',
                                  side_effect=self._fake_e_spawn_n), \
                mock.patch.object(pmgr.eventlet.GreenPool, 'spawn_n',
                                  side_effect=self._fake_e_spawn_n):
            self._make_pool()
            self.assertEqual(2, c_m.call_count)
