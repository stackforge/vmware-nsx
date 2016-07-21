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

import abc
import enum

import six

from vmware_nsx.common import locking


POOL_DRIVER_LOCKID = 'PoolDriver'


class PoolMemberState(enum.Enum):
    PM_CREATING = 'CREATING'
    PM_DELETING = 'DELETING'
    PM_SPARE = 'SPARE'
    PM_ALLOCATED = 'ALLOCATED'


@six.add_metaclass(abc.ABCMeta)
class PoolRegistry:
    def __init__(self, elem_size, elem_type, elem_zone):
        self._elem_size = elem_size
        self._elem_type = elem_type
        self._elem_zone = elem_zone

    @abc.abstractmethod
    def add_member(self, id, owner=None, state=PoolMemberState.PM_CREATING):
        pass

    @abc.abstractmethod
    def use_member(self, id, owner):
        pass

    @abc.abstractmethod
    def reuse_member(self, id):
        pass

    @abc.abstractmethod
    def mark_for_deletion(self, id):
        pass

    @abc.abstractmethod
    def del_member(self, id):
        pass

    @abc.abstractmethod
    def get_spare_members(self):
        return []


class PoolDriver:
    def __init__(self, elem_size, elem_type, elem_zone, low, high, registry):
        self._elem_size = elem_size
        self._elem_type = elem_type
        self._elem_zone = elem_zone
        self._registry = registry
        self._low = low
        self._high = high
        self._lock_id = POOL_DRIVER_LOCKID % (elem_size, elem_type, elem_zone)
        self.check_thresholds()

    @abc.abstractmethod
    def _create_member(self, state):
        pass

    @abc.abstractmethod
    def _delete_member(self, id):
        pass

    @abc.abstractmethod
    def _init_member(self, id):
        pass

    def check_thresholds(self):
        """ Check that the number of spares is within the predefined
            range and act when it's not """
        member_count = len(self._registry.get_spare_members())
        if member_count < self._low:
            self.create_members(member_count - self._low)
        elif member_count > self._high:
            self.dispose_members(self._high - member_count)

    def create_member(self, state, owner):
        """ Synchronously create member """
        with locking.LockManager.get_lock(self._lock_id):
            id = self._create_member(state)
            self._registry.use_member(id, owner)

    def delete_member(self, id):
        """ Synchronously delete member """
        with locking.LockManager.get_lock(self._lock_id):
            self._registry.mark_for_deletion(id)
        self.delete_member(id)
        self._registry.del_member(id)

    def reuse_member(self, id):
        self._init_member(id)
        self._registry.reuse_member(id)

    def get(self, owner):
        with locking.LockManager.get_lock(self._lock_id):
            members = self._registry.get_spare_members()
            if members:
                self._registry.use_member(members[0]['id'], owner)
                self.check_thresholds()
                return members[0]['id']

        return self.create_member(PoolMemberState.PM_ALLOCATED, owner)
