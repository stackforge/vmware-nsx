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
import eventlet

from oslo_log import log as logging
from oslo_utils import excutils
import six
from six import moves

from vmware_nsx._i18n import _, _LE, _LW
from vmware_nsx.common import locking


POOL_DRIVER_LOCKID = 'PoolDriver'
PM_POOL_WORKERS = 3
LOG = logging.getLogger(__name__)


class PoolMemberState(enum.Enum):
    PM_CREATING = 'CREATING'
    PM_DELETING = 'DELETING'
    PM_SPARE = 'SPARE'
    PM_ALLOCATED = 'ALLOCATED'
    PM_ERROR = 'ERROR'


@six.add_metaclass(abc.ABCMeta)
class PoolRegistry:
    def __init__(self, elem_size, elem_type, elem_zone):
        self._elem_size = elem_size
        self._elem_type = elem_type
        self._elem_zone = elem_zone

    @abc.abstractmethod
    def add_member(self, context, id, owner=None,
                   state=PoolMemberState.PM_CREATING):
        pass

    @abc.abstractmethod
    def use_member(self, context, id, owner):
        pass

    @abc.abstractmethod
    def reuse_member(self, context, id):
        pass

    @abc.abstractmethod
    def mark_for_deletion(self, context, id):
        pass

    @abc.abstractmethod
    def del_member(self, context, id):
        pass

    @abc.abstractmethod
    def get_spare_members(self, context):
        return []

    @abc.abstractmethod
    def _get_spare_id(self):
        pass


class PoolDriver:
    def __init__(self, context, elem_size, elem_type, elem_zone, low, high,
                 registry):

        self._elem_size = elem_size
        self._elem_type = elem_type
        self._elem_zone = elem_zone
        # TODO(kobis): use registry param here
        self._registry = PoolRegistry(elem_size, elem_type, elem_zone)
        self._low = low
        self._high = high
        self._lock_id = POOL_DRIVER_LOCKID % (elem_size, elem_type, elem_zone)
        self._worker_pool = eventlet.GreenPool(PM_POOL_WORKERS)
        self.check_thresholds(context)

    @abc.abstractmethod
    def _create_member(self):
        """Create member implementation, should return created element id"""
        pass

    @abc.abstractmethod
    def _delete_member(self, id):
        pass

    @abc.abstractmethod
    def _init_member(self, id):
        pass

    def check_thresholds(self, context):
        """Check that the number of spares is within the predefined range and
        act when it's not"""
        member_count = len(self._registry.get_spare_members(context))
        if member_count < self._low:
            self.create_members(context, member_count - self._low)
        elif member_count > self._high:
            # TODO(kobis): gather deletion candidates here, and mark them for deletion
            self.dispose_members(context, members)

    def _create_async_member(self, context, owner):
        try:
            id = self._create_member()
            # Set member to be a spare
            self._registry.reuse_member(context, id)
        except Exception as e:
            LOG.error(_LE('Failed to deploy pool member for %s'), owner)
                
    def _pool_creator(self, context, fake_owners):
        for fake_owner in fake_owners:
            self._worker_pool.spawn_n(self._create_async_member,
                                      context, fake_owner)

    def create_members(self, context, num):
        """Create multiple spare members asynchronously"""

        # We first generate the DB entries - to avoid concurrency issues
        fake_owners = []
        for n in moves.range(num):
            fake_owner = self._registry.get_spare_id()
            self._registry.add_member(context, fake_owner)
            fake_owners.append(fake_owner)

        eventlet.spawn_n(self._pool_creator, context, fake_owners)

    def dispose_members(self, context, members):
        """Dispose multiple spare members asynchronously"""
        eventlet.spawn_n(self._pool_disposer, context, members)

    def create_member(self, context, state, owner):
        """Synchronously create member"""
        with locking.LockManager.get_lock(self._lock_id):
            try:
                id = self._create_member()
                self._registry.add_member(id, context, owner, state)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _LE('Failed to create a pool member (size=%(size)s '
                            'type=%(type)s az=%(az)s) for owner %(owner)s'),
                        {'size': self._elem_size,
                         'type': self._elem_type,
                         'az': self._elem_zone,
                         'owner': owner})

    def delete_member(self, context, id):
        """Synchronously delete member"""
        with locking.LockManager.get_lock(self._lock_id):
            self._registry.mark_for_deletion(context, id)
        self._delete_member(id)
        self._registry.del_member(context, id)

    def reuse_member(self, context, id):
        self._init_member(id)
        self._registry.reuse_member(context, id)

    def get_member(self, context, owner):
        with locking.LockManager.get_lock(self._lock_id):
            members = self._registry.get_spare_members()
            if members:
                self._registry.use_member(context, members[0]['id'], owner)
                self.check_thresholds(context)
                return members[0]['id']

        return self.create_member(context, PoolMemberState.PM_ALLOCATED, owner)
