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

from neutron.plugins.common import constants as plugin_const
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils
import six
from six import moves

from vmware_nsx._i18n import _LE, _LW
from vmware_nsx.common import nsxv_constants
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vcns_const
from vmware_nsx.plugins.nsx_v.vshield import edge_utils

POOL_DRIVER_LOCKID = 'PoolDriver_%s_%s_%s'
PM_POOL_WORKERS = 3
LOG = logging.getLogger(__name__)


class PoolMemberState(enum.Enum):
    PM_CREATING = 'CREATING'
    PM_SPARE = 'SPARE'
    PM_ALLOCATED = 'ALLOCATED'
    PM_ERROR = 'ERROR'
    PM_DELETING = 'DELETING'


@six.add_metaclass(abc.ABCMeta)
class PoolRegistryBase(object):
    def __init__(self, elem_size, elem_type, elem_zone):
        self._elem_size = elem_size
        self._elem_type = elem_type
        self._elem_zone = elem_zone

    @abc.abstractmethod
    def add_member(self, context, id, owner,
                   state=PoolMemberState.PM_CREATING):
        pass

    @abc.abstractmethod
    def use_member(self, context, id, owner):
        pass

    @abc.abstractmethod
    def mark_for_creation(self, context, id):
        pass

    @abc.abstractmethod
    def mark_as_spare_by_owner(self, context, owner, id):
        pass

    @abc.abstractmethod
    def mark_as_spare_by_id(self, context, id):
        pass

    @abc.abstractmethod
    def mark_for_deletion(self, context, id):
        pass

    @abc.abstractmethod
    def del_member(self, context, id):
        pass

    @abc.abstractmethod
    def get_spare_members(self, context, states=PoolMemberState.PM_SPARE):
        pass

    @abc.abstractmethod
    def get_spare_id(self):
        pass


class PoolManagerBase(object):
    def __init__(self, context, elem_size, elem_type, elem_zone, low, high,
                 registry):

        self._elem_size = elem_size
        self._elem_type = elem_type
        self._elem_zone = elem_zone
        self._registry = registry
        self._low = low
        self._high = high
        self._lock_id = POOL_DRIVER_LOCKID % (elem_size, elem_type, elem_zone)
        self._worker_pool = eventlet.GreenPool(PM_POOL_WORKERS)
        self.check_thresholds(context)

    @abc.abstractmethod
    def _create_member(self, owner):
        """Create member implementation, should return created element id"""
        pass

    @abc.abstractmethod
    def _delete_member(self, id):
        """Delete member implementation"""
        pass

    @abc.abstractmethod
    def _init_member(self, id, new_owner):
        """Initialize member implementation"""
        pass

    def check_thresholds(self, context):
        """Check that the number of spares is within the predefined range and
        act when it's not
        """
        member_count = len(
            self._registry.get_spare_members(context,
                                             [PoolMemberState.PM_SPARE,
                                              PoolMemberState.PM_CREATING]))
        if member_count < self._low:
            self.create_members(context, self._low - member_count)
        elif member_count > self._high:
            with locking.LockManager.get_lock(self._lock_id):
                # Recollect member list to conclude which members will be
                # deleted. Then mark them so they won't be used while delete
                # is in progress
                members = self._registry.get_spare_members(
                    context, [PoolMemberState.PM_SPARE,
                              PoolMemberState.PM_CREATING])
                extra_members = members[:(len(members) - self._high)]
                for member in extra_members:
                    self._registry.mark_for_deletion(context, member)
            if extra_members:
                self.dispose_members(context, extra_members)

    def _async_create_member(self, context, owner):
        try:
            id = self._create_member(owner)
            # Set member to be a spare
            self._registry.mark_as_spare_by_owner(context, owner, id)
        except Exception:
            LOG.error(_LE('Failed to deploy pool member for %s'), owner)

    def _async_delete_member(self, context, id):
        self._delete_member(id)
        self._registry.del_member(context, id)

    def _pool_creator(self, context, fake_owners):
        for fake_owner in fake_owners:
            self._worker_pool.spawn_n(self._async_create_member,
                                      context, fake_owner)

    def _pool_disposer(self, context, members):
        for member in members:
            self._worker_pool.spawn_n(self._async_delete_member,
                                      context, member)

    def create_members(self, context, num):
        """Create multiple spare members asynchronously"""

        # We first generate the DB entries - to avoid concurrency issues
        fake_owners = []
        for n in moves.range(num):
            fake_owner = self._registry.get_spare_id()
            self._registry.add_member(context, None, fake_owner)
            fake_owners.append(fake_owner)

        eventlet.spawn_n(self._pool_creator, context, fake_owners)

    def dispose_members(self, context, members):
        """Dispose multiple spare members asynchronously"""
        eventlet.spawn_n(self._pool_disposer, context, members)

    def create_member(self, context, state, owner):
        """Synchronously create member"""
        id = None
        with locking.LockManager.get_lock(self._lock_id):
            try:
                id = self._create_member(owner)
                self._registry.add_member(context, id, owner, state)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(
                        _LE('Failed to create a pool member (size=%(size)s '
                            'type=%(type)s az=%(az)s) for owner %(owner)s'),
                        {'size': self._elem_size,
                         'type': self._elem_type,
                         'az': self._elem_zone,
                         'owner': owner})
        return id

    def delete_member(self, context, id):
        """Synchronously delete member"""
        with locking.LockManager.get_lock(self._lock_id):
            self._registry.mark_for_deletion(context, id)
        self._delete_member(id)
        self._registry.del_member(context, id)

    def reuse_member(self, context, id):
        """Scrap member and pull it back into the spare pool. Check that
        number of free members is within range while doing so.
        """
        new_owner = self._registry.mark_for_creation(context, id)
        self._init_member(id, new_owner)
        self._registry.mark_as_spare_by_id(context, id)
        self.check_thresholds(context)

    def get_member(self, context, owner):
        """Get a free member from pool. Check that number of free members
        is within range while doing so.
        """
        with locking.LockManager.get_lock(self._lock_id):
            members = self._registry.get_spare_members(context)
            if members:
                self._registry.use_member(context, members[0], owner)
                self.check_thresholds(context)
                return members[0]

        id = self.create_member(context, PoolMemberState.PM_ALLOCATED, owner)
        self.check_thresholds(context)
        return id


class NsxvEdgeRegistry(PoolRegistryBase):
    STATE_DICT = {
        PoolMemberState.PM_CREATING: plugin_const.PENDING_CREATE,
        PoolMemberState.PM_SPARE: plugin_const.ACTIVE,
        PoolMemberState.PM_ALLOCATED: plugin_const.ACTIVE,
        PoolMemberState.PM_ERROR: plugin_const.ERROR,
        PoolMemberState.PM_DELETING: plugin_const.PENDING_DELETE}

    def __init__(self, elem_size, elem_type, elem_zone):
        super(NsxvEdgeRegistry, self).__init__(elem_size, elem_type, elem_zone)

    def get_spare_id(self):
        return (vcns_const.BACKUP_ROUTER_PREFIX +
                uuidutils.generate_uuid())[:vcns_const.EDGE_NAME_LEN]

    def add_member(self, context, id, owner,
                   state=PoolMemberState.PM_CREATING):
        nsxv_db.add_nsxv_router_binding(
            context.session, owner, id, None,
            self.STATE_DICT[state],
            appliance_size=self._elem_size, edge_type=self._elem_type,
            availability_zone=self._elem_zone)

    def del_member(self, context, id):
        binds = nsxv_db.get_nsxv_router_bindings_by_edge(context.session, id)
        for bind in binds:
            nsxv_db.delete_nsxv_router_binding(context.session,
                                               bind['router_id'])

    def use_member(self, context, id, owner):
        self.del_member(context, id)
        nsxv_db.add_nsxv_router_binding(
            context.session, owner, id, None,
            plugin_const.ACTIVE,
            appliance_size=self._elem_size, edge_type=self._elem_type,
            availability_zone=self._elem_zone)

    def _set_spare_state(self, context, binds, state, id=None):
        if binds:
            if len(binds) == 1:
                if binds[0]['router_id'].startswith(
                        vcns_const.BACKUP_ROUTER_PREFIX):
                    if id:
                        nsxv_db.update_nsxv_router_binding(
                            context.session,
                            binds[0]['router_id'],
                            status=state, edge_id=id)
                    else:
                        nsxv_db.update_nsxv_router_binding(
                            context.session,
                            binds[0]['router_id'],
                            status=state)
                    return binds[0]['router_id']
                else:
                    nsxv_db.delete_nsxv_router_binding(context.session,
                                                       binds[0]['router_id'])
            else:
                LOG.warning(_LW('Found %(len)d bindings for edge %(id)s while '
                                'setting %(state)s state while expecting one'),
                            {'len': len(binds), 'id': id, 'state': state})
                self.del_member(context, id)

        owner = self.get_spare_id()
        if not id:
            id = binds[0]['edge_id']

        nsxv_db.add_nsxv_router_binding(
            context.session, owner, id, None,
            state,
            appliance_size=self._elem_size, edge_type=self._elem_type,
            availability_zone=self._elem_zone)
        return owner

    def mark_for_creation(self, context, id):
        binds = nsxv_db.get_nsxv_router_bindings_by_edge(context.session, id)
        return self._set_spare_state(
            context, binds, plugin_const.PENDING_CREATE)

    def mark_for_deletion(self, context, id):
        binds = nsxv_db.get_nsxv_router_bindings_by_edge(context.session, id)
        self._set_spare_state(context, binds, plugin_const.PENDING_DELETE)

    def mark_as_spare_by_owner(self, context, owner, id):
        binds = nsxv_db.get_nsxv_router_bindings(
            context.session, filters={'router_id': [owner]})
        self._set_spare_state(context, binds, plugin_const.ACTIVE, id=id)

    def mark_as_spare_by_id(self, context, id):
        binds = nsxv_db.get_nsxv_router_bindings_by_edge(context.session, id)
        self._set_spare_state(context, binds, plugin_const.ACTIVE)

    def get_spare_members(self, context, states=PoolMemberState.PM_SPARE):
        if not isinstance(states, list):
            states = [states]
        db_states = []
        for state in states:
            db_states.append(self.STATE_DICT[state])

        binds = nsxv_db.get_nsxv_router_bindings(
            context.session,
            filters={'status': db_states,
                     'availability_zone': [self._elem_zone],
                     'appliance_size': [self._elem_size],
                     'edge_type': [self._elem_type]},
            like_filters={'router_id': vcns_const.BACKUP_ROUTER_PREFIX + "%"})

        b = [b['edge_id'] for b in binds]
        return b


class EdgePoolManager(PoolManagerBase):
    def __init__(
            self, context, vcns, elem_size, elem_type, elem_zone, low, high):
        registry = NsxvEdgeRegistry(elem_size, elem_type, elem_zone)

        super(EdgePoolManager, self).__init__(
            context, elem_size, elem_type, elem_zone, low, high, registry)
        self.vcns = vcns

    def _get_initial_edge_cfg(self, owner):
        dist = self._elem_type == nsxv_constants.VDR_EDGE
        edge = edge_utils.assemble_edge(
            owner, datacenter_moid=cfg.CONF.nsxv.datacenter_moid,
            deployment_container_id=cfg.CONF.nsxv.deployment_container_id,
            appliance_size=self._elem_size, dist=dist,
            edge_ha=self._elem_zone.edge_ha)
        appliances = edge_utils.assemble_edge_appliances(self._elem_zone)
        if appliances:
            edge['appliances']['appliances'] = appliances

        if not dist:
            vnic_external = edge_utils.assemble_edge_vnic(
                vcns_const.EXTERNAL_VNIC_NAME, vcns_const.EXTERNAL_VNIC_INDEX,
                cfg.CONF.nsxv.external_network, type="uplink")
            edge['vnics']['vnics'].append(vnic_external)
        else:
            edge['mgmtInterface'] = {
                'connectedToId': cfg.CONF.nsxv.external_network,
                'name': "mgmtInterface"}

        # If default login credentials for Edge are set, configure accordingly
        if (cfg.CONF.nsxv.edge_appliance_user and
                cfg.CONF.nsxv.edge_appliance_password):
            edge['cliSettings'].update({
                'userName': cfg.CONF.nsxv.edge_appliance_user,
                'password': cfg.CONF.nsxv.edge_appliance_password})

        if not dist:
            edge_utils.enable_loadbalancer(edge)
        return edge

    def _create_member(self, owner):
        """Create member implementation, should return created element id"""
        edge = self._get_initial_edge_cfg(owner)

        header = self.vcns.deploy_edge(edge)[0]
        edge_id = header.get('location', '/').split('/')[-1]

        if not edge_id:
            error = _('Failed to deploy edge')
            raise nsx_exc.NsxPluginException(err_msg=error)
        return edge_id

    def _delete_member(self, id):
        """Delete member implementation"""
        self.vcns.delete_edge(id)

    @abc.abstractmethod
    def _init_member(self, id, new_owner):
        """Initialize member implementation"""
        pass

    def get_member(self, context, owner):
        edge_id = super(EdgePoolManager, self).get_member(context, owner)
        edge = self._get_initial_edge_cfg(owner)
        edge['id'] = edge_id

        self.vcns.update_edge(edge_id, edge)
        return edge_id
