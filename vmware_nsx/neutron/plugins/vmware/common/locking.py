# Copyright 2015 VMware, Inc.
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
from oslo_log import log
from tooz import coordination


LOG = log.getLogger(__name__)


class LockManager:
    _coordinator = None
    _connect_string = cfg.CONF.database.connection

    def __init__(self):
        LOG.debug('LockManager initialized!')

    @staticmethod
    def set_connect_string(connect_string):
        LockManager._connect_string = connect_string

    @staticmethod
    def get_lock(name):

        if not LockManager._coordinator:
            LOG.debug('Initialized coordinator with connect string %s',
                      LockManager._connect_string)
            LockManager._coordinator = coordination.get_coordinator(
                LockManager._connect_string, 'vmware-neutron-plugin')

        LOG.debug('Retrieved lock for %s' % name)
        return LockManager._coordinator.get_lock(name)
