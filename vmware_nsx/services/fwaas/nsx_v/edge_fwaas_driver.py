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

from neutron import manager
from neutron.plugins.common import constants
from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from vmware_nsx.plugins.nsx_v.vshield.common import (
    exceptions as vcns_exc)
from vmware_nsx.plugins.nsx_v.vshield.tasks import (
    constants as task_const)
from vmware_nsx.plugins.nsx_v.vshield.tasks import tasks

from vmware_nsx.db import nsxv_db

LOG = logging.getLogger(__name__)


class EdgeFwaasDriver(object):
    _fwaas_driver = None
    _core_plugin = None

    def _get_plugin(self, plugin_type):
        loaded_plugins = manager.NeutronManager.get_service_plugins()
        return loaded_plugins[plugin_type]

    @property
    def fw_driver(self):
        if not EdgeFwaasDriver._fwaas_driver:
            plugin = self._get_plugin(
                constants.FIREWALL)
            EdgeFwaasDriver._fwaas_driver = plugin.drivers['vmwareedge']

        return EdgeFwaasDriver._fwaas_driver

    @property
    def core_plugin(self):
        if not EdgeFwaasDriver._core_plugin:
            EdgeFwaasDriver._core_plugin = self._get_plugin(constants.CORE)

        return EdgeFwaasDriver._core_plugin

    @log_helpers.log_method_call
    def __init__(self):
        pass

    @log_helpers.log_method_call
    def create_firewall(self, agent_mode, apply_list, firewall):
        pass

    @log_helpers.log_method_call
    def update_firewall(self, agent_mode, apply_list, firewall):
        pass

    @log_helpers.log_method_call
    def delete_firewall(self, agent_mode,  firewall):
        pass

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        pass
