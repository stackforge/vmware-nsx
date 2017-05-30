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

from oslo_log import log as logging
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_const
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsxlib.v3 import nsx_constants as consts

LOG = logging.getLogger(__name__)


class LoadbalancerBaseManager(object):
    _lbv2_driver = None
    _core_plugin = None
    _flavor_plugin = None

    def __init__(self):
        super(LoadbalancerBaseManager, self).__init__()

    def _get_plugin(self, plugin_type):
        return directory.get_plugin(plugin_type)

    @property
    def lbv2_driver(self):
        if not LoadbalancerBaseManager._lbv2_driver:
            plugin = self._get_plugin(
                plugin_const.LOADBALANCERV2)
            LoadbalancerBaseManager._lbv2_driver = (
                plugin.drivers['vmwareedge'])

        return LoadbalancerBaseManager._lbv2_driver

    @property
    def core_plugin(self):
        if not LoadbalancerBaseManager._core_plugin:
            LoadbalancerBaseManager._core_plugin = (
                self._get_plugin(plugin_const.CORE))

        return LoadbalancerBaseManager._core_plugin

    @property
    def flavor_plugin(self):
        if not LoadbalancerBaseManager._flavor_plugin:
            LoadbalancerBaseManager._flavor_plugin = (
                self._get_plugin(plugin_const.FLAVORS))

        return LoadbalancerBaseManager._flavor_plugin


class EdgeLoadbalancerBaseManager(LoadbalancerBaseManager):

    def __init__(self, vcns_driver):
        super(EdgeLoadbalancerBaseManager, self).__init__()
        self.vcns_driver = vcns_driver

    @property
    def vcns(self):
        return self.vcns_driver.vcns


class Nsxv3LoadbalancerBaseManager(LoadbalancerBaseManager):

    def __init__(self):
        super(Nsxv3LoadbalancerBaseManager, self).__init__()
        self.nsxlib = v3_utils.get_nsxlib_wrapper()

        self.backend_support = True
        registry.subscribe(
            self.check_backend_version,
            resources.PROCESS, events.BEFORE_SPAWN)

    def check_backend_version(self, resource, event, trigger, **kwargs):
        if not self.nsxlib.feature_supported(consts.FEATURE_LOAD_BALANCER):
            # loadbalancer is not supported
            LOG.warning("LBaaS is not supported by the NSX backend (version "
                        "%s): loadbalancer is not supported",
                        self.nsxlib.get_version())
            self.backend_support = False

    def validate_backend_version(self):
        # prevent loadbalancer actions if the backend does not support it
        if not self.backend_support:
            LOG.error("The NSX backend does not support loadbalancer")
            raise nsx_exc.InvalidVersion(version=self.nsxlib.get_version())
