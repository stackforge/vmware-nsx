# Copyright 2017 VMware, Inc.
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

from neutron_lib.plugins import directory
from oslo_log import log
import six

from vmware_nsx.extensions import projectpluginmap

LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseJob(object):

    _core_plugin = None

    def __init__(self, readonly):
        self.readonly = readonly

    @property
    def plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
            if self._core_plugin.is_tvd_plugin() is True:
                # get the plugin that match this driver
                self._core_plugin = self._core_plugin.get_plugin_by_type(
                    projectpluginmap.NsxPlugins.NSX_V)
        return self._core_plugin

    @abc.abstractmethod
    def get_name(self):
        pass

    @abc.abstractmethod
    def get_description(self):
        pass

    @abc.abstractmethod
    def run(self, context):
        pass
