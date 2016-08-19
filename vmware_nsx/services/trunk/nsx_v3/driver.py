# Copyright 2016 VMware, Inc.
#
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
from oslo_log import log as logging

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.extensions import portbindings
from neutron.services.trunk import constants as trunk_consts
from neutron.services.trunk.drivers import base

LOG = logging.getLogger(__name__)

VMWARE_NSX_V3_PLUGIN_NAME = 'vmware_nsx.plugin.NsxV3Plugin'
SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
)
SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.VLAN,
)


class NsxV3TrunkHandler(object):
    """Class to handle trunk events."""

    def __init__(self, plugin_driver):
        self.plugin_driver = plugin_driver

    def trunk_created(self, trunk):
        pass

    def trunk_deleted(self, trunk):
        pass

    def subports_added(self, trunk, subports):
        pass

    def subports_deleted(self, subports):
        pass

    def trunk_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.trunk_created(payload.current_trunk)
        elif event == events.AFTER_DELETE:
            self.trunk_deleted(payload.original_trunk)

    def subport_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.subports_added(payload.original_trunk, payload.subports)
        elif event == events.AFTER_DELETE:
            self.subports_deleted(payload.subports)


class NsxV3TrunkDriver(base.DriverBase):
    """Driver to implement neutron's trunk extensions."""

    @property
    def is_loaded(self):
        try:
            return VMWARE_NSX_V3_PLUGIN_NAME == cfg.CONF.core_plugin
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(VMWARE_NSX_V3_PLUGIN_NAME, SUPPORTED_INTERFACES,
                   SUPPORTED_SEGMENTATION_TYPES,
                   agent_type=None, can_trunk_bound_port=False)

    def register(self, resource, event, trigger, **kwargs):
        super(NsxV3TrunkDriver, self).register(
            resource, event, trigger, **kwargs)
        self._handler = NsxV3TrunkHandler(self.plugin_driver)
        for event in (events.AFTER_CREATE, events.AFTER_DELETE):
            registry.subscribe(self._handler.trunk_event,
                               trunk_consts.TRUNK,
                               event)
            registry.subscribe(self._handler.subport_event,
                               trunk_consts.SUBPORTS,
                               event)
        LOG.debug("VMware NSXv3 trunk driver initialized.")
