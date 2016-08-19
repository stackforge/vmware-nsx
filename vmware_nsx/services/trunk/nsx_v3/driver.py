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

from vmware_nsx.common import nsx_constants as nsx_consts
from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.db import db as nsx_db

LOG = logging.getLogger(__name__)

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

    def _update_port_at_backend(self, context, parent_port_id, subport):
        # Retrieve the child port details
        child_port = self.plugin_driver.get_port(context, subport.port_id)
        # Retrieve the logical port ID based on the child port's neutron ID
        nsx_child_port_id = nsx_db.get_nsx_switch_and_port_id(
            session=context.session, neutron_id=subport.port_id)[1]
        # Retrieve child logical port from the backend
        nsx_child_port = self.plugin_driver._port_client.get(nsx_child_port_id)
        address_bindings = self.plugin_driver._build_address_bindings(
            child_port)
        if parent_port_id:
            # Retrieve the logical port ID based on the parent port neutron ID
            parent_vif_id = nsx_db.get_nsx_switch_and_port_id(
                session=context.session, neutron_id=parent_port_id)
            # Set properties for VLAN trunking
            if subport.segmentation_type == nsx_utils.NsxV3NetworkTypes.VLAN:
                attachment_type = nsx_consts.ATTACHMENT_CIF
                seg_id = subport.segmentation_id
        else:
            # Unset the parent port properties from child port
            attachment_type = nsx_consts.ATTACHMENT_VIF
            parent_vif_id = None
            seg_id = None
        # Update logical port in the backend to set/unset parent port
        self._nsx_plugin._port_client.update(
            lport_id=nsx_child_port.get('id'),
            vif_uuid=subport.port_id,
            name=nsx_child_port.get('display_name'),
            admin_state=nsx_child_port.get('admin_state'),
            address_bindings=address_bindings,
            switch_profile_ids=nsx_child_port.get('switching_profile_ids', []),
            attachment_type=attachment_type,
            parent_vif_id=parent_vif_id,
            parent_tag=seg_id)

    def _set_subports(self, context, parent_port_id, subports):
        for subport in subports:
            # Update port with parent port for backend.
            self._update_port_at_backend(context, parent_port_id, subport)

    def _unset_subports(self, context, subports):
        for subport in subports:
            # Update port and remove parent port attachment in the backend
            self._update_port_at_backend(
                context=context, parent_port_id=None, subport=subport)

    def trunk_created(self, context, trunk):
        if trunk.sub_ports:
            self._set_subports(context, trunk.port_id, trunk.sub_ports)
        trunk.update(status=trunk_consts.ACTIVE_STATUS)

    def trunk_deleted(self, context, trunk):
        self._unset_subports(context, trunk.sub_ports)

    def subports_added(self, context, trunk, subports):
        self._set_subports(context, trunk.port_id, subports)
        trunk.update(status=trunk_consts.ACTIVE_STATUS)

    def subports_deleted(self, context, trunk, subports):
        self._unset_subports(context, subports)
        trunk.update(status=trunk_consts.ACTIVE_STATUS)

    def trunk_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.trunk_created(payload.context, payload.current_trunk)
        elif event == events.AFTER_DELETE:
            self.trunk_deleted(payload.context, payload.original_trunk)

    def subport_event(self, resource, event, trunk_plugin, payload):
        if event == events.AFTER_CREATE:
            self.subports_added(
                payload.context, payload.original_trunk, payload.subports)
        elif event == events.AFTER_DELETE:
            self.subports_deleted(
                payload.context, payload.original_trunk, payload.subports)


class NsxV3TrunkDriver(base.DriverBase):
    """Driver to implement neutron's trunk extensions."""

    @property
    def is_loaded(self):
        try:
            return nsx_consts.VMWARE_NSX_V3_PLUGIN_NAME == cfg.CONF.core_plugin
        except cfg.NoSuchOptError:
            return False

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return cls(nsx_consts.VMWARE_NSX_V3_PLUGIN_NAME, SUPPORTED_INTERFACES,
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
