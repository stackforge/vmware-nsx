
# Copyright 2015 VMware, Inc.
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

from networking_l2gw.db.l2gateway import l2gateway_db
from networking_l2gw.services.l2gateway.common import constants as l2gw_const
from networking_l2gw.services.l2gateway import exceptions as l2gw_exc
from neutron.common import exceptions as n_exc
from neutron.i18n import _LE
from neutron import manager
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils

from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.dbexts import db as nsx_db
from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_db
LOG = logging.getLogger(__name__)


class NsxvL2GatewayDriver(l2gateway_db.L2GatewayMixin):

    """Class to handle API calls for L2 gateway and NSXv backend."""
    def __init__(self):
        super(NsxvL2GatewayDriver, self).__init__()

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _nsxv(self):
        return self._core_plugin.nsx_v

    def _edge_manager(self):
        return self._core_plugin.edge_manager

    def _validate_device_list(self, devices):
        # In NSX-v, one L2 gateway is mapped to one DLR.
        # So we expect only one device to be configured as part of
        # a L2 gateway resource.
        if len(devices) != 1:
            msg = _("NSX requires exactly one device per L2 gateway")
            raise n_exc.InvalidInput(error_message=msg)

    def _validate_interface_list(self, interfaces):
        # In NSXv, interface is mapped to a vDS VLAN port group.
        # Since HA is not supported, only one interface is expected
        if len(interfaces) != 1:
            msg = _("NSX requires exactly one interface per L2 gateway")
            raise n_exc.InvalidInput(error_message=msg)
        if not self._nsxv().vcns.validate_network(interfaces[0]['name']):
            msg = _("Configured interface not found")
            raise n_exc.InvalidInput(error_message=msg)

    def create_l2_gateway(self, context, l2_gateway):
        """Create a logical L2 gateway."""
        self._admin_check(context, 'CREATE')
        gw = l2_gateway[self.gateway_resource]
        devices = gw['devices']
        self._validate_device_list(devices)
        interfaces = devices[0]['interfaces']
        self._validate_interface_list(interfaces)
        # Create a dedicated DLR
        try:
            edge_id = self._create_l2_gateway_edge(context)
        except nsx_exc.NsxL2GWDeviceNotFound:
            LOG.exception(_LE("Failed to create backend device "
                              "for L2 gateway"))
            raise nsx_exc.NsxL2GWDeviceNotFound

        devices[0]['device_name'] = edge_id
        l2_gateway[self.gateway_resource]['devices'] = devices
        return super(NsxvL2GatewayDriver, self).create_l2_gateway(context,
                                                                  l2_gateway)

    def _create_l2_gateway_edge(self, context):
        # Create a dedicated DLR
        lrouter = {}
        lrouter['name'] = "L2 bridging"
        lrouter['id'] = uuidutils.generate_uuid()
        edge_manager = self._edge_manager()
        edge_manager.create_lrouter(context, lrouter, lswitch=None, dist=True)
        edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                       lrouter['id'])
        if not edge_binding:
            raise nsx_exc.NsxL2GWDeviceNotFound()
        return edge_binding['edge_id']

    def _get_device(self, context, l2gw_id):
        devices = self._get_l2_gateway_devices(context, l2gw_id)
        return devices[0]

    def create_l2_gateway_connection(self, context, l2_gateway_connection):
        """Create a L2 gateway connection."""
        self._admin_check(context, 'CREATE')
        gw_connection = l2_gateway_connection.get(l2gw_const.
                                                  CONNECTION_RESOURCE_NAME)
        l2gw_connection = super(
                NsxvL2GatewayDriver, self).create_l2_gateway_connection(
                    context, l2_gateway_connection)
        network_id = gw_connection.get('network_id')
        virtual_wire = nsx_db.get_nsx_switch_ids(context.session, network_id)
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        # In NSX-v, there will be only one device configured per L2 gateway.
        # The name of the device shall carry the backend DLR.
        device = self._get_device(context, l2gw_id)
        device_name = device.get('device_name')
        device_id = device.get('id')
        interface = self._get_l2_gw_interfaces(context, device_id)
        interface_name = interface[0].get("interface_name")
        bridge_name = "bridge-" + uuidutils.generate_uuid()
        bridge_dict = {"bridges":
                       {"bridge":
                        {"name": bridge_name,
                         "virtualWire": virtual_wire[0],
                         "dvportGroup": interface_name}}}
        try:
            self._nsxv().create_bridge(device_name, bridge_dict)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(NsxvL2GatewayDriver, self).delete_l2_gateway_connection(
                    context, l2gw_connection['id'])
                LOG.exception(_LE("Failed to update NSX, "
                                  "rolling back changes on neutron"))
        return l2gw_connection

    def delete_l2_gateway_connection(self, context, l2_gateway_connection):
        """Delete a L2 gateway connection."""
        self._admin_check(context, 'DELETE')
        gw_connection = self.get_l2_gateway_connection(context,
                                                       l2_gateway_connection)
        if not gw_connection:
            raise l2gw_exc.L2GatewayConnectionNotFound(
                l2_gateway_connection)
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        device = self._get_device(context, l2gw_id)
        device_name = device.get('device_name')
        self._nsxv().delete_bridge(device_name)
        return super(NsxvL2GatewayDriver,
                     self).delete_l2_gateway_connection(context,
                                                        l2_gateway_connection)

    def delete_l2_gateway(self, context, l2_gateway):
        """Delete a L2 gateway."""
        self._admin_check(context, 'DELETE')
        device = self._get_device(context, l2_gateway)
        super(NsxvL2GatewayDriver, self).delete_l2_gateway(context, l2_gateway)
        edge_id = device.get('device_name')
        rtr_binding = nsxv_db.get_nsxv_router_binding_by_edge(
                        context.session, edge_id)
        if rtr_binding:
            edge_manager = self._edge_manager()
            edge_manager.delete_lrouter(context, rtr_binding['router_id'])
