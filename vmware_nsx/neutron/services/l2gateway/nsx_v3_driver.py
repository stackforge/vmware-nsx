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

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils

from networking_l2gw.db.l2gateway import l2gateway_db
from networking_l2gw.services.l2gateway.common import constants as l2gw_const

from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron import context as nctx
from neutron.i18n import _LE
from neutron import manager

from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import nsx_constants
from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib

LOG = logging.getLogger(__name__)


class NsxV3Driver(l2gateway_db.L2GatewayMixin):

    """Class to handle API calls for L2 gateway and NSXv3 backend."""
    gateway_resource = l2gw_const.GATEWAY_RESOURCE_NAME

    def __init__(self):
        # Create a  default L2 gateway if default_bridge_cluster_uuid is
        # provided in nsx.ini
        self._ensure_default_l2_gateway()
        LOG.debug("Initialization complete for NSXv3 driver for "
                  "L2 gateway service plugin.")

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _ensure_default_l2_gateway(self):
        """
        Create a default logical L2 gateway.

        Create a logical L2 gateway in the neutron database if the
        default_bridge_cluster_uuid config parameter is set and if it is
        not previously created. If not set, return.
        """
        def_l2gw_uuid = cfg.CONF.nsx_v3.default_bridge_cluster_uuid
        # Return if no default_bridge_cluster_uuid set in config
        if not def_l2gw_uuid:
            return
        admin_ctx = nctx.get_admin_context()
        l2gateways = self._get_l2_gateways(admin_ctx)
        for l2gateway in l2gateways:
            for device in l2gateway['devices']:
                # Return if default L2 gateway was previously created
                if device['device_name'] == def_l2gw_uuid:
                    return
        # Create the default L2 gateway in neutron DB
        device = {'device_name': def_l2gw_uuid,
                  'interfaces': [{'name': 'default-bridge-cluster'}]}
        def_l2gw = {'name': 'default-l2gw',
                    'devices': [device]}
        l2_gateway = {self.gateway_resource: def_l2gw}
        return self.create_l2_gateway(admin_ctx, l2_gateway)

    def _validate_device_list(self, devices):
        # In NSXv3, one L2 gateway is mapped to one bridge cluster.
        # So we expect only one device to be configured as part of
        # a L2 gateway resource. The name of the device must be the bridge
        # cluster's UUID.
        if len(devices) != 1:
            msg = _("NSX requires exactly one device per L2 gateway")
            raise n_exc.InvalidInput(error_message=msg)
        if not uuidutils.is_uuid_like(devices[0]['device_name']):
            msg = _("NSX requires device name to be configured with a UUID")
            raise n_exc.InvalidInput(error_message=msg)

    def create_l2_gateway(self, context, l2_gateway):
        """Create a logical L2 gateway."""
        gw = l2_gateway[self.gateway_resource]
        devices = gw['devices']
        self._validate_device_list(devices)
        return super(NsxV3Driver, self).create_l2_gateway(context,
                                                          l2_gateway)

    def _validate_network(self, context, gw_connection):
        network_id = gw_connection.get(l2gw_const.NETWORK_ID)
        network = self._core_plugin.get_network(context, network_id)
        if not network:
            raise n_exc.NetworkNotFound(net_id=network_id)
        network_type = network.get('provider:network_type', None)
        if not network_type or network_type != "vxlan":
            msg = _("NSX: Unsupported network type %s for L2 gateway "
                    "connection. VXLAN network type supported") % network_type
            raise n_exc.InvalidInput(error_message=msg)

    def create_l2_gateway_connection(self, context, l2_gateway_connection):
        """Create a L2 gateway connection."""
        gw_connection = l2_gateway_connection.get(l2gw_const.
                                                  CONNECTION_RESOURCE_NAME)
        #self._validate_network(context, gw_connection)
        l2gw_connection = super(
            NsxV3Driver, self).create_l2_gateway_connection(
                context, l2_gateway_connection)
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        network_id = gw_connection.get(l2gw_const.NETWORK_ID)
        devices = self._get_l2_gateway_devices(context, l2gw_id)
        # In NSXv3, there will be only one device configured per L2 gateway.
        # The name of the device shall carry the backend bridge cluster's UUID.
        device_name = devices[0].get('device_name')
        # The seg-id will be provided either during gateway create or gateway
        # connection create. l2gateway_db_mixin makes sure that it is
        # configured one way or the other.
        seg_id = gw_connection.get(l2gw_const.SEG_ID, None)
        if seg_id is None:
            seg_id = devices[0]['interfaces'][0].get('segmentation_id')
        try:
            bridge_endpoint = nsxlib.create_bridge_endpoint(device_name,
                                                            seg_id)
        except nsx_exc.ManagerError:
            LOG.exception(_LE("Unable to update NSX backend, rolling back "
                              "changes on neutron"))
            with excutils.save_and_reraise_exception():
                super(NsxV3Driver,
                      self).delete_l2_gateway_connection(context,
                                                         l2gw_connection['id'])
        tenant_id = self._core_plugin._get_tenant_id_for_create(context,
                                                                gw_connection)
        # _get_tenant_id_for_create might return None in some cases.
        # This is not acceptable for the NSX plugin
        if context.is_admin and not tenant_id:
            tenant_id = context.tenant_id
        port_dict = {'port': {
                        'tenant_id': tenant_id,
                        'network_id': network_id,
                        'mac_address': attributes.ATTR_NOT_SPECIFIED,
                        'admin_state_up': True,
                        'fixed_ips': [],
                        'device_id': bridge_endpoint['id'],
                        'device_owner': nsx_constants.BRIDGE_ENDPOINT,
                        'name': '', }}
        #TODO(abhiraut): Add try except block here
        try:
            port = self._core_plugin.create_port(context, port_dict)
            # Deallocate IP address from the port.
            for fixed_ip in port.get('fixed_ips', []):
                self._core_plugin._delete_ip_allocation(context, network_id,
                                                        fixed_ip['subnet_id'],
                                                        fixed_ip['ip_address'])
            LOG.debug("IP addresses deallocated on port %s", port['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                nsxlib.delete_bridge_endpoint(bridge_endpoint['id'])
                super(NsxV3Driver,
                      self).delete_l2_gateway_connection(context,
                                                         l2gw_connection['id'])
        return l2gw_connection

    def delete_l2_gateway_connection(self, context, l2_gateway_connection):
        """Delete a L2 gateway connection."""
        #TODO(abhiraut): Add backend logic
        return super(NsxV3Driver,
                     self).delete_l2_gateway_connection(context,
                                                        l2_gateway_connection)
