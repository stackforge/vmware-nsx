# Copyright 2013 VMware, Inc.  All rights reserved.
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

from sqlalchemy.orm import exc as sa_orm_exc

from neutron.db import _model_query as model_query
from neutron.db import _utils as db_utils
from neutron.db import api as db_api
from neutron.plugins.common import utils
from neutron_lib import constants
from neutron_lib import exceptions
from oslo_log import log as logging
from oslo_utils import uuidutils
import six

from vmware_nsx._i18n import _
from vmware_nsx.db import nsx_models
from vmware_nsx.extensions import networkgw

LOG = logging.getLogger(__name__)
DEVICE_OWNER_NET_GW_INTF = 'network:gateway-interface'
NETWORK_ID = 'network_id'
SEGMENTATION_TYPE = 'segmentation_type'
SEGMENTATION_ID = 'segmentation_id'
ALLOWED_CONNECTION_ATTRIBUTES = set((NETWORK_ID,
                                     SEGMENTATION_TYPE,
                                     SEGMENTATION_ID))
# Constants for gateway device operational status
STATUS_UNKNOWN = "UNKNOWN"
STATUS_ERROR = "ERROR"
STATUS_ACTIVE = "ACTIVE"
STATUS_DOWN = "DOWN"


class GatewayInUse(exceptions.InUse):
    message = _("Network Gateway '%(gateway_id)s' still has active mappings "
                "with one or more neutron networks.")


class GatewayNotFound(exceptions.NotFound):
    message = _("Network Gateway %(gateway_id)s could not be found")


class GatewayDeviceInUse(exceptions.InUse):
    message = _("Network Gateway Device '%(device_id)s' is still used by "
                "one or more network gateways.")


class GatewayDeviceNotFound(exceptions.NotFound):
    message = _("Network Gateway Device %(device_id)s could not be found.")


class GatewayDevicesNotFound(exceptions.NotFound):
    message = _("One or more Network Gateway Devices could not be found: "
                "%(device_ids)s.")


class NetworkGatewayPortInUse(exceptions.InUse):
    message = _("Port '%(port_id)s' is owned by '%(device_owner)s' and "
                "therefore cannot be deleted directly via the port API.")


class GatewayConnectionInUse(exceptions.InUse):
    message = _("The specified mapping '%(mapping)s' is already in use on "
                "network gateway '%(gateway_id)s'.")


class MultipleGatewayConnections(exceptions.Conflict):
    message = _("Multiple network connections found on '%(gateway_id)s' "
                "with provided criteria.")


class GatewayConnectionNotFound(exceptions.NotFound):
    message = _("The connection %(network_mapping_info)s was not found on the "
                "network gateway '%(network_gateway_id)s'")


class NetworkGatewayUnchangeable(exceptions.InUse):
    message = _("The network gateway %(gateway_id)s "
                "cannot be updated or deleted")


class NetworkGatewayMixin(networkgw.NetworkGatewayPluginBase):

    gateway_resource = networkgw.GATEWAY_RESOURCE_NAME
    device_resource = networkgw.DEVICE_RESOURCE_NAME

    def _get_network_gateway(self, context, gw_id):
        try:
            gw = model_query.get_by_id(context, nsx_models.NetworkGateway,
                                       gw_id)
        except sa_orm_exc.NoResultFound:
            raise GatewayNotFound(gateway_id=gw_id)
        return gw

    def _make_gw_connection_dict(self, gw_conn):
        return {'port_id': gw_conn['port_id'],
                'segmentation_type': gw_conn['segmentation_type'],
                'segmentation_id': gw_conn['segmentation_id']}

    def _make_network_gateway_dict(self, network_gateway, fields=None):
        device_list = []
        for d in network_gateway['devices']:
            device_list.append({'id': d['id'],
                                'interface_name': d['interface_name']})
        res = {'id': network_gateway['id'],
               'name': network_gateway['name'],
               'default': network_gateway['default'],
               'devices': device_list,
               'tenant_id': network_gateway['tenant_id']}
        # Query gateway connections only if needed
        if not fields or 'ports' in fields:
            res['ports'] = [self._make_gw_connection_dict(conn)
                            for conn in network_gateway.network_connections]
        return db_utils.resource_fields(res, fields)

    def _set_mapping_info_defaults(self, mapping_info):
        if not mapping_info.get('segmentation_type'):
            mapping_info['segmentation_type'] = 'flat'
        if not mapping_info.get('segmentation_id'):
            mapping_info['segmentation_id'] = 0

    def _validate_network_mapping_info(self, network_mapping_info):
        self._set_mapping_info_defaults(network_mapping_info)
        network_id = network_mapping_info.get(NETWORK_ID)
        if not network_id:
            raise exceptions.InvalidInput(
                error_message=_("A network identifier must be specified "
                                "when connecting a network to a network "
                                "gateway. Unable to complete operation"))
        connection_attrs = set(network_mapping_info.keys())
        if not connection_attrs.issubset(ALLOWED_CONNECTION_ATTRIBUTES):
            raise exceptions.InvalidInput(
                error_message=(_("Invalid keys found among the ones provided "
                                 "in request body: %(connection_attrs)s."),
                               connection_attrs))
        seg_type = network_mapping_info.get(SEGMENTATION_TYPE)
        seg_id = network_mapping_info.get(SEGMENTATION_ID)
        # It is important to validate that the segmentation ID is actually an
        # integer value
        try:
            seg_id = int(seg_id)
        except ValueError:
            msg = _("An invalid segmentation ID was specified. The "
                    "segmentation ID must be a positive integer number")
            raise exceptions.InvalidInput(error_message=msg)
        # The NSX plugin accepts 0 as a valid vlan tag
        seg_id_valid = seg_id == 0 or utils.is_valid_vlan_tag(seg_id)
        if seg_type.lower() == 'flat' and seg_id:
            msg = _("Cannot specify a segmentation id when "
                    "the segmentation type is flat")
            raise exceptions.InvalidInput(error_message=msg)
        elif (seg_type.lower() == 'vlan' and not seg_id_valid):
            msg = _("Invalid segmentation id (%s) for "
                    "vlan segmentation type") % seg_id
            raise exceptions.InvalidInput(error_message=msg)
        return network_id

    def _retrieve_gateway_connections(self, context, gateway_id,
                                      mapping_info=None, only_one=False):
        mapping_info = mapping_info or {}
        filters = {'network_gateway_id': [gateway_id]}
        for k, v in six.iteritems(mapping_info):
            if v and k != NETWORK_ID:
                filters[k] = [v]
        query = model_query.get_collection_query(context,
                                                 nsx_models.NetworkConnection,
                                                 filters)
        return query.one() if only_one else query.all()

    def _unset_default_network_gateways(self, context):
        with db_api.context_manager.writer.using(context):
            context.session.query(nsx_models.NetworkGateway).update(
                {nsx_models.NetworkGateway.default: False})

    def _set_default_network_gateway(self, context, gw_id):
        with db_api.context_manager.writer.using(context):
            gw = (context.session.query(nsx_models.NetworkGateway).
                  filter_by(id=gw_id).one())
            gw['default'] = True

    def prevent_network_gateway_port_deletion(self, context, port):
        """Pre-deletion check.

        Ensures a port will not be deleted if is being used by a network
        gateway. In that case an exception will be raised.
        """
        if port['device_owner'] == DEVICE_OWNER_NET_GW_INTF:
            raise NetworkGatewayPortInUse(port_id=port['id'],
                                          device_owner=port['device_owner'])

    def _validate_device_list(self, context, tenant_id, gateway_data):
        device_query = self._query_gateway_devices(
            context, filters={'id': [device['id']
                                     for device in gateway_data['devices']]})
        retrieved_device_ids = set()
        for device in device_query:
            retrieved_device_ids.add(device['id'])
            if device['tenant_id'] != tenant_id:
                raise GatewayDeviceNotFound(device_id=device['id'])
        missing_device_ids = (
            set(device['id'] for device in gateway_data['devices']) -
            retrieved_device_ids)
        if missing_device_ids:
            raise GatewayDevicesNotFound(
                device_ids=",".join(missing_device_ids))

    def create_network_gateway(self, context, network_gateway,
            validate_device_list=True):
        gw_data = network_gateway[self.gateway_resource]
        tenant_id = gw_data['tenant_id']
        with db_api.context_manager.writer.using(context):
            gw_db = nsx_models.NetworkGateway(
                id=gw_data.get('id', uuidutils.generate_uuid()),
                tenant_id=tenant_id,
                name=gw_data.get('name'))
            # Device list is guaranteed to be a valid list, but some devices
            # might still either not exist or belong to a different tenant
            if validate_device_list:
                self._validate_device_list(context, tenant_id, gw_data)
            gw_db.devices.extend(
                [nsx_models.NetworkGatewayDeviceReference(**device)
                 for device in gw_data['devices']])
            context.session.add(gw_db)
            LOG.debug("Created network gateway with id:%s", gw_db['id'])
            return self._make_network_gateway_dict(gw_db)

    def update_network_gateway(self, context, id, network_gateway):
        gw_data = network_gateway[self.gateway_resource]
        with db_api.context_manager.writer.using(context):
            gw_db = self._get_network_gateway(context, id)
            if gw_db.default:
                raise NetworkGatewayUnchangeable(gateway_id=id)
            # Ensure there is something to update before doing it
            if any([gw_db[k] != gw_data[k] for k in gw_data]):
                gw_db.update(gw_data)
            LOG.debug("Updated network gateway with id:%s", id)
            return self._make_network_gateway_dict(gw_db)

    def get_network_gateway(self, context, id, fields=None):
        gw_db = self._get_network_gateway(context, id)
        return self._make_network_gateway_dict(gw_db, fields)

    def delete_network_gateway(self, context, id):
        with db_api.context_manager.writer.using(context):
            gw_db = self._get_network_gateway(context, id)
            if gw_db.network_connections:
                raise GatewayInUse(gateway_id=id)
            if gw_db.default:
                raise NetworkGatewayUnchangeable(gateway_id=id)
            context.session.delete(gw_db)
        LOG.debug("Network gateway '%s' was destroyed.", id)

    def get_network_gateways(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        marker_obj = db_utils.get_marker_obj(self,
            context, 'network_gateway', limit, marker)
        return model_query.get_collection(context, nsx_models.NetworkGateway,
                                          self._make_network_gateway_dict,
                                          filters=filters, fields=fields,
                                          sorts=sorts, limit=limit,
                                          marker_obj=marker_obj,
                                          page_reverse=page_reverse)

    def connect_network(self, context, network_gateway_id,
                        network_mapping_info):
        network_id = self._validate_network_mapping_info(network_mapping_info)
        LOG.debug("Connecting network '%(network_id)s' to gateway "
                  "'%(network_gateway_id)s'",
                  {'network_id': network_id,
                   'network_gateway_id': network_gateway_id})
        with db_api.context_manager.writer.using(context):
            gw_db = self._get_network_gateway(context, network_gateway_id)
            tenant_id = gw_db['tenant_id']
            if context.is_admin and not tenant_id:
                tenant_id = context.tenant_id
            # TODO(salvatore-orlando): Leverage unique constraint instead
            # of performing another query!
            if self._retrieve_gateway_connections(context,
                                                  network_gateway_id,
                                                  network_mapping_info):
                raise GatewayConnectionInUse(mapping=network_mapping_info,
                                             gateway_id=network_gateway_id)
            # TODO(salvatore-orlando): Creating a port will give it an IP,
            # but we actually do not need any. Instead of wasting an IP we
            # should have a way to say a port shall not be associated with
            # any subnet
            try:
                # We pass the segmentation type and id too - the plugin
                # might find them useful as the network connection object
                # does not exist yet.
                # NOTE: they're not extended attributes, rather extra data
                # passed in the port structure to the plugin
                # TODO(salvatore-orlando): Verify optimal solution for
                # ownership of the gateway port
                port = self.create_port(context, {
                    'port':
                    {'tenant_id': tenant_id,
                     'network_id': network_id,
                     'mac_address': constants.ATTR_NOT_SPECIFIED,
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': network_gateway_id,
                     'device_owner': DEVICE_OWNER_NET_GW_INTF,
                     'name': '',
                     'gw:segmentation_type':
                     network_mapping_info.get('segmentation_type'),
                     'gw:segmentation_id':
                     network_mapping_info.get('segmentation_id')}})
            except exceptions.NetworkNotFound:
                err_msg = (_("Requested network '%(network_id)s' not found."
                             "Unable to create network connection on "
                             "gateway '%(network_gateway_id)s") %
                           {'network_id': network_id,
                            'network_gateway_id': network_gateway_id})
                LOG.error(err_msg)
                raise exceptions.InvalidInput(error_message=err_msg)
            port_id = port['id']
            LOG.debug("Gateway port for '%(network_gateway_id)s' "
                      "created on network '%(network_id)s':%(port_id)s",
                      {'network_gateway_id': network_gateway_id,
                       'network_id': network_id,
                       'port_id': port_id})
            # Create NetworkConnection record
            network_mapping_info['port_id'] = port_id
            network_mapping_info['tenant_id'] = tenant_id
            gw_db.network_connections.append(
                nsx_models.NetworkConnection(**network_mapping_info))
            port_id = port['id']
            # now deallocate and recycle ip from the port
            for fixed_ip in port.get('fixed_ips', []):
                self._delete_ip_allocation(context, network_id,
                                           fixed_ip['subnet_id'],
                                           fixed_ip['ip_address'])
            LOG.debug("Ensured no Ip addresses are configured on port %s",
                      port_id)
            return {'connection_info':
                    {'network_gateway_id': network_gateway_id,
                     'network_id': network_id,
                     'port_id': port_id}}

    def disconnect_network(self, context, network_gateway_id,
                           network_mapping_info):
        network_id = self._validate_network_mapping_info(network_mapping_info)
        LOG.debug("Disconnecting network '%(network_id)s' from gateway "
                  "'%(network_gateway_id)s'",
                  {'network_id': network_id,
                   'network_gateway_id': network_gateway_id})
        with db_api.context_manager.writer.using(context):
            # Uniquely identify connection, otherwise raise
            try:
                net_connection = self._retrieve_gateway_connections(
                    context, network_gateway_id,
                    network_mapping_info, only_one=True)
            except sa_orm_exc.NoResultFound:
                raise GatewayConnectionNotFound(
                    network_mapping_info=network_mapping_info,
                    network_gateway_id=network_gateway_id)
            except sa_orm_exc.MultipleResultsFound:
                raise MultipleGatewayConnections(
                    gateway_id=network_gateway_id)
            # Remove gateway port from network
            # FIXME(salvatore-orlando): Ensure state of port in NSX is
            # consistent with outcome of transaction
            self.delete_port(context, net_connection['port_id'],
                             nw_gw_port_check=False)
            # Remove NetworkConnection record
            context.session.delete(net_connection)

    def _make_gateway_device_dict(self, gateway_device, fields=None,
                                  include_nsx_id=False):
        res = {'id': gateway_device['id'],
               'name': gateway_device['name'],
               'status': gateway_device['status'],
               'connector_type': gateway_device['connector_type'],
               'connector_ip': gateway_device['connector_ip'],
               'tenant_id': gateway_device['tenant_id']}
        if include_nsx_id:
            # Return the NSX mapping as well. This attribute will not be
            # returned in the API response anyway. Ensure it will not be
            # filtered out in field selection.
            if fields:
                fields.append('nsx_id')
            res['nsx_id'] = gateway_device['nsx_id']
        return db_utils.resource_fields(res, fields)

    def _get_gateway_device(self, context, device_id):
        try:
            return model_query.get_by_id(context,
                                         nsx_models.NetworkGatewayDevice,
                                         device_id)
        except sa_orm_exc.NoResultFound:
            raise GatewayDeviceNotFound(device_id=device_id)

    def _is_device_in_use(self, context, device_id):
        query = model_query.get_collection_query(
            context, nsx_models.NetworkGatewayDeviceReference,
            {'id': [device_id]})
        return query.first()

    def get_gateway_device(self, context, device_id, fields=None,
                           include_nsx_id=False):
        return self._make_gateway_device_dict(
            self._get_gateway_device(context, device_id),
            fields, include_nsx_id)

    def _query_gateway_devices(self, context,
                               filters=None, sorts=None,
                               limit=None, marker=None,
                               page_reverse=None):
        marker_obj = db_utils.get_marker_obj(self,
            context, 'gateway_device', limit, marker)
        return self._get_collection_query(context,
                                          nsx_models.NetworkGatewayDevice,
                                          filters=filters,
                                          sorts=sorts,
                                          limit=limit,
                                          marker_obj=marker_obj,
                                          page_reverse=page_reverse)

    def get_gateway_devices(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False, include_nsx_id=False):
        query = self._query_gateway_devices(context, filters, sorts, limit,
                                            marker, page_reverse)
        return [self._make_gateway_device_dict(row, fields, include_nsx_id)
                for row in query]

    def create_gateway_device(self, context, gateway_device,
                              initial_status=STATUS_UNKNOWN):
        device_data = gateway_device[self.device_resource]
        tenant_id = device_data['tenant_id']
        with db_api.context_manager.writer.using(context):
            device_db = nsx_models.NetworkGatewayDevice(
                id=device_data.get('id', uuidutils.generate_uuid()),
                tenant_id=tenant_id,
                name=device_data.get('name'),
                connector_type=device_data['connector_type'],
                connector_ip=device_data['connector_ip'],
                status=initial_status)
            context.session.add(device_db)
        LOG.debug("Created network gateway device: %s", device_db['id'])
        return self._make_gateway_device_dict(device_db)

    def update_gateway_device(self, context, gateway_device_id,
                              gateway_device, include_nsx_id=False):
        device_data = gateway_device[self.device_resource]
        with db_api.context_manager.writer.using(context):
            device_db = self._get_gateway_device(context, gateway_device_id)
            # Ensure there is something to update before doing it
            if any([device_db[k] != device_data[k] for k in device_data]):
                device_db.update(device_data)
        LOG.debug("Updated network gateway device: %s",
                  gateway_device_id)
        return self._make_gateway_device_dict(
            device_db, include_nsx_id=include_nsx_id)

    def delete_gateway_device(self, context, device_id):
        with db_api.context_manager.writer.using(context):
            # A gateway device should not be deleted
            # if it is used in any network gateway service
            if self._is_device_in_use(context, device_id):
                raise GatewayDeviceInUse(device_id=device_id)
            device_db = self._get_gateway_device(context, device_id)
            context.session.delete(device_db)
        LOG.debug("Deleted network gateway device: %s.", device_id)
