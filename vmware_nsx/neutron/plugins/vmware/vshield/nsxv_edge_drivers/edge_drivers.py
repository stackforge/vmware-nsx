# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2015 VMware, Inc
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

from vmware_nsx.neutron.plugins.vmware.common import nsxv_constants
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    exceptions as nsxv_exc)
from vmware_nsx.neutron.plugins.vmware.vshield.common import constants
from vmware_nsx.neutron.plugins.vmware.vshield.nsxv_edge_drivers import (
    base_edge_driver)
from vmware_nsx.neutron.plugins.vmware.vshield import nsxv_int_obj_utils


class EdgeServiceDriver(base_edge_driver.EdgeBaseDriver):

    def get_type(self):
        if self._edge_type != nsxv_constants.SERVICE_EDGE:
            msg = _('Inconsist mapping between edge type and driver')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)
        return self._edge_type

    def add_interface(self, portgroup_id, primary_address=None,
                      subnet_mask=None, secondary=None, type="internal",
                      is_connected=True, mtu=1500, address_groups=None):
        msg = _('Can not add interface on service edge')
        raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)

    def validate_payload(self):
        super(EdgeServiceDriver, self).validate_payload()
        if not self.vnics:
            msg = _('At least one vnic should be added in service edge')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)
        if self.interfaces:
            msg = _('Can not add interface on service edge')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)

    def serializable_payload(self):
        payload = super(EdgeServiceDriver, self).serializable_payload()
        self.nsx_v._enable_loadbalancer(payload)
        return payload

    def _prepare_before_send(self):
        if not self.vnics:
            external_vnic = self.add_vnic(
                self.nsx_v.external_network,
                name=constants.EXTERNAL_VNIC_NAME,
                index=constants.EXTERNAL_VNIC_INDEX,
                type="uplink")
            self.vnics.append(external_vnic)


class EdgeVdrDriver(base_edge_driver.EdgeBaseDriver):

    def get_type(self):
        if self._edge_type != nsxv_constants.VDR_EDGE:
            msg = _('Inconsist mapping between edge type and driver')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)
        return self._edge_type

    def add_vnic(self, portgroup_id, name=None, index=None,
                 tunnel_index=-1, primary_address=None, subnet_mask=None,
                 secondary=None, type="internal", enable_proxy_arp=False,
                 enable_send_redirects=True, is_connected=True, mtu=1600,
                 address_groups=None):
        msg = _('Can not add vnic on vdr edge')
        raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)

    def validate_payload(self):
        super(EdgeVdrDriver, self).validate_payload()
        if self.vnics:
            msg = _('Can not add vnic on vdr edge')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)

    def _prepare_before_send(self):
        if not self.payload.get('mgmtInterface'):
            self.payload['mgmtInterface'] = {
                'connectedToId': self.nsx_v.external_network,
                'name': "mgmtInterface"}


class EdgeMultiContextDriver(base_edge_driver.EdgeBaseDriver):

    def get_type(self):
        if self._edge_type != nsxv_constants.MULTI_CONTEXT_EDGE:
            msg = _('Inconsist mapping between edge type and driver')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)
        return self._edge_type

    def add_interface(self, portgroup_id, primary_address=None,
                      subnet_mask=None, secondary=None, type="internal",
                      is_connected=True, mtu=1500, address_groups=None):
        msg = _('Can not add interface on multi context gateway edge')
        raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)

    def validate_payload(self):
        super(EdgeMultiContextDriver, self).validate_payload()
        if self.interfaces:
            msg = _('Can not add interface on multi context gateway edge')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)
        for vnic in self.vnics:
            if vnic.get('type') == 'trunk':
                return
        msg = _('At least one trunk vnic should be added '
                'in multi context edge which is for service container '
                'edge use')
        raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)

    def _prepare_before_send(self):
        is_trunk_vnic_exist = False
        for vnic in self.vnics:
            if vnic.get('type') == 'trunk':
                is_trunk_vnic_exist = True
                break
        if not is_trunk_vnic_exist:
            self.nsxv_plugin = self.nsx_v.callbacks.plugin
            trunk_net_obj = nsxv_int_obj_utils.NsxvInternalNet(
                self.nsxv_plugin)
            trunk_net_ref = trunk_net_obj.get_internal_network_at_backend(
                nsxv_constants.TRUNK_EDGE_PURPOSE, net_type='flat')
            self.add_vnic(trunk_net_ref, type='trunk')


class EdgeServiceContainerDriver(base_edge_driver.EdgeBaseDriver):

    def __init__(self, nsx_v, edge_type, name=None,
                 fqdn=None, enable_aesni=True, enable_fips=False,
                 master_edge_id=None):
        super(EdgeServiceContainerDriver, self).__init__(
            nsx_v, edge_type, name=name,
            fqdn=fqdn, enable_aesni=enable_aesni, enable_fips=enable_fips,
            master_edge_id=master_edge_id)
        self.payload['masterEdgeId'] = master_edge_id

    def get_type(self):
        if self._edge_type != nsxv_constants.SERVICE_CONTAINER_EDGE:
            msg = _('Inconsist mapping between edge type and driver')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)
        return self._edge_type

    def add_vnic(self, portgroup_id, name=None, index=None,
                 tunnel_index=-1, primary_address=None, subnet_mask=None,
                 secondary=None, type="internal", enable_proxy_arp=False,
                 enable_send_redirects=True, is_connected=True, mtu=1600,
                 address_groups=None):
        msg = _('Can not add vnic on service container edge')
        raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)

    def set_master_edge_id(self, master_edge_id):
        self.payload['masterEdgeId'] = master_edge_id

    def validate_payload(self):
        if self.vnics:
            msg = _('Can not add vnic on service container edge')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)
        if not self.payload.get('masterEdgeId'):
            msg = _('masterEdgeId must be required for service container edge')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)

    def set_appliances(self, appliance_size, deployment_container_id=None,
                       datacenter_moid=None, resource_pool_id=None,
                       datastore_id=None):
        # No need to set appliance for service container edge.
        return
