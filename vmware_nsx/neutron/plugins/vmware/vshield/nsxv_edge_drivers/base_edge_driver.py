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

import abc

from oslo_config import cfg
from oslo_log import log as logging
import six

from vmware_nsx.neutron.plugins.vmware.common import nsxv_constants
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    exceptions as nsxv_exc)
from vmware_nsx.neutron.plugins.vmware.vshield.common import constants

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class EdgeAbstractDriver(object):
    """Abstract edge driver that expose API for edge_utils."""

    @abc.abstractmethod
    def get_type(self):
        return

    @abc.abstractmethod
    def validate_payload(self):
        return

    @abc.abstractmethod
    def serializable_payload(self):
        return

    @abc.abstractmethod
    def deploy_edge(self, appliance_size,
                    name=None, internal_network=None,
                    jobdata=None, async=True, wait_for_exec=False):
        return

    @abc.abstractmethod
    def deploy(self, jobdata=None, async=True, wait_for_exec=False):
        return

    @abc.abstractmethod
    def update_edge(self, edge_id, appliance_size,
                    name=None, internal_network=None,
                    jobdata=None, async=True):
        return

    @abc.abstractmethod
    def update(self, edge_id, jobdata=None, async=True):
        return

    @abc.abstractmethod
    def delete_edge(self, edge_id, jobdata=None):
        return

    @abc.abstractmethod
    def delete(self, edge_id, jobdata=None):
        return


class EdgeBaseDriver(EdgeAbstractDriver):

    def __init__(self, nsx_v, edge_type, name=None,
                 fqdn=None, enable_aesni=True, enable_fips=False,
                 master_edge_id=None):
        self.nsx_v = nsx_v
        self._edge_type = edge_type
        self.edge_name = name
        self.payload = {
            'name': name,
            'fqdn': fqdn,
            'enableAesni': enable_aesni,
            'enableFips': enable_fips,
            'type': nsxv_constants.EdgeTypeMapping.get(edge_type)}
        self.cli_settings = EdgeCliSettings().payload
        self.appliances = {}
        self.vnics = []
        self.interfaces = []
        self.features = []

    def get_type(self):
        return self._edge_type

    def set_cli_settings(self, user_name=None, password=None,
                         remote_access=False):
        self.cli_settings = EdgeCliSettings(user_name, password, remote_access)

    def set_appliances(self, appliance_size, deployment_container_id=None,
                       datacenter_moid=None, resource_pool_id=None,
                       datastore_id=None):
        self.appliances = EdgeAppliances(
            appliance_size, deployment_container_id,
            datacenter_moid, resource_pool_id, datastore_id).payload

    def add_vnic(self, portgroup_id, name=None, index=None,
                 tunnel_index=-1, primary_address=None, subnet_mask=None,
                 secondary=None, type="internal", enable_proxy_arp=False,
                 enable_send_redirects=True, is_connected=True, mtu=1600,
                 address_groups=None):
        if index is None:
            index = len(self.vnics) + 1
        vnic = EdgeVnic(name, index, portgroup_id, tunnel_index,
                        primary_address, subnet_mask, secondary, type,
                        enable_proxy_arp, enable_send_redirects,
                        is_connected, mtu, address_groups)
        self.vnics.append(vnic.payload)

    def add_interface(self, portgroup_id, primary_address=None,
                      subnet_mask=None, secondary=None, type="internal",
                      is_connected=True, mtu=1500, address_groups=None):
        interface = EdgeInterface(portgroup_id, primary_address, subnet_mask,
                                  secondary, type, is_connected, mtu,
                                  address_groups).payload
        self.interfaces.append(interface)

    def add_dhcp(self, static_bindings=None, enabled=True):
        dhcp_payload = EdgeDhcpService(static_bindings, enabled).payload
        self.features.append(dhcp_payload)

    def validate_payload(self):
        if not self.appliances:
            msg = _('payload is invalid since have not filled appliances')
            raise nsxv_exc.VcnsBadRequest(resource='edge', msg=msg)

    def serializable_payload(self):
        self.validate_payload()
        cli_settings = self.cli_settings
        appliances = self.appliances.copy()
        vnics = self.vnics
        interfaces = self.interfaces
        features = self.features

        payload = self.payload.copy()
        payload['cliSettings'] = cli_settings
        if appliances.get('datacenterMoid'):
            payload['datacenterMoid'] = appliances.pop('datacenterMoid')
        if appliances:
            payload['appliances'] = appliances
        if vnics:
            payload['vnics'] = {'vnics': vnics}
        if interfaces:
            payload['interfaces'] = {'interfaces': interfaces}
        if features:
            payload['featureConfigs'] = {'features': features}
        LOG.debug(_("payload of the edge is %s"), payload)
        return payload

    def _prepare_before_send(self):
        return

    def deploy_edge(self, appliance_size,
                    name=None, internal_network=None,
                    jobdata=None, async=True, wait_for_exec=False):
        if name:
            self.payload['name'] = name
        self.set_appliances(appliance_size)
        if internal_network:
            self.add_vnic(internal_network,
                          name=constants.INTERNAL_VNIC_NAME,
                          index=constants.INTERNAL_VNIC_INDEX,
                          primary_address=constants.INTEGRATION_EDGE_IPADDRESS,
                          subnet_mask=constants.INTEGRATION_SUBNET_NETMASK)
        self._prepare_before_send()
        return self.deploy(jobdata, async, wait_for_exec)

    def deploy(self, jobdata=None, async=True, wait_for_exec=False):
        payload = self.serializable_payload()
        resource_id = self.edge_name if self.edge_name else ''
        return self.nsx_v.deploy_edge_obj(self.edge_name, resource_id, payload,
                                          jobdata=jobdata,
                                          edge_type=self.get_type(),
                                          async=async,
                                          wait_for_exec=wait_for_exec)

    def update_edge(self, edge_id, appliance_size,
                    name=None, internal_network=None,
                    jobdata=None, async=True):
        if name:
            self.payload['name'] = name
        self.set_appliances(appliance_size)
        if internal_network:
            self.add_vnic(internal_network,
                          name=constants.INTERNAL_VNIC_NAME,
                          index=constants.INTERNAL_VNIC_INDEX,
                          primary_address=constants.INTEGRATION_EDGE_IPADDRESS,
                          subnet_mask=constants.INTEGRATION_SUBNET_NETMASK)
        self._prepare_before_send()
        return self.update(edge_id, jobdata=jobdata, async=async)

    def update(self, edge_id, jobdata=None, async=True):
        payload = self.serializable_payload()
        resource_id = edge_id
        return self.nsx_v.update_edge_obj(payload.get('name'), resource_id,
                                          edge_id, payload,
                                          jobdata=jobdata,
                                          edge_type=self.get_type(),
                                          async=async)

    def delete_edge(self, edge_id, jobdata=None):
        return self.delete(edge_id, jobdata)

    def delete(self, edge_id, jobdata=None):
        resource_id = edge_id
        return self.nsx_v.delete_edge(resource_id, edge_id,
                                      jobdata=jobdata,
                                      edge_type=self.get_type())


class EdgeCliSettings(object):

    def __init__(self, user_name=None, password=None, remote_access=False):
        self.payload = {'remoteAccess': remote_access}
        user_name = user_name or cfg.CONF.nsxv.edge_appliance_user
        password = password or cfg.CONF.nsxv.edge_appliance_password
        if user_name and password:
            self.payload['userName'] = user_name
            self.payload['password'] = password


class EdgeAppliances(object):

    def __init__(self, appliance_size,
                 deployment_container_id=None,
                 datacenter_moid=None, resource_pool_id=None,
                 datastore_id=None):
        self.payload = {
            'applianceSize': appliance_size,
            'appliances': []}

        deployment_container_id = (
            deployment_container_id
            or cfg.CONF.nsxv.deployment_container_id)
        datacenter_moid = datacenter_moid or cfg.CONF.nsxv.datacenter_moid
        resource_pool_id = resource_pool_id or cfg.CONF.nsxv.resource_pool_id
        datastore_id = datastore_id or cfg.CONF.nsxv.datastore_id

        if deployment_container_id:
            self.payload['deploymentContainerId'] = deployment_container_id
        elif (datacenter_moid and resource_pool_id and datastore_id):
            self.payload['datacenterMoid'] = datacenter_moid
            self.payload['appliances'].append({
                'resourcePoolId': resource_pool_id,
                'datastoreId': datastore_id})


class EdgeVnic(object):

    def __init__(self, name, index, portgroup_id, tunnel_index=-1,
                 primary_address=None, subnet_mask=None,
                 secondary=None,
                 type="internal",
                 enable_proxy_arp=False,
                 enable_send_redirects=True,
                 is_connected=True,
                 mtu=1500,
                 address_groups=None):
        self.payload = self._assemble_edge_vnic(
            name, index, portgroup_id, tunnel_index,
            primary_address, subnet_mask, secondary,
            type, enable_proxy_arp, enable_send_redirects,
            is_connected, mtu, address_groups)

    def _assemble_edge_vnic(self, name, index, portgroup_id, tunnel_index=-1,
                            primary_address=None, subnet_mask=None,
                            secondary=None,
                            type="internal",
                            enable_proxy_arp=False,
                            enable_send_redirects=True,
                            is_connected=True,
                            mtu=1500,
                            address_groups=None):
        vnic = {
            'index': index,
            'name': name,
            'type': type,
            'portgroupId': portgroup_id,
            'mtu': mtu,
            'enableProxyArp': enable_proxy_arp,
            'enableSendRedirects': enable_send_redirects,
            'isConnected': is_connected
        }
        if address_groups is None:
            address_groups = []
        if not address_groups:
            if primary_address and subnet_mask:
                address_group = {
                    'primaryAddress': primary_address,
                    'subnetMask': subnet_mask
                }
                if secondary:
                    address_group['secondaryAddresses'] = {
                        'ipAddress': secondary,
                        'type': 'secondary_addresses'
                    }

                vnic['addressGroups'] = {
                    'addressGroups': [address_group]
                }
            else:
                vnic['subInterfaces'] = {'subInterfaces': address_groups}
        else:
            if tunnel_index < 0:
                vnic['addressGroups'] = {'addressGroups': address_groups}
            else:
                vnic['subInterfaces'] = {'subInterfaces': address_groups}

        return vnic


class EdgeInterface(object):

    def __init__(self, portgroup_id,
                 primary_address=None, subnet_mask=None,
                 secondary=None,
                 type="internal",
                 is_connected=True,
                 mtu=1500,
                 address_groups=None):
        self.payload = self._assemble_vdr_interface(
            portgroup_id, primary_address, subnet_mask, secondary, type,
            is_connected, mtu, address_groups)

    def _assemble_vdr_interface(self, portgroup_id,
                                primary_address=None, subnet_mask=None,
                                secondary=None,
                                type="internal",
                                is_connected=True,
                                mtu=1500,
                                address_groups=None):
        interface = {
            'type': type,
            'connectedToId': portgroup_id,
            'mtu': mtu,
            'isConnected': is_connected
        }
        if address_groups is None:
            address_groups = []
        if not address_groups:
            if primary_address and subnet_mask:
                address_group = {
                    'primaryAddress': primary_address,
                    'subnetMask': subnet_mask
                }
                if secondary:
                    address_group['secondaryAddresses'] = {
                        'ipAddress': secondary,
                        'type': 'secondary_addresses'
                    }

                interface['addressGroups'] = {
                    'addressGroups': [address_group]
                }
        else:
            interface['addressGroups'] = {'addressGroups': address_groups}
        return interface


class EdgeDhcpService(object):

    def __init__(self, static_bindings=None, enabled=True):
        if not static_bindings:
            static_bindings = []
        self.payload = {'featureType': "dhcp_4.0",
                        'enabled': enabled,
                        'staticBindings': {'staticBindings': static_bindings}}
