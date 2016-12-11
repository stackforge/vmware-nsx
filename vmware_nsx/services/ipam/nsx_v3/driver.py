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

import netaddr

from oslo_log import log as logging

from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req

from vmware_nsx._i18n import _, _LE
from vmware_nsx.services.ipam.common import driver as common
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as error
from vmware_nsxlib.v3 import resources

LOG = logging.getLogger(__name__)


class Nsxv3IpamDriver(common.NsxAbstractIpamDriver):
    """IPAM Driver For NSX-V external & provider networks."""

    def __init__(self, subnetpool, context):
        super(Nsxv3IpamDriver, self).__init__(subnetpool, context)
        self.nsxlib_ipam = resources.IpPool(
            self.get_core_plugin().nsxlib.client)

    @property
    def _subnet_class(self):
        return Nsxv3IpamSubnet

    def _get_cidr_from_request(self, subnet_request):
        return "%s/%s" % (subnet_request.subnet_cidr[0],
                          subnet_request.prefixlen)

    def allocate_backend_pool(self, subnet_request):
        """Create a pool on the NSX backend and return its ID"""
        if subnet_request.allocation_pools:
            ranges = [
                {'start': netaddr.IPAddress(pool.first),
                 'end': netaddr.IPAddress(pool.last)}
                for pool in subnet_request.allocation_pools]
        else:
            ranges = []

        # name/description length on backend is long, so there is no problem
        name = 'subnet_' + subnet_request.subnet_id
        description = 'OS IP pool for subnet ' + subnet_request.subnet_id
        try:
            response = self.nsxlib_ipam.create(
                display_name=name,
                description=description,
                gateway_ip=subnet_request.gateway_ip,
                cidr=self._get_cidr_from_request(subnet_request),
                ranges=ranges)
            nsx_pool_id = response['id']
        except Exception as e:
            #TODO(asarfaty): handle specific errors
            msg = _('Failed to create subnet IPAM: %s') % e
            raise ipam_exc.IpamValueInvalid(message=msg)
        return nsx_pool_id

    def delete_backend_pool(self, nsx_pool_id):
        try:
            self.nsxlib_ipam.create(nsx_pool_id)
        except Exception as e:
            LOG.error(_LE("Failed to delete IPAM from backend: %s"), e)
            # Continue anyway, since this subnet was already removed


class Nsxv3IpamSubnet(common.NsxAbstractIpamSubnet):
    """Manage IP addresses for the NSX V3 IPAM driver."""

    def __init__(self, subnet_id, nsx_pool_id, ctx, tenant_id):
        super(Nsxv3IpamSubnet, self).__init__(
            subnet_id, nsx_pool_id, ctx, tenant_id)
        self.nsxlib_ipam = resources.IpPool(
            self.get_core_plugin().nsxlib.client)

    def backend_allocate(self, address_request):
        try:
            # allocate a specific IP
            if isinstance(address_request, ipam_req.SpecificAddressRequest):
                # This handles both specific and automatic address requests
                ip_address = str(address_request.address)
            else:
                # Allocate any free IP
                ip_address = None
            response = self.nsxlib_ipam.allocate(self._nsx_pool_id,
                                                 ip_addr=ip_address)
            ip_address = response['allocation_id']
        except nsx_lib_exc.ManagerError as e:
            LOG.error(_LE("NSX IPAM failed to allocate ip %(ip)s of subnet "
                          "%(id)s:"
                          " %(e)s; code %(code)s"),
                      {'e': e,
                       'ip': ip_address,
                       'id': self._subnet_id,
                       'code': e.error_code})
            # Currently the backend does not support allocation of specific IPs
            # When this support is added we should handle allocation errors.
            if e.error_code == error.ERR_CODE_IPAM_INSUFFICIENT_FREE_IP:
                # No more IP addresses available on the pool
                raise ipam_exc.IpAddressGenerationFailure(
                    subnet_id=self._subnet_id)
            if e.error_code == error.ERR_CODE_IPAM_SPECIFIC_IP:
                msg = (_("NSX-V3 IPAM driver does not support allocation of a "
                         "specific ip %s for port") % ip_address)
                raise ipam_exc.IpamValueInvalid(message=msg)
            if e.error_code == error.ERR_CODE_OBJET_NOT_FOUND:
                msg = (_("NSX-V3 IPAM failed to allocate: pool %s was not "
                        "found") % self._nsx_pool_id)
                raise ipam_exc.IpamValueInvalid(message=msg)
            else:
                # another backend error
                raise ipam_exc.IPAllocationFailed()
        except Exception as e:
            # handle unexpected failures
            raise ipam_exc.IPAllocationFailed()
        return ip_address

    def backend_deallocate(self, address):
        try:
            self.nsxlib_ipam.release(self._nsx_pool_id, ip_addr=address)
        except nsx_lib_exc.ManagerError as e:
            LOG.error(_LE("NSX IPAM failed to free ip %(ip)s of subnet "
                          "%(id)s:"
                          " %(e)s; code %(code)s"),
                      {'e': e,
                       'ip': address,
                       'id': self._subnet_id,
                       'code': e.error_code})
            raise ipam_exc.IpAddressAllocationNotFound(
                subnet_id=self._subnet_id,
                ip_address=address)

    def get_details(self):
        """Return subnet data as a SpecificSubnetRequest"""
        # get the pool from the backend
        try:
            pool_details = self.nsxlib_ipam.get(self._nsx_pool_id)
        except Exception as e:
            msg = _('Failed to get details for nsx pool: %(id)s: '
                    '%(e)s') % {'id': self._nsx_pool_id, 'e': e}
            raise ipam_exc.IpamValueInvalid(message=msg)

        first_range = pool_details.get('subnets', [None])[0]
        if not first_range:
            msg = _('Failed to get details for nsx pool: %(id)s') % {
                'id': self._nsx_pool_id}
            raise ipam_exc.IpamValueInvalid(message=msg)

        cidr = first_range.get('cidr')
        gateway_ip = first_range.get('gateway_ip')
        pools = []
        for subnet in pool_details.get('subnets', []):
            for ip_range in subnet.get('allocation_ranges', []):
                pools.append(netaddr.IPRange(ip_range.get('start'),
                                             ip_range.get('end')))

        return ipam_req.SpecificSubnetRequest(
            self._tenant_id, self._subnet_id,
            cidr, gateway_ip=gateway_ip, allocation_pools=pools)
