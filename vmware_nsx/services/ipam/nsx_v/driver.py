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

from neutron.extensions import external_net as ext_net_extn
from neutron.extensions import multiprovidernet as mpnet
from neutron.ipam import driver as ipam_base
from neutron.ipam.drivers.neutrondb_ipam import driver as neutron_driver
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc
from neutron import manager
from neutron_lib.api import validators
from oslo_log import log as logging

from vmware_nsx._i18n import _LE
from vmware_nsx.common import config  # noqa
#from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db

LOG = logging.getLogger(__name__)


class NsxvIpamDriver(subnet_alloc.SubnetAllocator):
    """IPAM Driver For NSX-V external & provider networks."""

    def __init__(self, subnetpool, context):
        super(NsxvIpamDriver, self).__init__(subnetpool, context)
        # in case of regular networks - we will use the internal driver
        self.default_implementation_instance = neutron_driver.NeutronDbPool(
            subnetpool, context)

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    @property
    def _vcns(self):
        return self._core_plugin.nsx_v.vcns

    def _is_ext_or_provider_net(self, subnet_request):
        network_id = subnet_request.network_id
        if network_id:
            network = self._core_plugin.get_network(self._context, network_id)
            if network.get(ext_net_extn.EXTERNAL):
                # external network
                return True
            if validators.is_attr_set(network.get(mpnet.SEGMENTS)):
                # provider network
                return True

        return False

    def get_subnet(self, subnet_id):
        """Retrieve an IPAM subnet."""
        nsx_pool_id = nsxv_db.get_nsxv_ipam_pool_for_subnet(
            self._context.session, subnet_id)
        if not nsx_pool_id:
            # This is either an old pre-upgrade subnet or a regular subnet
            self.default_implementation_instance.get_subnet(subnet_id)
            return

        return NsxvIpamSubnet.load(subnet_id, nsx_pool_id, self._context)

    def get_subnet_request_factory(self):
        # override the OOB factory to add the network ID
        return NsxvSubnetRequestFactory

    def allocate_backend_pool(self, subnet_request):
        LOG.error(_LE("DEBUG ADIT allocate_backend_pool for request: "
                      "%(g)s,%(a)s,%(s)s,%(p)s"),
                  {'g': subnet_request.gateway_ip,
                   'a': subnet_request.allocation_pools,
                   's': subnet_request.subnet_cidr,
                   'p': subnet_request.prefixlen})
        # DEBUG ADIT validation...
        # DEBUG ADIT can be more than one?? handle this in get_details too
        pool = subnet_request.allocation_pools[0]
        request = {'ipamAddressPool':
            {'name': 'subnet' + subnet_request.subnet_id,
             'prefixLength': subnet_request.prefixlen,
             'gateway': subnet_request.gateway_ip,
             'ipRanges':
                {'ipRangeDto':
                    {'startAddress': netaddr.IPAddress(pool.first),
                     'endAddress': netaddr.IPAddress(pool.last)}}}}

        response = self._vcns.create_ipam_ip_pool(request)
        nsx_pool_id = response[1]
        return nsx_pool_id

    def allocate_subnet(self, subnet_request):
        """Create an IPAMSubnet object for the provided cidr.

        :param cidr: subnet's CIDR
        :returns: a NeutronDbSubnet instance
        """
        if not self._is_ext_or_provider_net(subnet_request=subnet_request):
            # fallback to the neutron internal driver implementation
            return self.default_implementation_instance.allocate_subnet(
                subnet_request)

        if self._subnetpool:
            # DEBUG ADIT - make sure to test or remove this.
            # this is not the default workflow
            subnet = super(NsxvIpamDriver, self).allocate_subnet(
                subnet_request)
            subnet_request = subnet.get_details()

        # SubnetRequest must be an instance of SpecificSubnet
        if not isinstance(subnet_request, ipam_req.SpecificSubnetRequest):
            raise ipam_exc.InvalidSubnetRequestType(
                subnet_type=type(subnet_request))

        # Add the pool to the NSX backend
        nsx_pool_id = self.allocate_backend_pool(subnet_request)
        # Add the pool to the DB
        nsxv_db.add_nsxv_ipam_subnet_pool(self._context.session,
                                          subnet_request.subnet_id,
                                          nsx_pool_id)
        # return the subnet object
        return NsxvIpamSubnet(subnet_request.subnet_id, nsx_pool_id,
                              self._context, subnet_request.tenant_id)

    def update_subnet(self, subnet_request):
        """Update subnet info the in the IPAM driver.

        The only update subnet information the driver needs to be aware of
        are allocation pools.
        """
        if not self._is_ext_or_provider_net(subnet_request=subnet_request):
            return self.default_implementation_instance.update_subnet(
                subnet_request)

        # use NSX IPAM implementation
        # DEBUG ADIT - Not sure we want to support this
        # backend supports it bu get + put
        # Also for upgrade scenario:
        # if no pool id found in the DB - fallback to old implementation

    def remove_subnet(self, subnet_id):
        """Remove data structures & backend pool for a given subnet."""
        nsx_pool_id = nsxv_db.get_nsxv_ipam_pool_for_subnet(
            self._context.session, subnet_id)
        if not nsx_pool_id:
            # This is either an old pre-upgrade subnet or a regular subnet
            self.default_implementation_instance.remove_subnet(subnet_id)
            return

        # DEBUG ADIT add lock here and other places
        # Delete from backend
        self._vcns.delete_ipam_ip_pool(nsx_pool_id)

        # delete pool from DB
        nsxv_db.del_nsxv_ipam_subnet_pool(self._context.session,
                                          subnet_id, nsx_pool_id)


class NsxvSubnetRequestFactory(ipam_req.SubnetRequestFactory):
    """Builds request using subnet info, including the network id"""

    @classmethod
    def get_request(cls, context, subnet, subnetpool):
        req = super(NsxvSubnetRequestFactory, cls).get_request(
            context, subnet, subnetpool)
        #Just add the network id into the request"""
        req.network_id = subnet['network_id']
        return req


class NsxvIpamSubnet(ipam_base.Subnet):
    """Manage IP addresses for NSX IPAM driver."""

    def __init__(self, subnet_id, nsx_pool_id, ctx, tenant_id):
        self._subnet_id = subnet_id
        self._nsx_pool_id = nsx_pool_id
        self._context = ctx
        self._tenant_id = tenant_id

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    @property
    def _vcns(self):
        return self._core_plugin.nsx_v.vcns

    @classmethod
    def load(cls, neutron_subnet_id, nsx_pool_id, ctx):
        """Load an IPAM subnet from the database given its neutron ID."""
        # DEBUG ADIT not yet
        # ipam_subnet = ipam_db_api.IpamSubnetManager.
        #     load_by_neutron_subnet_id(
        #     ctx.session, neutron_subnet_id)
        # if not ipam_subnet:
        #     LOG.error(_LE("IPAM subnet referenced to "
        #                   "Neutron subnet %s does not exist"),
        #               neutron_subnet_id)
        #     raise n_exc.SubnetNotFound(subnet_id=neutron_subnet_id)
        # pools = []
        # for pool in ipam_subnet.allocation_pools:
        #     pools.append(netaddr.IPRange(pool['first_ip'], pool['last_ip']))

        # neutron_subnet = cls._fetch_subnet(ctx, neutron_subnet_id)

        # DEBUG ADIT what about the tenant id??
        return cls(neutron_subnet_id, nsx_pool_id, ctx, None)

    @classmethod
    def _fetch_subnet(cls, context, id):
        plugin = manager.NeutronManager.get_plugin()
        return plugin._get_subnet(context, id)

    def allocate(self, address_request):
        # NOTE(pbondar): Ipam driver is always called in context of already
        # running transaction, which is started on create_port or upper level.
        # To be able to do rollback/retry actions correctly ipam driver
        # should not create new nested transaction blocks.
        #session = self._context.session
        #all_pool_id = None
        # NOTE(salv-orlando): It would probably better to have a simpler
        # model for address requests and just check whether there is a
        # specific IP address specified in address_request
        if isinstance(address_request, ipam_req.SpecificAddressRequest):
            # This handles both specific and automatic address requests
            # Check availability of requested IP
            ip_address = str(address_request.address)
            # DEBUG ADIT use:
            #POST https://NSX-Manager-IP-Address/api/2.0/services/ipam/pools/
            #     poolId/ipaddresses
            #Request Body:
            # <ipAddressRequest>
            #  <allocationMode>RESERVE</allocationMode>
            #  <ipAddress>192.168.1.5</ipAddress>
            # </ipAddressRequest>
        else:
            # DEBUG ADIT use:
            # use https://nsx-manager-ip-address/api/2.0/services/ipam/pools/
            #     poolId/ipaddresses
            # Request Body:
            # <ipAddressRequest>
            #  <allocationMode>ALLOCATE</allocationMode>
            # </ipAddressRequest>
            # and get the ip from the response
            pass

        return ip_address

    def deallocate(self, address):
        # DEBUG ADIT not yet
        # This is almost a no-op because the Neutron DB IPAM driver does not
        # delete IPAllocation objects, neither rebuilds availability ranges
        # at every deallocation. The only operation it performs is to delete
        # an IPRequest entry.
        session = self._context.session

        count = self.subnet_manager.delete_allocation(
            session, address)
        # count can hardly be greater than 1, but it can be 0...
        if not count:
            raise ipam_exc.IpAddressAllocationNotFound(
                subnet_id=self.subnet_manager.neutron_id,
                ip_address=address)

    def _no_pool_changes(self, session, pools):
        # DEBUG ADIT not yet
        """Check if pool updates in db are required."""
        db_pools = self.subnet_manager.list_pools(session)
        iprange_pools = [netaddr.IPRange(pool.first_ip, pool.last_ip)
                         for pool in db_pools]
        return pools == iprange_pools

    def update_allocation_pools(self, pools, cidr):
        # DEBUG ADIT not yet
        # Pools have already been validated in the subnet request object which
        # was sent to the subnet pool driver. Further validation should not be
        # required.

        # DEBUG ADIT - not sure we want/need to implement this.
        # can through unimplemented maybe
        # session = self._context.session
        # if self._no_pool_changes(session, pools):
        #     return
        # self.subnet_manager.delete_allocation_pools(session)
        # self.create_allocation_pools(self.subnet_manager,
        #                              session, pools, cidr)
        # self._pools = pools
        pass

    def get_details(self):
        """Return subnet data as a SpecificSubnetRequest"""
        # get the pool from the backend
        pool_details = self._vcns.get_ipam_ip_pool(self._nsx_pool_id)[1]
        gateway_ip = pool_details['gateway']
        # rebuild the cidr from the range & prefix
        # DEBUG ADIT make this code safe! + what if we have multiple pools?
        cidr = '%s/%s' % (pool_details['ipRanges'][0]['startAddress'],
                          pool_details['prefixLength'])
        pools = []
        for ip_range in pool_details['ipRanges']:
            pools.append(netaddr.IPRange(ip_range['startAddress'],
                                         ip_range['endAddress']))

        return ipam_req.SpecificSubnetRequest(
            self._tenant_id, self._subnet_id,
            cidr, gateway_ip=gateway_ip, allocation_pools=pools)
