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

from neutron.ipam import requests as ipam_req
from neutron_lib.plugins import directory


class NsxIpamBase(object):
    @classmethod
    def get_core_plugin(cls):
        return directory.get_plugin()

    @classmethod
    def _fetch_subnet(cls, context, id):
        p = cls.get_core_plugin()
        return p._get_subnet(context, id)

    @classmethod
    def _fetch_network(cls, context, id):
        p = cls.get_core_plugin()
        return p.get_network(context, id)


class NsxSubnetRequestFactory(ipam_req.SubnetRequestFactory, NsxIpamBase):
    """Builds request using subnet info, including the network id"""

    @classmethod
    def get_request(cls, context, subnet, subnetpool):
        req = super(NsxSubnetRequestFactory, cls).get_request(
            context, subnet, subnetpool)
        # Add the network id into the request
        if 'network_id' in subnet:
            req.network_id = subnet['network_id']

        return req
