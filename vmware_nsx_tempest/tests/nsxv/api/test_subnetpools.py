# Copyright 2015 GlobalLogic.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest import test

from vmware_nsx_tempest._i18n import _LI

LOG = logging.getLogger(__name__)

CONF = config.CONF


class SubnetPoolsTestJSON(base.BaseNetworkTest):
    """Tests the following operations in the subnetpools API:

        1. Create, update, delete list and show subnet pool.
        2. Check shared subnetpool created by admin only.
        3. Check no-admin tenant can't delete shared pool created by admin.
        4. Create subentpool with quota limit for subnet and check subnet
           exhaust.
        5. Create subnets from subnetpool till the time no more ip left in
           subnetpool.

    v2.0 of the Neutron API is assumed. It is assumed that subnet_allocation
    options mentioned in the [network-feature-enabled] section and
    default_network option mentioned in the [network] section of
    etc/tempest.conf:

    """

    @classmethod
    def skip_checks(cls):
        super(SubnetPoolsTestJSON, cls).skip_checks()
        if not test.is_extension_enabled('subnet_allocation', 'network'):
            msg = "subnet_allocation extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(SubnetPoolsTestJSON, cls).setup_clients()
        cls.cmgr_pri = cls.get_client_manager('primary')
        cls.cmgr_alt = cls.get_client_manager('alt')
        cls.cmgr_adm = cls.get_client_manager('admin')

    def clean_subnet(self, subnet_client, subnet_id):
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnet_client.delete_subnet,
                        subnet_id)

    def test_subnetpools_crud_operations(self):
        subnetpool_name = data_utils.rand_name('subnetpools')
        # create subnet pool
        prefix = CONF.network.default_network
        subnetpool_client = self.cmgr_adm.subnetpools_client
        body = subnetpool_client.create_subnetpool(name=subnetpool_name,
                                                   prefixes=prefix)
        subnetpool_id = body["subnetpool"]["id"]
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnetpool_client.delete_subnetpool,
                        subnetpool_id)
        self.assertEqual(subnetpool_name, body["subnetpool"]["name"])
        # get detail about subnet pool
        body = subnetpool_client.show_subnetpool(subnetpool_id)
        self.assertEqual(subnetpool_name, body["subnetpool"]["name"])
        # update the subnet pool
        subnetpool_name = data_utils.rand_name('subnetpools_update')
        body = subnetpool_client.update_subnetpool(subnetpool_id,
                                                   name=subnetpool_name)
        self.assertEqual(subnetpool_name, body["subnetpool"]["name"])
        # delete subnet pool
        body = subnetpool_client.delete_subnetpool(subnetpool_id)
        self.assertRaises(lib_exc.NotFound,
                          subnetpool_client.show_subnetpool,
                          subnetpool_id)

    def test_subnetpools_shared_operations(self):
        subnetpool_name = data_utils.rand_name('subnetpools')
        # create subnet pool
        prefix = CONF.network.default_network
        subnetpool_client = self.cmgr_adm.subnetpools_client
        body = subnetpool_client.create_subnetpool(name=subnetpool_name,
                                                   prefixes=prefix,
                                                   shared='true')
        subnetpool_id = body["subnetpool"]["id"]
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnetpool_client.delete_subnetpool,
                        subnetpool_id)
        self.assertEqual(subnetpool_name, body["subnetpool"]["name"])
        # get detail about subnet pool
        subnetpool_alt_client = self.cmgr_alt.subnetpools_client
        body = subnetpool_alt_client.show_subnetpool(subnetpool_id)
        self.assertIn(subnetpool_id, body['subnetpool']['id'])
        body = subnetpool_alt_client.create_subnetpool(
            name=subnetpool_name,
            prefixes=prefix,
            shared='False')
        subnetpool_alt_id = body["subnetpool"]["id"]
        subnetpool_pri_client = self.cmgr_pri.subnetpools_client
        self.assertRaises(lib_exc.NotFound,
                          subnetpool_pri_client.show_subnetpool,
                          subnetpool_alt_id)

    def test_shared_subnetpool_created_by_admin_only(self):
        subnetpool_name = data_utils.rand_name('subnetpools')
        # create subnet pool
        prefix = CONF.network.default_network
        subnetpool_client = self.cmgr_adm.subnetpools_client
        body = subnetpool_client.create_subnetpool(name=subnetpool_name,
                                                   prefixes=prefix,
                                                   shared='true')
        subnetpool_id = body["subnetpool"]["id"]
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnetpool_client.delete_subnetpool,
                        subnetpool_id)
        self.assertEqual(subnetpool_name, body["subnetpool"]["name"])
        # get detail about subnet pool
        subnetpool_alt_client = self.cmgr_alt.subnetpools_client
        # PolicyNotAuthorized disallowed by policy
        self.assertRaises(lib_exc.Forbidden,
                          subnetpool_alt_client.create_subnetpool,
                          name=subnetpool_name, prefixes=prefix,
                          shared='true')

    def test_shared_subnetpool_not_deleted_by_non_admin(self):
        subnetpool_name = data_utils.rand_name('subnetpools')
        # create subnet pool
        prefix = CONF.network.default_network
        subnetpool_client = self.cmgr_adm.subnetpools_client
        body = subnetpool_client.create_subnetpool(name=subnetpool_name,
                                                   prefixes=prefix,
                                                   shared='true')
        subnetpool_id = body["subnetpool"]["id"]
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnetpool_client.delete_subnetpool,
                        subnetpool_id)
        self.assertEqual(subnetpool_name, body["subnetpool"]["name"])
        # get detail about subnet pool
        subnetpool_alt_client = self.cmgr_alt.subnetpools_client
        # PolicyNotAuthorized disallowed by policy
        self.assertRaises(lib_exc.NotFound,
                          subnetpool_alt_client.delete_subnetpool,
                          subnetpool_id)

    def test_subnetpools_with_quota_limit_subnets(self):
        subnetpool_name = data_utils.rand_name('subnetpools')
        # create subnet pool
        prefix = CONF.network.default_network
        subnetpool_client = self.cmgr_adm.subnetpools_client
        body = subnetpool_client.create_subnetpool(name=subnetpool_name,
                                                   prefixes=prefix,
                                                   shared='true',
                                                   default_quota=70)
        subnetpool_id = body["subnetpool"]["id"]
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnetpool_client.delete_subnetpool,
                        subnetpool_id)
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "ip_version": 4, "subnetpool_id": subnetpool_id,
                "prefixlen": 28}
        subnet_client = self.cmgr_adm.subnets_client
        subnet = subnet_client.create_subnet(**body)
        self.clean_subnet(subnet_client, subnet['subnet']['id'])
        body = {"network_id": network['network']['id'],
                "ip_version": 4, "subnetpool_id": subnetpool_id,
                "prefixlen": 26, "enable_dhcp": 'false'}
        # "Per-tenant subnet pool prefix quota exceeded"
        self.assertRaises(lib_exc.Conflict,
                          subnet_client.create_subnet, **body)

    def test_subnetpools_with_overlapping_subnets(self):
        subnetpool_name = data_utils.rand_name('subnetpools')
        # create subnet pool
        prefix = CONF.network.default_network
        subnetpool_client = self.cmgr_adm.subnetpools_client
        body = subnetpool_client.create_subnetpool(name=subnetpool_name,
                                                   prefixes=prefix)
        subnetpool_id = body["subnetpool"]["id"]
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnetpool_client.delete_subnetpool,
                        subnetpool_id)
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "ip_version": 4, "subnetpool_id": subnetpool_id,
                "prefixlen": 28}
        subnet_client = self.cmgr_adm.subnets_client
        subnet = subnet_client.create_subnet(**body)
        self.clean_subnet(subnet_client, subnet['subnet']['id'])
        body = {"network_id": network['network']['id'],
                "ip_version": 4, "subnetpool_id": subnetpool_id,
                "prefixlen": 28, "enable_dhcp": 'false'}
        subnet = subnet_client.create_subnet(**body)
        self.clean_subnet(subnet_client, subnet['subnet']['id'])
        body = {"network_id": network['network']['id'],
                "admin_state_up": 'true'}
        port_client = self.cmgr_adm.ports_client
        port_id = port_client.create_port(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        port_client.delete_port,
                        port_id['port']['id'])

    def test_subnetpools_with_overlapping_multi_subnets(self):
        subnetpool_name = data_utils.rand_name('subnetpools')
        # create subnet pool
        prefix = CONF.network.default_network
        subnetpool_client = self.cmgr_adm.subnetpools_client
        prefixlen = 26
        body = subnetpool_client.create_subnetpool(name=subnetpool_name,
                                                   prefixes=prefix)
        subnetpool_id = body["subnetpool"]["id"]
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        subnetpool_client.delete_subnetpool,
                        subnetpool_id)
        # Create subnet1 , subnet2
        net_client = self.cmgr_adm.networks_client
        body = {'name': 'provider-network'}
        network = net_client.create_network(**body)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        net_client.delete_network,
                        network['network']['id'])
        body = {"network_id": network['network']['id'],
                "ip_version": 4, "subnetpool_id": subnetpool_id,
                "prefixlen": prefixlen}
        subnet_client = self.cmgr_adm.subnets_client
        subnet = subnet_client.create_subnet(**body)
        self.clean_subnet(subnet_client, subnet['subnet']['id'])
        body = {"network_id": network['network']['id'],
                "ip_version": 4, "subnetpool_id": subnetpool_id,
                "prefixlen": prefixlen, "enable_dhcp": 'false'}
        actual_netmask = int(prefix[0].split('/')[1])
        no_of_ips = 2**(32-actual_netmask)
        no_of_ips_per_prefix = 2**(32 - prefixlen)
        no_of_subnets = no_of_ips/no_of_ips_per_prefix
        for subnet_num in range(1, no_of_subnets+1):
            try:
                subnet = subnet_client.create_subnet(**body)
                self.clean_subnet(subnet_client, subnet['subnet']['id'])
            except lib_exc.ServerFault:
                pass
                LOG.info(_LI("Failed to allocate subnet: Insufficient "
                             "prefix space to allocate subnet size"))
