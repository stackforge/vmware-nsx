# Copyright 2016 VMware, Inc.
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

from tempest.api.network import base
from tempest import config
from tempest.lib import exceptions
from tempest import test

from vmware_nsx_tempest.services import tags_client

CONF = config.CONF
MITAKA_RELEASE_NUMBER = 2016.1
MAX_TAG_LEN = 60


class BaseTagsTest(base.BaseNetworkTest):
    """Base class for Tags Test."""

    @classmethod
    def skip_checks(cls):
        """skip tests if tags is not enabled."""
        super(BaseTagsTest, cls).skip_checks()
        """
        if CONF.platform.os_release_number < MITAKA_RELEASE_NUMBER:
            msg = "tags is availabe begins from Mitaka release."
            raise cls.skipException(msg)
        """

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(BaseTagsTest, cls).resource_setup()
        cls.primary_mgr = cls.get_client_manager()
        cls.tags_client = tags_client.get_client(cls.primary_mgr)

    @classmethod
    def resource_cleanup(cls):
        """cleanup resources before handing over to framework."""
        super(BaseTagsTest, cls).resource_cleanup()

    def network_add_tag(self, network_id, tag):
        self.tags_client.add_tag(resource_type='network',
                                 resource_id=network_id,
                                 tag=tag)
        network = self.networks_client.show_network(network_id)['network']
        self.assertIn(tag, network['tags'])
        return network

    def network_remove_tag(self, network_id, tag):
        self.tags_client.remove_tag(resource_type='network',
                                    resource_id=network_id,
                                    tag=tag)
        network = self.networks_client.show_network(network_id)['network']
        self.assertNotIn(tag, network['tags'])
        return network

    def network_replace_tags(self, network_id, tags=['a', 'ab', 'abc']):
        req_body = dict(resource_type='network',
                        resource_id=network_id, tags=tags)
        self.tags_client.replace_tag(**req_body)
        network = self.networks_client.show_network(network_id)['network']
        self.assertEqual(len(tags), len(network['tags']))
        for tag in tags:
            self.assertIn(tag, network['tags'])
        return network

class NetworkAddTagTest(BaseTagsTest):
    """neutron tag-add test."""

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(NetworkAddTagTest, cls).resource_setup()
        cls.net = cls.create_network()

    @test.idempotent_id('0e37a579-aff3-47ba-9f1f-3ac4482fce16')
    def test_add_tags(self):
        """neutron tag-add operations."""
        tags = ['a', 'gold', 'T' * MAX_TAG_LEN]
        network_id = self.net.get('id')
        # check we can add tag one at time
        for tag in tags:
            network = self.network_add_tag(network_id, tag)
        # and all tags exist, not being overwritten.
        for tag in tags:
            self.assertIn(tag, network['tags'])

    @test.idempotent_id('eb52eac3-5e79-4183-803a-a3d97ceb171d')
    @test.attr(type='negative')
    def test_add_tag_one_too_long(self):
        tag_too_long = 'a' * (MAX_TAG_LEN + 1)
        network_id = self.net.get('id')
        req_body = dict(resource_type='network',
                        resource_id=network_id, tag=tag_too_long)
        self.assertRaises(exceptions.BadRequest,
                          self.tags_client.add_tag,
                          **req_body)


class NetworkRevmoeTagTest(BaseTagsTest):
    """neutron tag-remove test."""

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(NetworkRevmoeTagTest, cls).resource_setup()
        cls.net = cls.create_network()

    @test.idempotent_id('178fbd96-900f-4c3d-8cd1-5525f4cf2b81')
    def test_remove_tags(self):
        """neutron tag-remove operations."""
        network_id = self.net.get('id')
        tag = 'spinning-tail'
        self.network_add_tag(network_id, tag)
        self.network_remove_tag(network_id, tag)

    @test.idempotent_id('1fe5a8b2-ff5d-4250-b930-21b1a3b48055')
    @test.attr(type='negative')
    def test_remove_all_tags(self):
        network_id = self.net.get('id')
        self.network_replace_tags(network_id)
        req_body = dict(resource_type='network',
                        resource_id=network_id, all=True)
        self.tags_client.remove_tag(**req_body)
        network = self.networks_client.show_network(network_id)['network']
        self.assertEqual(len(network['tags']), 0)

    @test.idempotent_id('591337b0-a2e6-4d72-984c-e5b6a6ec12d2')
    @test.attr(type='negative')
    def test_remove_not_exist_tag(self):
        """neutron tag-remove operations."""
        network_id = self.net.get('id')
        req_body = dict(resource_type='network',
                        resource_id=network_id, tag='talking-head')
        self.assertRaises(exceptions.NotFound,
                          self.tags_client.remove_tag,
                          **req_body)


class NetworkReplaceTagTest(BaseTagsTest):
    """neutron tag-replace test."""

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(NetworkReplaceTagTest, cls).resource_setup()
        cls.net = cls.create_network()

    @test.idempotent_id('7d4fb288-2f2d-4f47-84af-be3175b057b5')
    def test_replace_tags(self):
        """neutron tag-replace operations."""
        network_id = self.net.get('id')
        self.network_replace_tags(network_id)
        tags = ['east', 'south', 'west', 'north']
        req_body = dict(resource_type='network',
                        resource_id=network_id, tags=tags)
        self.tags_client.replace_tag(**req_body)
        network = self.networks_client.show_network(network_id)['network']
        self.assertEqual(len(network['tags']), len(tags))
        for tag in tags:
            self.assertIn(tag, network['tags'])
        new_tags = ['BIG', 'small']
        req_body['tags'] = new_tags
        self.tags_client.replace_tag(**req_body)
        network = self.networks_client.show_network(network_id)['network']
        self.assertEqual(len(network['tags']), len(new_tags))
        for tag in new_tags:
            self.assertIn(tag, network['tags'])
        # EQ to remove all
        req_body['tags'] = []
        self.tags_client.replace_tag(**req_body)
        network = self.networks_client.show_network(network_id)['network']
        self.assertEqual(len(network['tags']), 0)


class NetworkTagFilterTest(BaseTagsTest):
    """searching/filtering using tags.

    """

    @classmethod
    def resource_setup(cls):
        """setup default values for testing.."""
        super(TagFilterNetworkTest, cls).resource_setup()
        cls.flavors = ['gold', 'silver', 'brown']
        cls.locations = ['east', 'south', 'west', 'north']
        cls.owners = ['development', 'testing', 'production']
        # tag in a_b_c only tag to one network
        cls.a_b_c = ['a', 'ab', 'abc']
        cls.not_tagged_tags = ['talking-head', 'spinning-tail']
        cls._tags = (['gold', 'east', 'production'],
                     ['silver', 'west', 'testing'],
                     ['brown', 'north', 'development', 'abc'],
                     ['brown', 'south', 'testing', 'ab'],
                     ['gold', 'west', 'production', 'a'])

    def setUp(self):
        """create networks with predefined tags (self._tags)."""
        super(NetworkTagFilterTest, self).setUp()
        self._nets = []
        self.G = {}
        for ix in range(0, len(self._tags)):
            net = self.create_network()
            net = self.network_replace_tags(net['id'], self._tags[ix])
            self._nets.append(net)
            for t in self._tags[ix]:
                if t in self.G:
                    self.G[t].append(net['id'])
                else:
                    self.G[t] = [net['id']]

    def tearDown(self):
        super(NetworkTagFilterTest, self).tearDown()

    @test.idempotent_id('9646af99-7e04-4724-ac54-4a938de764f1')
    def test_tag_to_only_one_network(self):
        """each tag in self.a_b_c only tag one network."""
        for tag in self.a_b_c:
            nets = self.networks_client.list_networks(tags=tag)['networks']
            self.assertEqual(len(nets), 1)

    @test.idempotent_id('a0d8c21b-1ec0-4c6d-b5d8-72baebabde26')
    def test_tag_not_tagged(self):
        """no networks being tagged by self.not_tagged_tag."""
        for tag in self.not_tagged_tags:
            nets = self.networks_client.list_networks(tags=tag)['networks']
            self.assertEqual(len(nets), 0)

    @test.idempotent_id('a9b42503-5dd1-490d-b0c6-673951cc86a1')
    def test_tags_of_specific_tags(self):
        """find networks of specified tags (and operations)"""
        tags = ['gold', 'production']
        nets = self.networks_client.list_networks(tags=tag)['networks']
        self.assertEqual(len(nets), 2)
