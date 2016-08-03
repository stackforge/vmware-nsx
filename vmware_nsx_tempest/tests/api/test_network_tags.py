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

from vmware_nsx_tempest._i18n import _
from vmware_nsx_tempest.services import tags_client

CONF = config.CONF
MAX_TAG_LEN = 60
MITAKA_RELEASE_NUMBER = 2016.1
OS_RELEASE_NUMBER = 2016.1
# OS_RELEASE_NUMBER = CONF.platform.os_release_number


class BaseTagsTest(base.BaseNetworkTest):
    """Base class for Tags Test."""

    @classmethod
    def skip_checks(cls):
        """skip tests if tags is not enabled."""
        super(BaseTagsTest, cls).skip_checks()
        if OS_RELEASE_NUMBER < MITAKA_RELEASE_NUMBER:
            msg = "tags is availabe begins from Mitaka release."
            raise cls.skipException(msg)

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

    @classmethod
    def list_networks(cls, **filters):
        nets = cls.networks_client.list_networks(**filters)
        return nets.get('networks')

    @classmethod
    def tag_add(cls, network_id, tag, resource_type='network'):
        cls.tags_client.add_tag(resource_type=resource_type,
                                resource_id=network_id,
                                tag=tag)
        network = cls.networks_client.show_network(network_id)['network']
        return network

    @classmethod
    def tag_remove(cls, network_id, tag, resource_type='network'):
        cls.tags_client.remove_tag(resource_type=resource_type,
                                   resource_id=network_id,
                                   tag=tag)
        network = cls.networks_client.show_network(network_id)['network']
        return network

    @classmethod
    def tag_replace(cls, network_id, tags, resource_type='network'):
        req_body = dict(resource_type=resource_type, resource_id=network_id)
        if type(tags) in (list, tuple, set):
            req_body['tags'] = tags
        else:
            req_body['tags'] = [tags]
        cls.tags_client.replace_tag(**req_body)
        network = cls.networks_client.show_network(network_id)['network']
        return network

    def network_add_tag(self, network_id, tag):
        network = self.tag_add(network_id, tag)
        self.assertIn(tag, network['tags'])
        return network

    def network_remove_tag(self, network_id, tag):
        network = self.tag_remove(network_id, tag)
        self.assertNotIn(tag, network['tags'])
        return network

    def network_replace_tags(self, network_id, tags=None):
        if tags is None:
            tags=['a', 'ab', 'abc']
        network = self.tag_replace(network_id, tags)
        self.assertEqual(len(tags), len(network['tags']))
        for tag in tags:
            self.assertIn(tag, network['tags'])
        return network


class NetworkTagAddTest(BaseTagsTest):
    """neutron tag-add test."""

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(NetworkTagAddTest, cls).resource_setup()
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


class NetworkTagRemoveTest(BaseTagsTest):
    """neutron tag-remove test."""

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(NetworkTagRemoveTest, cls).resource_setup()
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


class NetworkTagReplaceTest(BaseTagsTest):
    """neutron tag-replace test."""

    @classmethod
    def resource_setup(cls):
        """setup resources."""
        super(NetworkTagReplaceTest, cls).resource_setup()
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
    """searching/filtering using query tags.

    Following query parameters are supported:

        tags
        tags-any
        not-tags
        not-tags-any
    """

    @classmethod
    def resource_setup(cls):
        """setup default values for testing.."""
        super(NetworkTagFilterTest, cls).resource_setup()
        # tag in a_b_c only tag to one network
        cls.a_b_c = ['a', 'ab', 'abc']
        cls.not_tagged_tags = ['talking-head', 'spinning-tail']
        cls._tags = (['gold', 'east', 'production'],
                     ['silver', 'west', 'testing'],
                     ['brown', 'north', 'development', 'abc'],
                     ['brown', 'south', 'testing', 'ab'],
                     ['gold', 'west', 'production', 'a'])
        cls.QQ = {'router:external': False}
        cls.GG = {}
        for ix in range(0, len(cls._tags)):
            net = cls.create_network()
            tags=cls._tags[ix]
            net = cls.tag_replace(net['id'], tags=tags)
            if not (set(net['tags'])  == set(cls._tags[ix])):
                raise Exception(
                    _("tags[%s] are not replaced successfully.") % tags)
            net_id = net['id']
            cls.GG[net_id] = set(net['tags'])

    def setUp(self):
        """create networks with predefined tags (self._tags)."""
        super(NetworkTagFilterTest, self).setUp()

    def tearDown(self):
        super(NetworkTagFilterTest, self).tearDown()

    def check_matched_search_list(self, matched_nets, m_net_list):
        self.assertEqual(len(matched_nets), len(m_net_list))
        for net in matched_nets:
            self.assertIn(net['id'], m_net_list)

    @test.idempotent_id('9646af99-7e04-4724-ac54-4a938de764f1')
    def test_tags_only_one_network(self):
        """each tag in self.a_b_c only tag one network."""
        for tag in self.a_b_c:
            filters = {'tags': tag}
            filters.update(self.QQ)
            nets = self.list_networks(**filters)
            self.assertEqual(len(nets), 1)

    @test.idempotent_id('a0d8c21b-1ec0-4c6d-b5d8-72baebabde26')
    def test_tags_not_tagged(self):
        """search with tags for tags not being tagged."""
        for tag in self.not_tagged_tags:
            filters = {'tags': tag}
            filters.update(self.QQ)
            nets = self.list_networks(**filters)
            self.assertEqual(len(nets), 0)

    @test.idempotent_id('1049eac1-028b-4664-aeb7-c7656240622d')
    def test_tags_any_not_tagged(self):
        """search with tags-any for tags not being tagged."""
        for tag in self.not_tagged_tags:
            filters = {'tags-any': tag}
            filters.update(self.QQ)
            nets = self.list_networks(**filters)
            self.assertEqual(len(nets), 0)

    @test.idempotent_id('a9b42503-5dd1-490d-b0c6-673951cc86a1')
    def test_tags(self):
        """find networks of tags (and operation)"""
        tags = ['gold', 'production']
        m_net_list = x_and_y(tags, self.GG)
        filters = {'tags': tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.assertEqual(len(nets), len(m_net_list))
        for net in nets:
            self.assertIn(net['id'], m_net_list)

    @test.idempotent_id('c38e788d-749e-401a-8bbb-26e36a7b573f')
    def test_tags_any(self):
        """find networks of tags-any (or operation)"""
        tags = ['gold', 'production']
        m_net_list = x_or_y(tags, self.GG)
        filters = {'tags-any': tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.assertEqual(len(nets), len(m_net_list))
        for net in nets:
            self.assertIn(net['id'], m_net_list)

    @test.idempotent_id('e7bb1cea-3271-418c-bfe2-038fff6187e6')
    def test_not_tags(self):
        """find networks of not-tags (and operation)"""
        tags = ['gold', 'production']
        m_net_list = not_x_and_y(tags, self.GG)
        filters = {'not-tags': tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list)

    @test.idempotent_id('c36a1d00-c131-4297-86c1-a3fc06c61629')
    def test_not_tags_any(self):
        """find networks of not-tags-any (or operation)"""
        tags = ['gold', 'production']
        m_net_list = not_x_or_y(tags, self.GG)
        filters = {'not-tags-any': tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list)

    @test.idempotent_id('2067a8fc-2d7b-4085-a6c2-7e454f6f26f3')
    def test_tags_not_tags_any(self):
        """tags=<tags> and not-tags-any=<not-tags-any>"""
        tags = ['gold', 'production']
        not_tags = ['west']
        m_net_list = not_x_or_y(not_tags, self.GG,
                                x_and_y(tags, self.GG))
        filters = {'tags': tags, 'not-tags-any': not_tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list)

    @test.idempotent_id('7b17dfa8-f7ac-47c2-b814-35c5ed1c325b')
    def test_tags_not_tags(self):
        """tags=<tags> and not-tags=<not-tags>"""
        tags = ['gold', 'production']
        not_tags = ['west', 'south']
        m_net_list = not_x_and_y(not_tags, self.GG,
                                 x_and_y(tags, self.GG))
        filters = {'tags': tags, 'not-tags': not_tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.check_matched_search_list(nets, m_net_list)

    @test.idempotent_id('f723f717-660b-4d8e-ae9f-014f0a3f812d')
    def test_tags_not_tags_itself(self):
        """"tags and not-tags itself is always an empty set."""
        tags = ['gold', 'production']
        m_net_list = not_x_and_y(tags, self.GG,
                                 x_and_y(tags, self.GG))
        filters = {'tags': tags, 'not-tags': tags}
        filters.update(self.QQ)
        nets = self.list_networks(**filters)
        self.assertEqual(0, len(nets))


# search/filter methods
# K_sets: Dict of sets
def x_and_y(x_and_y, K_sets, on_keys=None):
    """tags=x_and_y"""
    s_xy = set(x_and_y)
    xy_s = [k for k, S in K_sets.items()
            if (on_keys is None or k in on_keys) and s_xy.issubset(S)]
    return xy_s


def not_x_and_y(x_and_y, K_sets, on_keys=None):
    """not-tags=x_and_y"""
    s_xy = set(x_and_y)
    xy_s = [k for k, S in K_sets.items()
            if (on_keys is None or k in on_keys) and not s_xy.issubset(S)]
    return xy_s


def x_or_y(x_or_y, K_sets, on_keys=None):
    """tags-any=x_or_y"""
    s_xy = set(x_or_y)
    xy_s = [k for k, S in K_sets.items()
            if (on_keys is None or k in on_keys) and len(S & s_xy) > 0]
    return xy_s


def not_x_or_y(x_or_y, K_sets, on_keys=None):
    """not tags-any=x_or_y"""
    s_xy = set(x_or_y)
    xy_s = [k for k, S in K_sets.items()
            if (on_keys is None or k in on_keys) and len(S & s_xy) == 0]
    return xy_s
