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

import mock
import re

from openstackclient.tests.network.v2 import test_subnet
from openstackclient.tests import utils as tests_utils

from vmware_nsx.osc.v2 import subnet


def _get_id(client, id_or_name, resource):
    return id_or_name


class TestCreateSubnet(test_subnet.TestCreateSubnet):

    def setUp(self):
        super(TestCreateSubnet, self).setUp()
        # Get the command object to test
        self.cmd = subnet.NsxCreateSubnet(self.app, self.namespace)

    def _test_create_with_arg_and_val(self, arg_name, arg_val, is_valid=True):
        self.network.create_subnet = mock.Mock(return_value=self._subnet)
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            "--subnet-range", self._subnet.cidr,
            "--network", self._subnet.network_id,
            conv_name, str(arg_val),
            self._subnet.name
        ]
        verifylist = [
            ('name', self._subnet.name),
            ('subnet_range', self._subnet.cidr),
            ('network', self._subnet.network_id),
            ('ip_version', self._subnet.ip_version),
            ('gateway', 'auto'),
            (arg_name, arg_val),
        ]
        if not is_valid:
            self.assertRaises(tests_utils.ParserException, self.check_parser,
                              self.cmd, arglist, verifylist)
            return

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        columns, data = self.cmd.take_action(parsed_args)
        self.network.create_subnet.assert_called_once_with(**{
            'cidr': mock.ANY,
            'ip_version': mock.ANY,
            'network_id': mock.ANY,
            'name': self._subnet.name,
            arg_name: arg_val,
        })

        self.assertEqual(self.columns, columns)
        self.assertEqual(self.data, data)

    def _test_create_with_mtu(self, mtu, is_valid=True):
        self._test_create_with_arg_and_val('dhcp_mtu', mtu, is_valid)

    def test_create_with_mtu(self):
        # TODO(asarfaty) need to fake the v plugin for this flag
        # check a valid value
        self._test_create_with_mtu(1500)

        # check illegal value
        self._test_create_with_mtu('illegal', is_valid=False)

    def _test_create_with_search_domain(self, mtu, is_valid=True):
        self._test_create_with_arg_and_val('dns_search_domain', mtu, is_valid)

    def test_create_with_search_domain(self):
        # TODO(asarfaty) need to fake the v plugin for this flag
        # check a valid value
        self._test_create_with_search_domain('www.aaa.com')

        # Cannot check illegal value - validation is on the server side
