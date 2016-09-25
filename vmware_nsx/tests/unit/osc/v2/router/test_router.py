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

import re

from openstackclient.tests.network.v2 import test_router
from openstackclient.tests import utils as tests_utils

from vmware_nsx.extensions import routersize
from vmware_nsx.extensions import routertype
from vmware_nsx.osc.v2 import router


def _get_id(client, id_or_name, resource):
    return id_or_name


class TestCreateRouter(test_router.TestCreateRouter):

    def setUp(self):
        super(TestCreateRouter, self).setUp()
        # Get the command object to test
        self.cmd = router.NsxCreateRouter(self.app, self.namespace)

    def _test_create_with_arg_and_val(self, arg_name, arg_val, is_valid=True):
        self.network.create_router.reset_mock()
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            self.new_router.name,
            conv_name, arg_val
        ]
        verifylist = [
            ('name', self.new_router.name),
            (arg_name, arg_val),
            ('enable', True),
            ('distributed', False),
        ]
        if not is_valid:
            self.assertRaises(tests_utils.ParserException, self.check_parser,
                              self.cmd, arglist, verifylist)
            return

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        columns, data = (self.cmd.take_action(parsed_args))
        self.network.create_router.assert_called_once_with(**{
            'admin_state_up': True,
            'name': self.new_router.name,
            arg_name: arg_val,
        })

        self.assertEqual(self.columns, columns)
        self.assertEqual(self.data, data)

    def _test_create_with_size(self, size, is_valid=True):
        self._test_create_with_arg_and_val('router_size', size, is_valid)

    def test_create_with_sizes(self):
        # TODO(asarfaty) need to fake the v plugin for the router-size flag
        # check all router types
        for rtr_size in routersize.VALID_EDGE_SIZES:
            self._test_create_with_size(rtr_size)

        # check illegal size
        self._test_create_with_size('illegal', is_valid=False)

    def _test_create_with_type(self, rtr_type, is_valid=True):
        self._test_create_with_arg_and_val('router_type', rtr_type, is_valid)

    def test_create_with_types(self):
        # TODO(asarfaty) need to fake the v plugin for the router-type flag
        # check all router types
        for rtr_type in routertype.VALID_TYPES:
            self._test_create_with_type(rtr_type)

        # check illegal type
        self._test_create_with_type('illegal', is_valid=False)


class TestSetRouter(test_router.TestSetRouter):

    def setUp(self):
        super(TestSetRouter, self).setUp()
        # Get the command object to test
        self.cmd = router.NsxSetRouter(self.app, self.namespace)

    def _test_set_with_arg_and_val(self, arg_name, arg_val, is_valid=True):
        self.network.update_router.reset_mock()
        # add '--' to the arg name and change '_' to '-'
        conv_name = '--' + re.sub('_', '-', arg_name)
        arglist = [
            self._router.name,
            conv_name, arg_val
        ]
        verifylist = [
            ('router', self._router.name),
            (arg_name, arg_val)
        ]
        if not is_valid:
            self.assertRaises(tests_utils.ParserException, self.check_parser,
                              self.cmd, arglist, verifylist)
            return

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        result = self.cmd.take_action(parsed_args)

        attrs = {arg_name: arg_val}
        self.network.update_router.assert_called_once_with(
            self._router, **attrs)
        self.assertIsNone(result)

    def _test_set_with_size(self, size, is_valid=True):
        self._test_set_with_arg_and_val('router_size', size, is_valid)

    def test_set_with_sizes(self):
        # TODO(asarfaty) need to fake the v plugin for the router-size flag
        # check all router types
        for rtr_size in routersize.VALID_EDGE_SIZES:
            self._test_set_with_size(rtr_size)

        # check illegal size
        self._test_set_with_size('illegal', is_valid=False)

    def _test_set_with_type(self, rtr_type, is_valid=True):
        self._test_set_with_arg_and_val('router_type', rtr_type, is_valid)

    def test_set_with_types(self):
        # TODO(asarfaty) need to fake the v plugin for the router-type flag
        # check all router types
        for rtr_type in routertype.VALID_TYPES:
            self._test_set_with_type(rtr_type)

        # check illegal type
        self._test_set_with_type('illegal', is_valid=False)
