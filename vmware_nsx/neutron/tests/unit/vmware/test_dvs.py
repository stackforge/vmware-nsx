# Copyright (c) 2014 VMware.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo.config import cfg

from neutron.common import exceptions as exp
from neutron.tests import base
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.dvs import dvs
from vmware_nsx.neutron.plugins.vmware.dvs import dvs_utils


class fake_session(object):
    def __init__(self, *ret):
        self._vim = mock.Mock()

    def invoke_api(self, *args, **kwargs):
        pass

    def wait_for_task(self, task):
        pass

    def vim(self):
        return self._vim


class DvsTestCase(base.BaseTestCase):

    @mock.patch.object(dvs_utils, 'dvs_create_session',
                       return_value=fake_session())
    @mock.patch.object(dvs.DvsManager, '_get_dvs_moref',
                       return_value='dvs-moref')
    def setUp(self, mock_moref, mock_session):
        super(DvsTestCase, self).setUp()
        cfg.CONF.set_override('dvs_name', 'fake_dvs', group='dvs')
        self._dvs = dvs.DvsManager()
        self.assertEqual('dvs-moref', self._dvs._dvs_moref)
        mock_moref.assert_called_once_with(mock_session.return_value,
                                           'fake_dvs')

    @mock.patch.object(dvs_utils, 'dvs_create_session',
                       return_value=fake_session())
    def test_dvs_not_found(self, mock_session):
        self.assertRaises(nsx_exc.DvsNotFound,
                          dvs.DvsManager)

    @mock.patch.object(dvs.DvsManager, '_get_port_group_spec',
                       return_value='fake-spec')
    def test_add_port_group(self, fake_get_spec):
        self._dvs.add_port_group('fake-uuid', 7)
        fake_get_spec.assert_called_once_with('fake-uuid', 7)

    @mock.patch.object(dvs.DvsManager, '_get_port_group_spec',
                       return_value='fake-spec')
    def test_add_port_group_with_exception(self, fake_get_spec):
        with (
            mock.patch.object(self._dvs._session, 'wait_for_task',
                              side_effect=exp.NeutronException())
        ):
            self.assertRaises(exp.NeutronException,
                              self._dvs.add_port_group,
                              'fake-uuid', 7)
            fake_get_spec.assert_called_once_with('fake-uuid', 7)

    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref',
                       return_value='fake-moref')
    def test_delete_port_group(self, fake_get_moref):
        self._dvs.delete_port_group('fake-uuid')
        fake_get_moref.assert_called_once_with('fake-uuid')

    @mock.patch.object(dvs.DvsManager, '_net_id_to_moref',
                       return_value='fake-moref')
    def test_delete_port_group_with_exception(self, fake_get_moref):
        with (
            mock.patch.object(self._dvs._session, 'wait_for_task',
                              side_effect=exp.NeutronException())
        ):
            self.assertRaises(exp.NeutronException,
                              self._dvs.delete_port_group,
                              'fake-uuid')
            fake_get_moref.assert_called_once_with('fake-uuid')
