# Copyright 2015 VMware, Inc.
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
#
import mock
import urlparse

from oslo_config import cfg
from oslo_serialization import jsonutils
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import cluster
from vmware_nsx.tests.unit.nsxlib.v3 import nsxlib_testcase
from vmware_nsx.tests.unit.nsx_v3 import mocks


class RequestsHTTPProviderTestCase(nsxlib_testcase.NsxClientTestCase):

    def test_new_connection(self):
        mock_api = mock.Mock()
        mock_api.username = 'nsxuser'
        mock_api.password = 'nsxpassword'
        mock_api.retries = 100
        mock_api.insecure = True
        mock_api.ca_file = None
        mock_api.http_timeout = 99
        mock_api.conn_idle_timeout = 39
        provider = cluster.NSXRequestsHTTPProvider()
        session = provider.new_connection(
            mock_api, cluster.Provider('9.8.7.6', 'https://9.8.7.6'))

        self.assertEqual(session.auth, ('nsxuser', 'nsxpassword'))
        self.assertEqual(session.verify, False)
        self.assertEqual(session.cert, None)
        self.assertEqual(session.adapters['https://'].max_retries.total, 100)
        self.assertEqual(session.timeout, 99)

    def test_validate_connection(self):
        mock_conn = mocks.MockRequestSessionApi()
        mock_ep = mock.Mock()
        mock_ep.provider.url = 'https://1.2.3.4'
        provider = cluster.NSXRequestsHTTPProvider()
        self.assertRaises(nsx_exc.ResourceNotFound,
                          provider.validate_connection,
                          mock.Mock(), mock_ep, mock_conn)

        mock_conn.post('api/v1/transport-zones',
                       data=jsonutils.dumps({'id': 'dummy-tz'}),
                       headers=client.JSONRESTClient._DEFAULT_HEADERS)
        provider.validate_connection(mock.Mock(), mock_ep, mock_conn)


class NsxV3ClusteredAPITestCase(nsxlib_testcase.NsxClientTestCase):

    @mock.patch.object(cluster.Provider, '__init__', return_value=None)
    @mock.patch.object(cluster.ClusteredAPI, '__init__', return_value=None)
    def test_conf_providers_no_scheme(self, mock_api_init, mock_provider_init):
        conf_managers = ['8.9.10.11', '9.10.11.12:4433']
        mock_provider = mock.Mock()
        mock_provider.default_scheme = 'https'
        cfg.CONF.set_override(
            'nsx_manager', conf_managers, 'nsx_v3')
        cluster.NSXClusteredAPI(http_provider=mock_provider)

        mock_calls = []
        for provider in conf_managers:
            mock_calls.append(mock.call(provider, "https://%s" % provider))

        mock_provider_init.assert_has_calls(mock_calls)

    @mock.patch.object(cluster.Provider, '__init__', return_value=None)
    @mock.patch.object(cluster.ClusteredAPI, '__init__', return_value=None)
    def test_conf_providers_with_scheme(self, mock_api_init, mock_provider_init):
        conf_managers = ['http://8.9.10.11:8080', 'https://9.10.11.12:4433']
        mock_provider = mock.Mock()
        mock_provider.default_scheme = 'https'
        cfg.CONF.set_override(
            'nsx_manager', conf_managers, 'nsx_v3')
        cluster.NSXClusteredAPI(http_provider=mock_provider)

        mock_calls = []
        for provider in conf_managers:
            mock_calls.append(
                mock.call(urlparse.urlparse(provider).netloc, provider))

        mock_provider_init.assert_has_calls(mock_calls)


class ClusteredAPITestCase(nsxlib_testcase.NsxClientTestCase):

    def _test_health(self, validate_fn, expected_health):
        conf_managers = ['8.9.10.11', '9.10.11.12']
        cfg.CONF.set_override(
            'nsx_manager', conf_managers, 'nsx_v3')

        mock_provider = mock.Mock()
        mock_provider.default_scheme = 'https'

        mock_provider.validate_connection = validate_fn
        api = cluster.NSXClusteredAPI(http_provider=mock_provider)
        self.assertEqual(api.health, expected_health)

    def test_orange_health(self):

        def _validate(cluster_api, endpoint, conn):
            if endpoint.provider.id == '8.9.10.11':
                raise Exception()

        self._test_health(_validate, cluster.ClusterHealth.ORANGE)

    def test_green_health(self):

        def _validate(cluster_api, endpoint, conn):
            return

        self._test_health(_validate, cluster.ClusterHealth.GREEN)

    def test_red_health(self):
        def _validate(cluster_api, endpoint, conn):
            raise Exception()

        self._test_health(_validate, cluster.ClusterHealth.RED)
