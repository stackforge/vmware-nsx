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
import abc
import contextlib
import datetime
import eventlet
import random
import requests
import six
import urlparse

from eventlet import greenpool
from eventlet import pools
from neutron.i18n import _LI, _LW, _
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_service import loopingcall
from requests import adapters
from vmware_nsx.common import exceptions as nsx_err

from vmware_nsx.common import exceptions as nsx_exc

LOG = log.getLogger(__name__)

ERRORS = {requests.codes.NOT_FOUND: nsx_exc.ResourceNotFound,
          requests.codes.PRECONDITION_FAILED: nsx_exc.StaleRevision}

DEFAULT_TIMEOUT = 75


@six.add_metaclass(abc.ABCMeta)
class AbstractHTTPProvider(object):
    """Interface for providers of HTTP connections which
    are responsible for creating and validating connections
    for their underlying HTTP support.
    """

    @property
    def default_scheme(self):
        return 'https'

    @abc.abstractproperty
    def provider_id(self):
        """A unique string name for this provider."""
        pass

    @abc.abstractmethod
    def validate_connection(self, cluster_api, endpoint, conn):
        """Validate the said connection for the given endpoint and cluster.
        """
        pass

    @abc.abstractmethod
    def new_connection(self, cluster_api, provider):
        """Create a new http connection for the said cluster and
        cluster provider. The actual connection should duck type
        requests.Session http methods (get(), put(), etc.).
        """
        pass


class NSXRequestsHTTPProvider(AbstractHTTPProvider):
    """Concrete implementation of AbstractHTTPProvider
    using requests.Session() as the underlying connection.
    """

    class TimeoutSession(requests.Session):
        """Extends requests.Session to support timeout
        at the session level.
        """

        def __init__(self, timeout=DEFAULT_TIMEOUT):
            self.timeout = timeout
            super(NSXRequestsHTTPProvider.TimeoutSession, self).__init__()

        # wrapper timeouts at the session level
        # see: https://goo.gl/xNk7aM
        def request(self, *args, **kwargs):
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.timeout
            return super(NSXRequestsHTTPProvider.TimeoutSession,
                         self).request(*args, **kwargs)

    @property
    def provider_id(self):
        return "HTTP Provider: %s %s" % (requests.__title__,
                                         requests.__version__)

    def validate_connection(self, cluster_api, endpoint, conn):
        client = NSX3Client(conn, url_prefix=endpoint.provider.url)
        zones = client.get('transport-zones')
        if not zones:
            msg = _("No transport zones found "
                    "for '%(url)s'") % endpoint.provider.url
            LOG.warning(_LW(msg))
            raise nsx_exc.ResourceNotFound(msg)

    def new_connection(self, cluster_api, provider):
        session = NSXRequestsHTTPProvider.TimeoutSession(
            cluster_api.http_timeout)
        session.auth = (cluster_api.username, cluster_api.password)
        session.max_redirects = cluster_api.redirects
        if not cluster_api.insecure:
            session.verify = True
        if cluster_api.ca_file:
            session.cert = cluster_api.ca_file
        # we are pooling with eventlet in the cluster class
        adapter = adapters.HTTPAdapter(
            pool_connections=1, pool_maxsize=1,
            max_retries=cluster_api.retries,
            pool_block=False)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        return session


class ClusteredAPI(object):
    """Duck types the major HTTP based methods of a
    requests.Session such as get(), put(), post(), etc.
    and transparently proxies those calls to one of
    its managed NSX manager endpoints.
    """

    class ClusterHealth(object):
        """Indicator of overall cluster health with respect
        to the connectivity of the clusters managed endpoints.
        """
        GREEN = 'GREEN'
        ORANGE = 'ORANGE'
        RED = 'RED'

    class EndpointState(object):
        """Tracks the connectivity state for a said endpoint.
        """
        INITIALIZED = 'INITIALIZED'
        UP = 'UP'
        DOWN = 'DOWN'

    class Provider(object):
        """Data holder for a provider which has a unique id
        and a connection URL.
        """

        def __init__(self, provider_id, provider_url):
            self.id = provider_id
            self.url = provider_url

        def __str__(self):
            return "Clustered API provider: %s : %s" % (self.id, self.url)

    class Endpoint(object):
        """A single NSX manager endpoint (host) which includes
        related information such as the endpoint's provider,
        state, etc.. A pool is used to hold connections to the
        endpoint which are doled out when proxying HTTP methods
        to the underlying connections.
        """

        def __init__(self, provider, pool):
            self.provider = provider
            self.pool = pool
            self._state = ClusteredAPI.EndpointState.INITIALIZED
            self._last_updated = datetime.datetime.now()

        @property
        def last_updated(self):
            return self._last_updated

        @property
        def state(self):
            return self._state

        def set_state(self, state):
            if self.state != state:
                LOG.debug("Endpoint '%s' changing from state '%s' to '%s'"
                          % (self.provider, self.state, state))
            old_state = self._state
            self._state = state

            self._last_updated = datetime.datetime.now()

            return old_state

        def __str__(self):
            return "Endpoint '%s' with state '%s'" % (self.provider,
                                                      self.state)

    class EndpointConnection(object):
        """Simple data holder which contains an endpoint and
        a connection for that endpoint.
        """

        def __init__(self, endpoint, connection):
            self.endpoint = endpoint
            self.connection = connection

    _HTTP_VERBS = ['get', 'delete', 'head', 'put', 'post', 'patch', 'create']

    def __init__(self, providers,
                 http_provider,
                 min_conns_per_pool=1,
                 max_conns_per_pool=500,
                 keepalive_interval=33):

        self._http_provider = http_provider
        self._keepalive_interval = keepalive_interval

        def _create_conn(p):
            def _conn():
                # called when a pool needs to create a new connection
                return self._http_provider.new_connection(self, p)
            return _conn

        self._endpoints = {}
        for provider in providers:
            pool = pools.Pool(
                min_size=min_conns_per_pool,
                max_size=max_conns_per_pool,
                order_as_stack=True,
                create=_create_conn(provider))

            endpoint = ClusteredAPI.Endpoint(provider, pool)
            self._endpoints[provider.id] = endpoint

        # duck type to proxy http invocations
        for method in ClusteredAPI._HTTP_VERBS:
            setattr(self, method, self._proxy_stub(method))

        LOG.debug("Initializing API endpoints")
        conns = greenpool.GreenPool()
        for endpoint in self._endpoints.values():
            conns.spawn(self._validate, endpoint)
        eventlet.sleep(0)
        while conns.running():
            if (self.health == ClusteredAPI.ClusterHealth.GREEN
                    or self.health == ClusteredAPI.ClusterHealth.ORANGE):
                # only wait for 1 or more endpoints to reduce init time
                break
            eventlet.sleep(0.5)

        for endpoint in self._endpoints.values():
            # dynamic loop for each endpoint to ensure connectivity
            loop = loopingcall.DynamicLoopingCall(
                self._endpoint_keepalive, endpoint)
            loop.start(initial_delay=self._keepalive_interval,
                       periodic_interval_max=self._keepalive_interval,
                       stop_on_exception=False)

        LOG.debug("Done initializing API endpoint(s). "
                  "API cluster health: %s" % self.health)

    def _endpoint_keepalive(self, endpoint):
        delta = datetime.datetime.now() - endpoint.last_updated
        if delta.seconds >= self._keepalive_interval:
            # TODO(boden): backoff on validation failure
            self._validate(endpoint)
            return self._keepalive_interval
        return self._keepalive_interval - delta.seconds

    @property
    def providers(self):
        return [ep.provider for ep in self._endpoints.values()]

    @property
    def endpoints(self):
        return self._endpoints[:]

    @property
    def http_provider(self):
        return self._http_provider

    @property
    def health(self):
        down = 0
        up = 0
        for endpoint in self._endpoints.values():
            if endpoint.state != ClusteredAPI.EndpointState.UP:
                down += 1
            else:
                up += 1

        if down == len(self._endpoints):
            return ClusteredAPI.ClusterHealth.RED
        return (ClusteredAPI.ClusterHealth.GREEN
                if up == len(self._endpoints)
                else ClusteredAPI.ClusterHealth.ORANGE)

    def revalidate_endpoints(self):
        # validate each endpoint in serial
        for endpoint in self._endpoints.values():
            self._validate(endpoint)

    def _validate(self, endpoint):
        try:
            with endpoint.pool.item() as conn:
                self._http_provider.validate_connection(self, endpoint, conn)
                endpoint.set_state(ClusteredAPI.EndpointState.UP)
                LOG.debug("Validated API cluster endpoint: %s" % endpoint)
        except Exception as e:
            endpoint.set_state(ClusteredAPI.EndpointState.DOWN)
            LOG.warning(_LW("Failed to validate API cluster endpoint "
                            "'%(ep)s' due to: %(err)s"),
                        {'ep': endpoint, 'err': e})

    def _select_endpoint(self):
        connected = {}
        for provider_id, endpoint in self._endpoints.items():
            if endpoint.state == ClusteredAPI.EndpointState.UP:
                connected[provider_id] = endpoint
                if endpoint.pool.free():
                    # connection can be used now
                    return endpoint

        # no free connections; randmonly select a connected endpoint
        # which will likely wait pool.item() until a connection frees up
        return (connected[random.choice(connected.keys())]
                if connected else None)

    def endpoint_for_connection(self, conn):
        # check all endpoint pools
        for endpoint in self._endpoints.values():
            if (conn in endpoint.pool.channel.queue or
                    conn in endpoint.pool.free_items):
                return endpoint
        return None

    @property
    def cluster_id(self):
        return ','.join([str(ep.provider.url)
                         for ep in self._endpoints.values()])

    @contextlib.contextmanager
    def connection(self):
        with self.endpoint_connection() as conn_data:
            yield conn_data.connection

    @contextlib.contextmanager
    def endpoint_connection(self):
        endpoint = self._select_endpoint()
        if not endpoint:
            raise nsx_err.ServiceClusterUnavailable(
                cluster_id=self.cluster_id)

        if endpoint.pool.free() == 0:
            msg = _("API endpoint %(ep)s at connection capacity "
                    "%(max)s and has %(waiting)s waiting") % {
                'ep': endpoint,
                'max': endpoint.pool.max_size,
                'waiting': endpoint.pool.waiting()
            }
            LOG.info(_LI(msg))
        # pool.item() will block if pool has 0 free
        with endpoint.pool.item() as conn:
            yield ClusteredAPI.EndpointConnection(endpoint, conn)

    def _proxy_stub(self, proxy_for):
        def _call_proxy(url, *args, **kwargs):
            return self._proxy(proxy_for, url, *args, **kwargs)
        return _call_proxy

    def _proxy(self, proxy_for, uri, *args, **kwargs):
        # proxy http request call to an avail endpoint
        with self.endpoint_connection() as conn_data:
            conn = conn_data.connection
            endpoint = conn_data.endpoint

            # http conn must support requests style interface
            do_request = getattr(conn, proxy_for)

            if not uri.startswith('/'):
                uri = "/%s" % uri
            url = "%s%s" % (endpoint.provider.url, uri)
            try:
                LOG.debug("API cluster proxy %s %s to %s" % (
                    proxy_for.upper(), uri, url))
                # call the actual connection method to do the
                # http request/response over the wire
                response = do_request(url, *args, **kwargs)
                endpoint.set_state(ClusteredAPI.EndpointState.UP)

                return response
            except Exception as e:
                msg = _("Request failed due to: %s") % e
                LOG.warning(_LW(msg))
                endpoint.set_state(ClusteredAPI.EndpointState.DOWN)
                # retry until exhausting endpoints
                return self._proxy(proxy_for, uri, *args, **kwargs)


class NSXClusteredAPI(ClusteredAPI):
    """Extends ClusteredAPI to get conf values and setup the
    NSX v3 cluster.
    """

    def __init__(self, http_provider=None):
        self.username = cfg.CONF.nsx_v3.nsx_user
        self.password = cfg.CONF.nsx_v3.nsx_password
        self.retries = cfg.CONF.nsx_v3.retries
        self.insecure = cfg.CONF.nsx_v3.insecure
        self.ca_file = cfg.CONF.nsx_v3.ca_file
        self.conns_per_pool = cfg.CONF.nsx_v3.concurrent_connections
        self.http_timeout = cfg.CONF.nsx_v3.http_timeout
        self.conn_idle_timeout = cfg.CONF.nsx_v3.conn_idle_timeout
        self.redirects = cfg.CONF.nsx_v3.redirects

        self._http_provider = http_provider or NSXRequestsHTTPProvider()

        super(NSXClusteredAPI, self).__init__(
            self._build_conf_providers(),
            self._http_provider,
            max_conns_per_pool=self.conns_per_pool,
            keepalive_interval=self.conn_idle_timeout)

        LOG.debug("Created NSX clustered API with '%s' "
                  "provider" % self._http_provider.provider_id)

    def _build_conf_providers(self):

        def _schemed_url(uri):
            uri = uri.strip('/')
            return urlparse.urlparse(
                uri if uri.startswith('http') else
                "%s://%s" % (self._http_provider.default_scheme, uri))

        conf_urls = cfg.CONF.nsx_v3.nsx_manager[:]
        urls = []
        providers = []

        for conf_url in conf_urls:
            conf_url = _schemed_url(conf_url)
            if conf_url in urls:
                msg = (_("'%s' already defined in configuration file."
                        " Skipping.") % urlparse.urlunparse(conf_url))
                LOG.warning(_LW(msg))
                continue
            urls.append(conf_url)
            providers.append(ClusteredAPI.Provider(
                conf_url.netloc, urlparse.urlunparse(conf_url)))
        return providers


class RESTClient(object):

    _VERB_RESP_CODES = {
        'get': [requests.codes.ok],
        'post': [requests.codes.created, requests.codes.ok],
        'put': [requests.codes.ok],
        'delete': [requests.codes.ok]
    }

    def __init__(self, connection, url_prefix=None,
                 default_headers=None):
        self._conn = connection
        self._url_prefix = url_prefix or ""
        self._default_headers = default_headers or {}

    def new_client_for(self, *uri_segments):
        uri = self._build_url('/'.join(uri_segments))

        return self.__class__(
            self._conn,
            url_prefix=uri,
            default_headers=self._default_headers)

    def list(self, headers=None):
        return self.url_list('')

    def get(self, uuid, headers=None):
        return self.url_get(uuid, headers=headers)

    def delete(self, uuid, headers=None):
        return self.url_delete(uuid, headers=headers)

    def update(self, uuid, body=None, headers=None):
        return self.url_put(uuid, body, headers=headers)

    def create(self, body=None, headers=None):
        return self.url_post('', body, headers=headers)

    def url_list(self, url, headers=None):
        return self.url_get(url, headers=headers)

    def url_get(self, url, headers=None):
        return self._rest_call(url, method='GET', headers=headers)

    def url_delete(self, url, headers=None):
        return self._rest_call(url, method='DELETE', headers=headers)

    def url_put(self, url, body, headers=None):
        return self._rest_call(url, method='PUT', body=body, headers=headers)

    def url_post(self, url, body, headers=None):
        return self._rest_call(url, method='POST', body=body, headers=headers)

    def _validate_result(self, result, expected, operation):
        if result.status_code not in expected:
            result_msg = result.json() if result.content else ''
            LOG.warning(_LW("The HTTP request returned error code "
                            "%(result)d, whereas %(expected)s response "
                            "codes were expected. Response body %(body)s"),
                        {'result': result.status_code,
                         'expected': '/'.join([str(code)
                                               for code in expected]),
                         'body': result_msg})

            manager_error = ERRORS.get(
                result.status_code, nsx_exc.ManagerError)
            if type(result_msg) is dict:
                result_msg = result_msg.get('error_message', result_msg)
            raise manager_error(
                manager=_get_nsx_manager_from_conf(),
                operation=operation,
                details=result_msg)

    @classmethod
    def merge_headers(cls, *headers):
        merged = {}
        for header in headers:
            if header:
                merged.update(header)
        return merged

    def _build_url(self, uri):
        prefix = urlparse.urlparse(self._url_prefix)
        uri = ("/%s/%s" % (prefix.path, uri)).replace('//', '/').strip('/')
        if prefix.netloc:
            uri = "%s/%s" % (prefix.netloc, uri)
        if prefix.scheme:
            uri = "%s://%s" % (prefix.scheme, uri)
        return uri

    def _rest_call(self, url, method='GET', body=None, headers=None):
        request_headers = headers.copy() if headers else {}
        request_headers.update(self._default_headers)
        request_url = self._build_url(url)

        do_request = getattr(self._conn, method.lower())

        LOG.debug("REST call: %s %s\nHeaders: %s\nBody: %s",
                  method, request_url, request_headers, body)

        result = do_request(
            request_url,
            data=body,
            headers=request_headers)

        self._validate_result(
            result, RESTClient._VERB_RESP_CODES[method.lower()],
            _("%(verb)s %(url)s") % {'verb': method, 'url': request_url})
        return result


class JSONRESTClient(RESTClient):

    _DEFAULT_HEADERS = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    def __init__(self, connection, url_prefix=None,
                 default_headers=None):

        super(JSONRESTClient, self).__init__(
            connection,
            url_prefix=url_prefix,
            default_headers=RESTClient.merge_headers(
                JSONRESTClient._DEFAULT_HEADERS, default_headers))

    def _rest_call(self, *args, **kwargs):
        if kwargs.get('body') is not None:
            kwargs['body'] = jsonutils.dumps(kwargs['body'], sort_keys=True)
        result = super(JSONRESTClient, self)._rest_call(*args, **kwargs)
        return result.json() if result.content else result


class NSX3Client(JSONRESTClient):

    _NSX_V1_API_PREFIX = 'api/v1/'

    def __init__(self, connection, url_prefix=None,
                 default_headers=None):

        url_prefix = url_prefix or NSX3Client._NSX_V1_API_PREFIX
        if url_prefix and NSX3Client._NSX_V1_API_PREFIX not in url_prefix:
            if url_prefix.startswith('http'):
                url_prefix += '/' + NSX3Client._NSX_V1_API_PREFIX
            else:
                url_prefix = "%s/%s" % (NSX3Client._NSX_V1_API_PREFIX,
                                        url_prefix or '')

        super(NSX3Client, self).__init__(
            connection, url_prefix=url_prefix,
            default_headers=default_headers)


# TODO(boden): remove mod level fns and vars below
_DEFAULT_API_CLUSTER = None


def _get_default_api_cluster():
    global _DEFAULT_API_CLUSTER
    if _DEFAULT_API_CLUSTER is None:
        _DEFAULT_API_CLUSTER = NSXClusteredAPI()
    return _DEFAULT_API_CLUSTER


def _set_default_api_cluster(cluster):
    global _DEFAULT_API_CLUSTER
    old = _DEFAULT_API_CLUSTER
    _DEFAULT_API_CLUSTER = cluster
    return old


def _get_client(client):
    return client or NSX3Client(_get_default_api_cluster())


# NOTE(shihli): tmp until all refs use client class
def _get_nsx_manager_from_conf():
    return cfg.CONF.nsx_v3.nsx_manager


def get_resource(resource, client=None):
    return _get_client(client).get(resource)


def create_resource(resource, data, client=None):
    return _get_client(client).url_post(resource, body=data)


def update_resource(resource, data, client=None):
    return _get_client(client).update(resource, body=data)


def delete_resource(resource, client=None):
    return _get_client(client).delete(resource)
