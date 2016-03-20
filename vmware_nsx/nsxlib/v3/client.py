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
import requests
import six.moves.urllib.parse as urlparse

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from vmware_nsx._i18n import _, _LW
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils

LOG = log.getLogger(__name__)

ERRORS = {requests.codes.NOT_FOUND: nsx_exc.ResourceNotFound,
          requests.codes.PRECONDITION_FAILED: nsx_exc.StaleRevision}


class RESTClient(object):

    _VERB_RESP_CODES = {
        'get': [requests.codes.ok],
        'post': [requests.codes.created, requests.codes.ok],
        'put': [requests.codes.ok],
        'delete': [requests.codes.ok]
    }

    @utils.trace_method_call
    def __init__(self, connection, url_prefix=None,
                 default_headers=None):
        self._conn = connection
        self._url_prefix = url_prefix or ""
        self._default_headers = default_headers or {}

    @utils.trace_method_call
    def new_client_for(self, *uri_segments):
        uri = self._build_url('/'.join(uri_segments))

        return self.__class__(
            self._conn,
            url_prefix=uri,
            default_headers=self._default_headers)

    @utils.trace_method_call
    def list(self, headers=None):
        return self.url_list('')

    @utils.trace_method_call
    def get(self, uuid, headers=None):
        return self.url_get(uuid, headers=headers)

    @utils.trace_method_call
    def delete(self, uuid, headers=None):
        return self.url_delete(uuid, headers=headers)

    @utils.trace_method_call
    def update(self, uuid, body=None, headers=None):
        return self.url_put(uuid, body, headers=headers)

    @utils.trace_method_call
    def create(self, body=None, headers=None):
        return self.url_post('', body, headers=headers)

    @utils.trace_method_call
    def url_list(self, url, headers=None):
        return self.url_get(url, headers=headers)

    @utils.trace_method_call
    def url_get(self, url, headers=None):
        return self._rest_call(url, method='GET', headers=headers)

    @utils.trace_method_call
    def url_delete(self, url, headers=None):
        return self._rest_call(url, method='DELETE', headers=headers)

    @utils.trace_method_call
    def url_put(self, url, body, headers=None):
        return self._rest_call(url, method='PUT', body=body, headers=headers)

    @utils.trace_method_call
    def url_post(self, url, body, headers=None):
        return self._rest_call(url, method='POST', body=body, headers=headers)

    @utils.trace_method_call
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
                manager=_get_nsx_managers_from_conf(),
                operation=operation,
                details=result_msg)

    @classmethod
    def merge_headers(cls, *headers):
        merged = {}
        for header in headers:
            if header:
                merged.update(header)
        return merged

    @utils.trace_method_call
    def _build_url(self, uri):
        prefix = urlparse.urlparse(self._url_prefix)
        uri = ("/%s/%s" % (prefix.path, uri)).replace('//', '/').strip('/')
        if prefix.netloc:
            uri = "%s/%s" % (prefix.netloc, uri)
        if prefix.scheme:
            uri = "%s://%s" % (prefix.scheme, uri)
        return uri

    @utils.trace_method_call
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

        LOG.debug("REST call: %s %s\nResponse: %s",
                  method, request_url, result.json() if result.content else '')

        self._validate_result(
            result, RESTClient._VERB_RESP_CODES[method.lower()],
            _("%(verb)s %(url)s") % {'verb': method, 'url': request_url})
        return result


class JSONRESTClient(RESTClient):

    _DEFAULT_HEADERS = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    @utils.trace_method_call
    def __init__(self, connection, url_prefix=None,
                 default_headers=None):

        super(JSONRESTClient, self).__init__(
            connection,
            url_prefix=url_prefix,
            default_headers=RESTClient.merge_headers(
                JSONRESTClient._DEFAULT_HEADERS, default_headers))

    @utils.trace_method_call
    def _rest_call(self, *args, **kwargs):
        if kwargs.get('body') is not None:
            kwargs['body'] = jsonutils.dumps(kwargs['body'], sort_keys=True)
        result = super(JSONRESTClient, self)._rest_call(*args, **kwargs)
        return result.json() if result.content else result


class NSX3Client(JSONRESTClient):

    _NSX_V1_API_PREFIX = 'api/v1/'

    @utils.trace_method_call
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


@utils.trace_method_call
def _get_default_api_cluster():
    global _DEFAULT_API_CLUSTER
    if _DEFAULT_API_CLUSTER is None:
        # removes circular ref between client / cluster
        import vmware_nsx.nsxlib.v3.cluster as nsx_cluster
        _DEFAULT_API_CLUSTER = nsx_cluster.NSXClusteredAPI()
    return _DEFAULT_API_CLUSTER


@utils.trace_method_call
def _set_default_api_cluster(cluster):
    global _DEFAULT_API_CLUSTER
    old = _DEFAULT_API_CLUSTER
    _DEFAULT_API_CLUSTER = cluster
    return old


@utils.trace_method_call
def _get_client(client):
    return client or NSX3Client(_get_default_api_cluster())


# NOTE(shihli): tmp until all refs use client class
@utils.trace_method_call
def _get_nsx_managers_from_conf():
    return cfg.CONF.nsx_v3.nsx_api_managers


@utils.trace_method_call
def get_resource(resource, client=None):
    return _get_client(client).get(resource)


@utils.trace_method_call
def create_resource(resource, data, client=None):
    return _get_client(client).url_post(resource, body=data)


@utils.trace_method_call
def update_resource(resource, data, client=None):
    return _get_client(client).update(resource, body=data)


@utils.trace_method_call
def delete_resource(resource, client=None):
    return _get_client(client).delete(resource)
