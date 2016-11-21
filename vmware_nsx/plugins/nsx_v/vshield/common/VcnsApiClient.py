# Copyright 2013 VMware, Inc
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

import base64
import six
import ssl

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from oslo_serialization import jsonutils

from vmware_nsx.plugins.nsx_v.vshield.common import exceptions


def _xmldump(obj):
    """Sort of improved xml creation method.

    This converts the dict to xml with following assumptions:
    Keys starting with _(underscore) are to be used as attributes and not
    element keys starting with @ so that dict can be made.
    Keys starting with __(double underscore) are to be skipped and its
    value is processed.
    The keys are not part of any xml schema.
    """

    config = ""
    attr = ""
    if isinstance(obj, dict):
        for key, value in six.iteritems(obj):
            if key.startswith('__'):
                # Skip the key and evaluate it's value.
                a, x = _xmldump(value)
                config += x
            elif key.startswith('_'):
                attr += ' %s="%s"' % (key[1:], value)
            else:
                a, x = _xmldump(value)
                if key.startswith('@'):
                    cfg = "%s" % (x)
                else:
                    cfg = "<%s%s>%s</%s>" % (key, a, x, key)

                config += cfg
    elif isinstance(obj, list):
        for value in obj:
            a, x = _xmldump(value)
            attr += a
            config += x
    else:
        config = obj

    return attr, config


def xmldumps(obj):
    attr, xml = _xmldump(obj)
    return xml


class MyAdapter(HTTPAdapter):
        def init_poolmanager(self, connections, maxsize):
            self.poolmanager = PoolManager(num_pools=connections,
                                           maxsize=maxsize,
                                           ssl_version=ssl.PROTOCOL_TLSv1)


class VcnsApiHelper(object):
    errors = {
        303: exceptions.ResourceRedirect,
        400: exceptions.RequestBad,
        403: exceptions.Forbidden,
        404: exceptions.ResourceNotFound,
        409: exceptions.ServiceConflict,
        415: exceptions.MediaTypeUnsupport,
        503: exceptions.ServiceUnavailable
    }

    def __init__(self, address, user, password, format='json', ca_file=None,
                 insecure=True):
        self.authToken = base64.encodestring(six.b("%s:%s" % (user, password)))
        self.user = user
        self.passwd = password
        self.address = address
        self.format = format
        if format == 'json':
            self.encode = jsonutils.dumps
        else:
            self.encode = xmldumps

        if insecure:
            self.verify_cert = False
        else:
            if ca_file:
                self.verify_cert = ca_file
            else:
                self.verify_cert = True

    def request(self, method, uri, params=None, headers=None,
                encodeparams=True):
        uri = self.address + uri
        if headers is None:
            headers = {}

        headers['Accept'] = 'application/' + self.format
        headers['Authorization'] = 'Basic ' + self.authToken.strip()
        headers['Content-Type'] = 'application/' + self.format

        if params:
            if encodeparams is True:
                data = self.encode(params)
            else:
                data = params
        else:
            data = None

        response = requests.request(method,
                                    uri,
                                    verify=self.verify_cert,
                                    data=data,
                                    headers=headers)

        status = response.status_code
        if 200 <= status < 300:
            return response.headers, response.text
        if status in self.errors:
            cls = self.errors[status]
        else:
            cls = exceptions.VcnsApiException
        raise cls(uri=uri, status=status,
                  header=response.headers, response=response.text)
