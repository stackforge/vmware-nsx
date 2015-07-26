# Copyright 2015 OpenStack Foundation
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

import abc
import re
import six

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
import requests
from requests import auth

from neutron.i18n import _LW
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc

LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class NsxManagerBase(object):

    @classmethod
    def _get_manager_endpoint(cls, manager, version):
        return 'https://%s/api/%s/' % (manager, version)

    @abc.abstractmethod
    def get_resource(self, resource):
        pass

    @abc.abstractmethod
    def create_resource(self, resource, data):
        pass

    @abc.abstractmethod
    def update_resource(self, resource, data):
        pass

    @abc.abstractmethod
    def delete_resource(self, resource):
        pass


class NsxManagerError(nsx_exc.NsxPluginException):
    def __init__(self, status_code, err_msg):
        self.status_code = status_code
        super(NsxManagerError, self).__init__(err_msg=err_msg)


class NsxResourceNotFound(NsxManagerError):
    pass


class NsxStaleResourceRevision(NsxManagerError):
    pass


def _get_manager_endpoint():
    manager = _get_manager_ip()
    username = cfg.CONF.nsx_v3.nsx_user
    password = cfg.CONF.nsx_v3.nsx_password
    return "https://%s" % manager, username, password


def _get_manager_ip():
    # NOTE: In future this may return the IP address from a pool
    manager = cfg.CONF.nsx_v3.nsx_manager
    return manager


class NsxV3Manager(NsxManagerBase):

    def __init__(self, endpoint='', username='', password='', version='v1'):
        self.username = username
        self.password = password
        self.manager = self._get_manager_endpoint(endpoint, version)

    def _get_auth(self):
        return auth.HTTPBasicAuth(self.user, self.password)

    def _validate_result(self, result, expected, operation):
        if result.status_code not in expected:
            # Do not reveal internal details in the exception message,
            # as it will be user-visible
            LOG.warning(_LW("The HTTP request returned error code %(result)d, "
                            "whereas %(expected)s response codes were "
                            "expected"), {'result': result.status_code,
                                          'expected': expected})
            err_msg = _("Unexpected error in the backend while %s") % operation

            if result.status_code == requests.codes.not_found:
                raise NsxResourceNotFound(result.status_code, err_msg)
            elif result.status_code == requests.codes.bad:
                # REVISIT(roeyc): use designated code (i.e - 409, 412)
                res_body = result.json()
                if re.match(r'revision number \d+ is stale',
                            res_body) is not None:
                    raise NsxStaleResourceRevision(result.status_code, err_msg)
            raise NsxManagerError(result.status_code, err_msg)

    def _get_url(self, resource):
        return '%s/%s' % (self.manager, resource)

    def get_resource(self, resource):
        url = self._get_url(resource)
        headers = {'Accept': 'application/json'}
        result = requests.get(
            url, auth=self._get_auth(), verify=False, headers=headers)
        self._validate_result(result, [requests.codes.ok],
                              _("reading resource: %s") % resource)
        return result.json()

    def create_resource(self, resource, data):
        url = self._get_url(resource)
        data = jsonutils.dumps(data)
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json'}
        result = requests.post(url, auth=self._auth(), verify=False,
                               headers=headers, data=data)
        self._validate_result(result, [requests.codes.created],
                              _("creating resource: %s") % resource)
        return result.json()

    def update_resource(self, resource, data):
        url = self._get_url(resource)
        data = jsonutils.dumps(data)
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json'}
        result = requests.put(url, auth=self._get_auth(), verify=False,
                              headers=headers, data=data)
        self._validate_result(result, [requests.codes.ok],
                              _("updating resource: %s") % resource)
        return result.json()

    def delete_resource(self, resource):
        url = self._get_url(resource)
        result = requests.delete(url, auth=self._get_auth(), verify=False)
        # REVISIT(roeyc): expecting 204 no-content?
        self._validate_result(result, [requests.codes.ok],
                              _("deleting resource: %s") % resource)
        return result.json()
