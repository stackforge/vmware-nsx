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
import six

from oslo_log import log
from oslo_serialization import jsonutils
import requests
from requests import auth

from neutron.i18n import _LW
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc

LOG = log.getLogger(__name__)


NOT_FOUND = 404
PRECONDITION_FAILED = 412

ERRORS = {NOT_FOUND: nsx_exc.ResourceNotFound,
          PRECONDITION_FAILED: nsx_exc.StaleRevision}


@six.add_metaclass(abc.ABCMeta)
class NsxManagerBase(object):

    @abc.abstractproperty
    def manager(self):
        pass

    @abc.abstractproperty
    def version(self):
        pass

    def _validate_result(self, result_status_code, expected, operation):
        if result_status_code not in expected:
            # Do not reveal internal details in the exception message,
            # as it will be user-visible
            LOG.warning(_LW("The HTTP request returned error code %(result)s "
                            "whereas %(expected)s response codes were "
                            "expected"),
                        {'result': result_status_code, 'expected': expected})

            manager_error = ERRORS.get(result_status_code,
                                       nsx_exc.ManagerError)
            raise manager_error(manager=self.manager, operation=operation)

    def get_manager_endpoint(self):
        return 'https://%s/api/%s/' % (self.manager, self.version)

    def get_url(self, resource):
        manager_endpoint = self.get_manager_endpoint()
        return '%s/%s' % (manager_endpoint, resource)

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


class NsxV3Manager(NsxManagerBase):

    def __init__(self, endpoint='', username='', password='', version='v1'):
        self.username = username
        self.password = password
        self._version = version
        self._manager = endpoint

    @property
    def manager(self):
        return self._manager

    @property
    def version(self):
        return self._version

    def _get_auth(self):
        return auth.HTTPBasicAuth(self.user, self.password)

    def get_resource(self, resource):
        url = self.get_url(self.resource)
        headers = {'Accept': 'application/json'}

        result = requests.get(
            url, auth=self._get_auth(), verify=False, headers=headers)
        self.validate_result(result.status_code, [requests.codes.ok],
                             _("reading resource: %s") % resource)
        return result.json()

    def create_resource(self, resource, data):
        url = self.get_url(self.manager, resource)
        data = jsonutils.dumps(data)
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json'}

        result = requests.post(url, auth=self._auth(), verify=False,
                               headers=headers, data=data)
        self.validate_result(result.status_code, [requests.codes.created],
                             _("creating resource: %s") % resource)
        return result.json()

    def update_resource(self, resource, data):
        url = self.get_url(resource)
        data = jsonutils.dumps(data)
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json'}

        result = requests.put(url, auth=self._get_auth(), verify=False,
                              headers=headers, data=data)
        self.validate_result(result.status_code, [requests.codes.ok],
                             _("updating resource: %s") % resource)
        return result.json()

    def delete_resource(self, resource):
        url = self.get_url(resource)
        result = requests.delete(url, auth=self._get_auth(), verify=False)

        self.validate_result(result.status_code, [requests.codes.ok],
                             _("deleting resource: %s") % resource)
        return result.json()
