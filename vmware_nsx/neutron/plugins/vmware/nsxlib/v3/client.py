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

from oslo_config import cfg
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


def _get_manager_endpoint():
    manager = _get_manager_ip()
    username = cfg.CONF.nsx_v3.nsx_user
    password = cfg.CONF.nsx_v3.nsx_password
    return "https://%s" % manager, username, password


def _get_manager_ip():
    # NOTE: In future this may return the IP address from a pool
    manager = cfg.CONF.nsx_v3.nsx_manager
    return manager


def _validate_result(result_status_code, expected, operation):
    if result_status_code not in expected:
        # Do not reveal internal details in the exception message, as it will
        # be user-visible
        LOG.warning(_LW("The HTTP request returned error code %(result)d, "
                        "whereas %(expected)s response codes were expected"),
                    {'result': result_status_code,
                     'expected': '/'.join([str(code) for code in expected])})

        manager_ip = _get_manager_ip()

        manager_error = ERRORS.get(result_status_code, nsx_exc.ManagerError)
        raise manager_error(manager=manager_ip, operation=operation)


def get_resource(resource):
    manager, user, password = _get_manager_endpoint()
    url = manager + "/api/v1/%s" % resource
    headers = {'Accept': 'application/json'}
    result = requests.get(url, auth=auth.HTTPBasicAuth(user, password),
                          verify=False, headers=headers)
    _validate_result(result.status_code, [requests.codes.ok],
                     _("reading resource: %s") % resource)
    return result.json()


def create_resource(resource, data):
    manager, user, password = _get_manager_endpoint()
    url = manager + "/api/v1/%s" % resource
    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json'}
    result = requests.post(url, auth=auth.HTTPBasicAuth(user, password),
                           verify=False, headers=headers,
                           data=jsonutils.dumps(data))
    _validate_result(result.status_code, [requests.codes.created],
                     _("creating resource at: %s") % resource)
    return result.json()


def update_resource(resource, data):
    manager, user, password = _get_manager_endpoint()
    url = manager + "/api/v1/%s" % resource
    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json'}
    result = requests.put(url, auth=auth.HTTPBasicAuth(user, password),
                          verify=False, headers=headers,
                          data=jsonutils.dumps(data))
    _validate_result(result.status_code, [requests.codes.ok],
                     _("updating resource: %s") % resource)
    return result.json()


def delete_resource(resource):
    manager, user, password = _get_manager_endpoint()
    url = manager + "/api/v1/%s" % resource
    result = requests.delete(url, auth=auth.HTTPBasicAuth(user, password),
                             verify=False)
    _validate_result(result.status_code, [requests.codes.ok],
                     _("deleting resource: %s") % resource)
    return result.json()
