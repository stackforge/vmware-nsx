# Copyright 2013 OpenStack Foundation.
#
# All Rights Reserved.
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

import os

from oslo.vmware.network.nsx.nsxv.api import api as nsxv_api
from oslo.vmware.network.nsx.nsxv.api import api_helper as nsxv_api_helper

from vmware_nsx.neutron.plugins.vmware.api_client import client as nsx_client
from vmware_nsx.neutron.plugins.vmware.api_client import eventlet_client
from vmware_nsx.neutron.plugins.vmware import extensions
import vmware_nsx.neutron.plugins.vmware.plugin as neutron_plugin
from vmware_nsx.neutron.plugins.vmware.vshield import edge_utils
import vmware_nsx.neutron.plugins.vmware.vshield.vcns_driver as vcnsdriver


plugin = neutron_plugin.NsxPlugin
api_client = nsx_client.NsxApiClient
evt_client = eventlet_client.EventletApiClient
nsxv_class = nsxv_api.NsxvApi
nsxv_driver = vcnsdriver.VcnsDriver
api_helper = nsxv_api_helper.NsxvApiHelper
edge_manage_class = edge_utils.EdgeManager

STUBS_PATH = os.path.join(os.path.dirname(__file__), 'etc')
NSXEXT_PATH = os.path.dirname(extensions.__file__)
NSXAPI_NAME = '%s.%s' % (api_client.__module__, api_client.__name__)
PLUGIN_NAME = '%s.%s' % (plugin.__module__, plugin.__name__)
CLIENT_NAME = '%s.%s' % (evt_client.__module__, evt_client.__name__)
VCNS_NAME = '%s.%s' % (nsxv_class.__module__, nsxv_class.__name__)
VCNS_DRIVER_NAME = '%s.%s' % (nsxv_driver.__module__, nsxv_driver.__name__)
VCNSAPI_NAME = '%s.%s' % (api_helper.__module__, api_helper.__name__)
EDGE_MANAGE_NAME = '%s.%s' % (edge_manage_class.__module__,
                              edge_manage_class.__name__)


def get_fake_conf(filename):
    return os.path.join(STUBS_PATH, filename)


def nsx_method(method_name, module_name='nsxlib'):
    return '%s.%s.%s' % ('vmware_nsx.neutron.plugins.vmware', module_name,
                         method_name)
