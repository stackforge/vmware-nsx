# Copyright 2015 VMware, Inc.  All rights reserved.
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
#     under the License.


from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def output_formatter(resource_name, resources_list, attrs):
    LOG.info(("%(resource_name)s "), {'resource_name': resource_name})
    for resource in resources_list:
        resource_str = ''
        for attr in attrs:
            resource_str += "%s: %s   " % (attr, resource[attr])
        LOG.info(resource_str)
