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


import json
import logging

from tabulate import tabulate


LOG = logging.getLogger(__name__)

def output_formatter(resource_name, resources_list, attrs, fmt='default'):
    if fmt == 'default':
        LOG.info('%(resource_name)s', {'resource_name': resource_name})
        resource_attr_values = []
        for resource in resources_list:
            resource_list = []
            for attr in attrs:
                resource_list.append(resource[attr])
            resource_attr_values.append(resource_list)
        return tabulate(resource_attr_values, attrs, tablefmt='psql')

    if fmt == 'json':
        js_output = {}
        js_output[resource_name] = []
        for resource in resources_list:
            result = {}
            for attr in attrs:
                result[attr] = resource[attr]
            js_output[resource_name].append(result)
        return json.dumps(js_output, sort_keys=True, indent=4)
