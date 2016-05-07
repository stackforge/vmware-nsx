#!/usr/bin/env python

# Copyright 2016 VMware Inc
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

import base64
import optparse
import requests

from oslo_serialization import jsonutils


requests.packages.urllib3.disable_warnings()


class NSXClient(object):
    """Base NSX REST client"""
    API_VERSION = "v1"

    def __init__(self, host, username, password, *args, **kwargs):
        self.host = host
        self.username = username
        self.password = password
        self.version = None
        self.endpoint = None
        self.content_type = "application/json"
        self.accept_type = "application/json"
        self.verify = False
        self.secure = True
        self.interface = "json"
        self.url = None
        self.api_version = NSXClient.API_VERSION
        self.headers = {
            'Authorization': "Basic %s" % base64.b64encode(
                self.username + ":" + self.password),
            'Content-Type': self.content_type,
            'Accept': self.accept_type
        }

    def __set_url(self, version=None, secure=None, host=None, endpoint=None):
        self.url = '%s://%s/api/%s%s' % (
            'https' if secure or self.secure else 'http',
            host or self.host,
            version or self.api_version,
            endpoint or self.endpoint)

    def get(self, endpoint=None, params=None):
        """
        Basic query method for json API request
        """
        self.__set_url(endpoint=endpoint)
        response = requests.get(self.url, headers=self.headers,
                                verify=self.verify, params=params)
        return response

    def put(self, endpoint=None, body=None):
        """
        Basic put API method on endpoint
        """
        self.__set_url(endpoint=endpoint)
        response = requests.put(self.url, headers=self.headers,
                                verify=self.verify, data=jsonutils.dumps(body))
        return response

    def delete(self, endpoint=None, params=None):
        """
        Basic delete API method on endpoint
        """
        self.__set_url(endpoint=endpoint)
        response = requests.delete(self.url, headers=self.headers,
                                   verify=self.verify, params=params)
        return response

    def post(self, endpoint=None, body=None):
        """
        Basic post API method on endpoint
        """
        self.__set_url(endpoint=endpoint)
        response = requests.post(self.url, headers=self.headers,
                                 verify=self.verify,
                                 data=jsonutils.dumps(body))
        return response

    def get_os_resources(self, resources):
        """
        Get all logical resources created by OpenStack
        """
        os_resources = [r for r in resources if 'tags' in r
                        for tag in r['tags']
                        if 'os-project-id' in tag.values()]
        return os_resources

    def get_logical_switch(self, id):
        """
        Retrieve a logical switch on NSX backend
        """
        response = self.get(endpoint="/logical-switches/%s" % id)
        return response.json()

    def get_logical_switch_services(self, id):
        """
        Retrieve the service bindings of a logical switch on NSX backend
        """
        response = self.get(endpoint="/logical-switches/%s/services" % id)
        return response.json()['results']

    def add_logical_switch_service(self, id, service):
        """
        Add a service binding to a logical switch on NSX backend
        """
        old_services = self.get_logical_switch_services(id)['results']
        if service in [s['service_id']['target_id'] for s in old_services]:
            return old_services
        new_services = old_services + [{'service_id': {'target_id': service}}]
        response = self.put(endpoint="/logical-switches/%s/services" % id,
                            body=new_services)
        return response.json()['results']

    def get_logical_switches(self):
        """
        Retrieve all logical switches on NSX backend
        """
        response = self.get(endpoint="/logical-switches")
        return response.json()['results']

    def get_os_logical_switches(self):
        """
        Retrieve all logical switches created from OpenStack
        """
        lswitches = self.get_logical_switches()
        return self.get_os_resources(lswitches)

    def get_metadata_proxy(self, id):
        """
        Retrieve a metadata proxy on NSX backend
        """
        response = self.get(endpoint="/md-proxies/%s" % id)
        return response.json()

    def get_metadata_proxies(self):
        """
        Retrieve all metadata proxies on NSX backend
        """
        response = self.get(endpoint="/md-proxies")
        return response.json()['results']


if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("--mgr-ip", dest="mgr_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Manager username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Manager password")
    parser.add_option("--md-proxy-uuid", dest="md_proxy_uuid",
                      help="NSX Metadata Proxy UUID")
    (options, args) = parser.parse_args()

    # Get NSX REST client
    nsx_client = NSXClient(options.mgr_ip, options.username,
                           options.password)

    # Get all logical switches created from OpenStack.
    lswitches = nsx_client.get_os_logical_switches()
    if options.md_proxy_uuid:
        for ls in lswitches:
            # Add metadata-proxy service to each logical switch.
            nsx_client.add_logical_switch_service(ls['id'],
                                                  options.md_proxy_uuid)
