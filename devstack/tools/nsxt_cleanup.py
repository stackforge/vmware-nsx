# Copyright 2015 VMware Inc
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

import sys
import json
import base64
import requests

requests.packages.urllib3.disable_warnings()


class NSXClient(object):
    """ Base NSX REST client """
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
        self.headers = None
        self.api_version = NSXClient.API_VERSION

        self.__set_headers()

    def __set_endpoint(self, endpoint):
        self.endpoint = endpoint

    def get_endpoint(self):
        return self.endpoint

    def __set_content_type(self, content_type):
        self.content_type = content_type

    def get_content_type(self):
        return self.content_type

    def __set_accept_type(self, accept_type):
        self.accept_type = accept_type

    def get_accept_type(self):
        return self.accept_type

    def __set_api_version(self, api_version):
        self.api_version = api_version

    def get_api_version(self):
        return self.api

    def __set_url(self, api=None, secure=None, host=None, endpoint=None):
        api = self.api_version if api is None else api
        secure = self.secure if secure is None else secure
        host = self.host if host is None else host
        endpoint = self.endpoint if endpoint is None else endpoint
        http_type = 'https' if secure else 'http'
        self.url = '%s://%s/api/%s%s' % (http_type, host, api, endpoint)

    def get_url(self):
        return self.url

    def __set_headers(self, content=None, accept=None):
        content_type = self.content_type if content is None else content
        accept_type = self.accept_type if accept is None else accept
        auth_cred = self.username + ":" + self.password
        auth = base64.b64encode(auth_cred)
        headers = {}
        headers['Authorization'] = "Basic %s" % auth
        headers['Content-Type'] = content_type
        headers['Accept'] = accept_type
        self.headers = headers

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
                                verify=self.verify, data=json.dumps(body))
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
                                 verify=self.verify, data=json.dumps(body))
        return response

    def get_transport_zones(self):
        """
        Retrieve all transport zones
        """
        response = self.get(endpoint="/transport-zones")
        return response.json()['results']

    def get_logical_ports(self):
        """
        Retrieve all logical ports on NSX backend
        """
        response = self.get(endpoint="/logical-ports")
        return response.json()['results']

    def update_logical_port_attachment(self, lports):
        """
        In order to delete logical ports, we need to detach
        the VIF attachment on the ports first.
        """
        for p in lports:
            p['attachment'] = None
            endpoint = "/logical-ports/%s" % p['id']
            response = self.put(endpoint=endpoint, body=p)
            if response.status_code != 200:
                print("ERROR: Failed to update lport %s" % p['id'])

    def cleanup_os_logical_ports(self):
        """
        Delete all logical ports created by OpenStack
        """
        lports = self.get_logical_ports()
        os_lports = self.get_os_resources(lports)
        print("Number of logical ports to be deleted: %s" % len(os_lports))
        # logical port vif detachment
        self.update_logical_port_attachment(os_lports)
        for p in os_lports:
            endpoint = '/logical-ports/%s' % p['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == 200:
                print("Successfully deleted logical port %s" % p['id'])
            else:
                print("ERROR: Failed to delete lport %s, response code %s" %
                      (p['id'], response.status_code))

    def get_os_resources(self, resources):
        """
        Get all logical resources created by OpenStack
        """
        os_resources = [r for r in resources if 'tags' in r
                        for tag in r['tags'] if 'os-tid' in tag.values()]
        return os_resources

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
        os_lswitches = [l for l in lswitches if 'tags' in l
                        for tag in l['tags'] if 'os-tid' in tag.values()]
        return os_lswitches

    def get_lswitch_ports(self, ls_id):
        """
        Return all the logical ports that belong to this lswitch
        """
        lports = self.get_logical_ports()
        return [p for p in lports if p['logical_switch_id'] is ls_id]

    def cleanup_os_logical_switches(self):
        """
        Delete all logical switches created from OpenStack
        """
        lswitches = self.get_os_logical_switches()
        print("Number of OS logical switches to be deleted: %s" %
              len(lswitches))
        for ls in lswitches:
            endpoint = '/logical-switches/%s' % ls['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code == 200:
                print("Successfully deleted logical switch %s-%s" %
                      (ls['display_name'], ls['id']))
            else:
                print("Failed to delete lswitch %s-%s, and response is %s" %
                      (ls['display_name'], ls['id'], response.status_code))

    def cleanup_all(self):
        """
        Cleanup order:
            1. Cleanup logical ports
            2. Cleanup logical switches
        """
        self.cleanup_os_logical_ports()
        self.cleanup_os_logical_switches()


if __name__ == "__main__":
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("--mgr-ip", dest="mgr_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Manager username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Manager password")
    (options, args) = parser.parse_args()

    # Get NSX REST client
    nsx_client = NSXClient(options.mgr_ip, options.username,
                           options.password)
    # Clean all objects created by OpenStack
    nsx_client.cleanup_all()
