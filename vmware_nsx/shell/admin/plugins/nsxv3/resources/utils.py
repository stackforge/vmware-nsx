# Copyright 2016 VMware, Inc.  All rights reserved.
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
import requests

from oslo_serialization import jsonutils

from neutron import context
from neutron.db import db_base_plugin_v2

from vmware_nsx.db import db as nsx_db

requests.packages.urllib3.disable_warnings()


class NeutronDbClient(db_base_plugin_v2.NeutronDbPluginV2):
    def __init__(self):
        super(NeutronDbClient, self).__init__()
        self.context = context.get_admin_context()

    def get_ports(self, filters=None, fields=None):
        return super(NeutronDbClient, self).get_ports(
            self.context, filters=filters, fields=fields)

    def get_networks(self, filters=None, fields=None):
        return super(NeutronDbClient, self).get_networks(
            self.context, filters=filters, fields=fields)

    def get_network(self, network_id):
        return super(NeutronDbClient, self).get_network(
            self.context, network_id)

    def get_subnet(self, subnet_id):
        return super(NeutronDbClient, self).get_subnet(self.context, subnet_id)

    def get_lswitch_and_lport_id(self, port_id):
        return nsx_db.get_nsx_switch_and_port_id(self.context.session, port_id)

    def lswitch_id_to_net_id(self, lswitch_id):
        net_ids = nsx_db.get_net_ids(self.context.session, lswitch_id)
        return net_ids[0] if net_ids else None

    def net_id_to_lswitch_id(self, net_id):
        lswitch_ids = nsx_db.get_nsx_switch_ids(self.context.session, net_id)
        return lswitch_ids[0] if lswitch_ids else None


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

    def get_os_logical_switches(self):
        """
        Retrieve all logical switches created from OpenStack
        """
        lswitches = self.get_logical_switches()
        return self.get_os_resources(lswitches)

    def get_logical_switch(self, id):
        """
        Retrieve a logical switch on NSX backend
        """
        response = self.get(endpoint="/logical-switches/%s" % id)
        return response.json()

    def get_logical_switches(self):
        """
        Retrieve all logical switches on NSX backend
        """
        response = self.get(endpoint="/logical-switches")
        return response.json()['results']

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

    def create_logical_dhcp_server(self, dhcp_profile_id, server_ip,
                                   dns_servers=None, domain_name=None,
                                   gateway_ip=None, tags=None):
        """
        Create a logical DHCP server
        """
        ipv4_dhcp_server = {'dhcp_server_ip': server_ip}
        if dns_servers:
            ipv4_dhcp_server['dns_nameservers'] = dns_servers
        if domain_name:
            ipv4_dhcp_server['domain_name'] = domain_name
        if gateway_ip:
            ipv4_dhcp_server['gateway_ip'] = gateway_ip
        body = {'dhcp_profile_id': dhcp_profile_id,
                'ipv4_dhcp_server': ipv4_dhcp_server}
        if tags:
            body['tags'] = tags
        response = self.post(endpoint="/dhcp/services", body=body)
        return response.json()

    def create_logical_switch_port(self, lswitch_id, attachment=None):
        """
        Create a logical switch port with an attachment
        """
        body = {'logical_switch_id': lswitch_id, 'admin_state': 'UP'}
        if attachment:
            body['attachment'] = attachment
        response = self.post(endpoint="/logical-ports", body=body)
        return response.json()

    def create_static_binding(self, dhcp_server_id, mac, ip, hostname=None,
                              lease_time=None):
        """
        Create a Mac/IP static binding on a DHCP server
        """
        body = {'mac_address': mac, 'ip_address': ip}
        if hostname:
            body['host_name'] = hostname
        if lease_time:
            body['lease_time'] = lease_time
        response = self.post(endpoint="/dhcp/services/%s/bindings" %
                             dhcp_server_id, body=body)
        return response.json()

    def update_logical_switch_port(self, id, data):
        """
        Update a logical switch port.
        """
        response = self.get(endpoint="/logical-ports/%s" % id)
        body = response.json()
        body.update(data)
        response = self.put(endpoint="/logical-ports/%s" % id, body=body)
        return response.json()
