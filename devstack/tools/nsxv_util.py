#!/usr/bin/env python

"""
Purpose: Sometimes NSXv backend are out of sync with OpenStack and all
the objects created by OpenStack needs to be cleaned up.

This is a util script to cleanup NSXv objects created by OpenStack
List of objects to be cleared:
    - Edge (Service Edge, DHCP Edge, VDR Edge)
    - Logical Switches (Tenant Networks)
    - Firewall Rules (Security Group)

Usage:
    python nsxv_cleanup.py --vsm-ip <nsx-manager-ip>
                           --username <nsx-manager-username>
                           --password <nsx-manager-password>
                           --force
Note: force is optional. If it is specified, force delete security group

You can also use it in python interactive console by import the module
>>>> import nsxv_cleanup
>>>> vsm = nsxv_cleanup.VSMClient('10.34.57.101', 'admin', 'default')
Cleanup all logical switch
>>>> vsm.cleanup_logical_switch()
Cleanup all firewall section
>>>> vsm.cleanup_firewall_section()
Cleanup all security group
>>>> vsm.cleanup_security_group()
Cleanup all edges
>>>> vsm.cleanup_edge()
Cleanup all
>>>> vsm.cleanup_all()

If you have any comment or find a bug, please contact
Tong Liu <tongl@vmware.com>
"""

from abc import ABCMeta, abstractmethod

import base64
import json
import math
import requests
import sys

requests.packages.urllib3.disable_warnings()

vsm_client = None

class BaseResource():

    __metaclass__ = ABCMeta

    @abstractmethod
    def read_endpoint():
        pass

    @abstractmethod
    def delete_endpoint():
        pass

    @abstractmethod
    def get_name(obj):
        pass

    @abstractmethod
    def get_id(obj):
        pass

    @abstractmethod
    def process_response(response):
        pass
    

class FirewallSection(BaseResource):

    CONSTANT = 'firewall section'
    API_VERSION = '4.0'

    @staticmethod
    def read_endpoint():
        return '/firewall/globalroot-0/config'

    @staticmethod
    def delete_endpoint():
        return '/firewall/globalroot-0/config/layer3sections/%s'

    @staticmethod
    def name(obj):
        return obj['name']

    @staticmethod
    def id(obj):
        return obj['id']

    @staticmethod
    def process_response(response):
        l3_sections = response.json()['layer3Sections']['layer3Sections']
        firewall_sections = [s for s in l3_sections if s['name'] !=
                             "Default Section Layer3"]
        return firewall_sections


class SecurityGroup(BaseResource):

    CONSTANT = 'security group'
    API_VERSION = '2.0'

    @staticmethod
    def read_endpoint():
        return '/services/securitygroup/scope/globalroot-0'

    @staticmethod
    def delete_endpoint():
        return '/services/securitygroup/%s'

    @staticmethod
    def name(obj):
        return obj['name']

    @staticmethod
    def id(obj):
        return obj['objectId']

    @staticmethod
    def process_response(response):
        sg_all = response.json()
        # Remove Activity Monitoring Data Collection, which is not
        # related to any security group created by OpenStack
        security_groups = [sg for sg in sg_all if
                           sg['name'] != "Activity Monitoring Data Collection"]
        return security_groups


class SpoofguardPolicies(BaseResource):

    CONSTANT = 'spoofguard policies'
    API_VERSION = '4.0'

    @staticmethod
    def read_endpoint():
        return '/services/spoofguard/policies/'

    @staticmethod
    def delete_endpoint():
        return '/services/spoofguard/policies/%s'

    @staticmethod
    def name(obj):
        return obj['name']

    @staticmethod
    def id(obj):
        return obj['policyId']

    @staticmethod
    def process_response(response):
        sgp_all = response.json()
        policies = [sgp for sgp in sgp_all['policies'] if
                    sgp['name'] != 'Default Policy']
        return policies

class Edge(BaseResource):
    
    CONSTANT = 'edge'
    API_VERSION = '4.0'

    @staticmethod
    def read_endpoint():
        return '/edges'

    @staticmethod
    def delete_endpoint():
        return '/edges/%s'

    @staticmethod
    def name(obj):
        return obj['name']

    @staticmethod
    def id(obj):
        return obj['id']

    @staticmethod
    def process_response(response):
        edges = []
        paging_info = response.json()['edgePage']['pagingInfo']
        page_size = int(paging_info['pageSize'])
        total_count = int(paging_info['totalCount'])
        print "There are total %s edges and page size is %s" % (
            total_count, page_size)
        pages = 0 if page_size == 0 else int(math.ceil(float(total_count) / page_size))
        print "Total pages: %s" % pages
        for i in range(0, pages):
            start_index = page_size * i
            params = {'startindex': start_index}
            response = self.get(params=params)
            temp_edges = response.json()['edgePage']['data']
            edges += temp_edges
        return edges

class Util(object):
    @staticmethod
    def get_vdn_scope_id():
        """
        Retrieve existing network scope id
        """

        vsm_client.set_api_version('2.0');
        vsm_client.set_endpoint("/vdn/scopes")
        response = vsm_client.get();
        if len(response.json()['allScopes']) == 0:
            return
        else:
            return response.json()['allScopes'][0]['objectId']
   

class LogicalSwitch(BaseResource):

    CONSTANT = 'logical switch'
    API_VERSION = '2.0'
    
    @staticmethod
    def read_endpoint():
        vdn_scope_id = Util.get_vdn_scope_id()
        return '/vdn/scopes/%s/virtualwires' % (vdn_scope_id)

    @staticmethod
    def delete_endpoint():
        return '/vdn/virtualwires/%s'

    @staticmethod
    def name(obj):
        return obj['name']

    @staticmethod
    def id(obj):
        return obj['objectId']

    @staticmethod
    def process_response(response):
        lswitches = []
        paging_info = response.json()['dataPage']['pagingInfo']
        page_size = int(paging_info['pageSize'])
        total_count = int(paging_info['totalCount'])
        print "There are total %s logical switches and page size is %s" % ( 
              total_count, page_size)
        pages = 0 if page_size == 0 else int(math.ceil(float(total_count) / page_size))
        print "Total pages: %s" % pages
        for i in range(0, pages):
            start_index = page_size * i 
            params = {'startindex': start_index}
            response = self.get(params=params)
            temp_lswitches = response.json()['dataPage']['data']
            lswitches += temp_lswitches
        return lswitches

class VSMClient(object):
    """ Base VSM REST client """
    API_VERSION = "2.0"

    def __init__(self, host, username, password, *args, **kwargs):
        self.force = True if 'force' in kwargs else False
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
        self.api_version = VSMClient.API_VERSION

        self.__set_headers()

    def set_endpoint(self, endpoint):
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

    def set_api_version(self, api_version):
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
        self.__set_headers()
        response = requests.post(self.url, headers=self.headers,
                                 verify=self.verify, data=json.dumps(body))
        return response




    def cleanup(self, BaseResource):
        print "Clean up %s(s) on NSX manager\n" % BaseResource.CONSTANT
        resource_list = self.query_all(BaseResource)
        print "There are total %d %s(s)\n" % (len(resource_list), BaseResource.CONSTANT)
        for each_resource in resource_list:
            print "Deleting %s %s (%s) ..." %(BaseResource.CONSTANT, BaseResource.name(each_resource), BaseResource.id(each_resource))
            response = self.delete(endpoint= (BaseResource.delete_endpoint() % BaseResource.id(each_resource)))
            if response.status_code != 200:
                print "ERROR: response status code %s" % response.status_code


    def query_all(self, BaseResource):
        resource_list = []
 
        self.set_api_version(BaseResource.API_VERSION)
 
        response = self.get(BaseResource.read_endpoint())
        if response.status_code is 200:
            resource_list = BaseResource.process_response(response)
        else:
            print "ERROR: wrong response status code! Exiting..."
            sys.exit()

        return resource_list


    def cleanup_all(self):
        self.cleanup(FirewallSection)
        self.cleanup(SecurityGroup)
        self.cleanup(SpoofguardPolicies)
        self.cleanup(Edge)
        self.cleanup(LogicalSwitch)


if __name__ == "__main__":
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("--vsm-ip", dest="vsm_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Manager username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Manager password")
    parser.add_option("-f", "--force", dest="force", action="store_true",
                      help="Force cleanup option")
    (options, args) = parser.parse_args()
    print "vsm-ip: %s" % options.vsm_ip
    print "username: %s" % options.username
    print "password: %s" % options.password
    print "force: %s" % options.force

    # Get VSM REST client
    if options.force:
        vsm_client = VSMClient(options.vsm_ip, options.username,
                               options.password, force=options.force)
    else:
        vsm_client = VSMClient(options.vsm_ip, options.username,
                               options.password)
    # Clean all objects created by OpenStack
    vsm_client.cleanup_all()
