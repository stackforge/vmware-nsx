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

import sys
import json
import base64
import requests

requests.packages.urllib3.disable_warnings()


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
        self.content_type = "applicatioon/json"
        self.accept_type = "application/json"
        self.verify = False
        self.secure = True
        self.interface = "json"
        self.url = None
        self.headers = None
        self.api_version = VSMClient.API_VERSION

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

    # TODO(Tong): Get exact vdnscope-id instead using of default one
    def query_all_logical_switches(self):
        lswitches = []
        self.__set_api_version('2.0')
        self.__set_endpoint("/vdn/scopes/vdnscope-1/virtualwires")
        # Query all logical switches
        response = self.get()
        paging_info = response.json()['dataPage']['pagingInfo']
        page_size = int(paging_info['pageSize'])
        total_count = int(paging_info['totalCount'])
        print "There are total %s logical switches and page size is %s" % (
            total_count, page_size)
        pages = ceil(total_count, page_size)
        print "Total pages: %s" % pages
        for i in range(0, pages):
            start_index = page_size * i
            params = {'startindex': start_index}
            response = self.get(params=params)
            temp_lswitches = response.json()['dataPage']['data']
            lswitches += temp_lswitches

        return lswitches

    def cleanup_logical_switch(self):
        print "Cleaning up logical switches on NSX manager"
        lswitches = self.query_all_logical_switches()
        print "There are total %s logical switches" % len(lswitches)
        for ls in lswitches:
            print "\nDeleting logical switch %s (%s) ..." % (ls['name'],
                                                             ls['objectId'])
            endpoint = '/vdn/virtualwires/%s' % ls['objectId']
            response = self.delete(endpoint=endpoint)
            if response.status_code != 200:
                print "ERROR: reponse status code %s" % response.status_code

    def query_all_firewall_sections(self):
        firewall_sections = []
        self.__set_api_version('4.0')
        self.__set_endpoint('/firewall/globalroot-0/config')
        # Query all firewall sections
        response = self.get()
        # Get layer3 sections related to security group
        if response.status_code is 200:
            l3_sections = response.json()['layer3Sections']['layer3Sections']
            firewall_sections = [s for s in l3_sections if s['name'] !=
                                 "Default Section Layer3"]
        else:
            print "ERROR: wrong response status code! Exiting..."
            sys.exit()

        return firewall_sections

    def cleanup_firewall_section(self):
        print "\n\nCleaning up firewall sections on NSX manager"
        l3_sections = self.query_all_firewall_sections()
        print "There are total %s firewall sections" % len(l3_sections)
        for l3sec in l3_sections:
            print "\nDeleting firewall section %s (%s) ..." % (l3sec['name'],
                                                               l3sec['id'])
            endpoint = '/firewall/globalroot-0/config/layer3sections/%s' % \
                       l3sec['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code != 200:
                print "ERROR: reponse status code %s" % response.status_code

    def query_all_security_groups(self):
        security_groups = []
        self.__set_api_version('2.0')
        self.__set_endpoint("/services/securitygroup/scope/globalroot-0")
        # Query all security groups
        response = self.get()
        if response.status_code is 200:
            sg_all = response.json()
        else:
            print "ERROR: wrong response status code! Exiting..."
            sys.exit()
        # Remove Activity Monitoring Data Collection, which is not
        # related to any security group created by OpenStack
        security_groups = [sg for sg in sg_all if
                           sg['name'] != "Activity Monitoring Data Collection"]
        return security_groups

    def cleanup_security_group(self):
        print "\n\nCleaning up security groups on NSX manager"
        security_groups = self.query_all_security_groups()
        print "There are total %s security groups" % len(security_groups)
        for sg in security_groups:
            print "\nDeleting security group %s (%s) ..." % (sg['name'],
                                                             sg['objectId'])
            endpoint = '/services/securitygroup/%s' % sg['objectId']
            params = {'force': self.force}
            response = self.delete(endpoint=endpoint, params=params)
            if response.status_code != 200:
                print "ERROR: reponse status code %s" % response.status_code

    def query_all_spoofguard_policies(self):
        self.__set_api_version('4.0')
        self.__set_endpoint("/services/spoofguard/policies/")
        # Query all spoofguard policies
        response = self.get()
        if response.status_code is not 200:
            print "ERROR: Faield to get spoofguard policies"
            return
        sgp_all = response.json()
        policies = [sgp for sgp in sgp_all['policies'] if
                    sgp['name'] != 'Default Policy']
        return policies

    def cleanup_spoofguard_policies(self):
        print "\n\nCleaning up spoofguard policies"
        policies = self.query_all_spoofguard_policies()
        print "There are total %s policies" % len(policies)
        for spg in policies:
            print "\nDeleting spoofguard policy %s (%s) ..." % (spg['name'],
                                                                spg['policyId'])
            endpoint = '/services/spoofguard/%s' % spg['policyId']
            response = self.delete(endpoint=endpoint)
            print "Response code: %s" % response.status_code

    def query_all_edges(self):
        edges = []
        self.__set_api_version('4.0')
        self.__set_endpoint("/edges")
        # Query all edges
        response = self.get()
        paging_info = response.json()['edgePage']['pagingInfo']
        page_size = int(paging_info['pageSize'])
        total_count = int(paging_info['totalCount'])
        print "There are total %s edges and page size is %s" % (
            total_count, page_size)
        pages = ceil(total_count, page_size)
        print "Total pages: %s" % pages
        for i in range(0, pages):
            start_index = page_size * i
            params = {'startindex': start_index}
            response = self.get(params=params)
            temp_edges = response.json()['edgePage']['data']
            edges += temp_edges

        return edges

    def cleanup_edge(self):
        print "\n\nCleaning up edges on NSX manager"
        edges = self.query_all_edges()
        for edge in edges:
            print "\nDeleting edge %s (%s) ..." % (edge['name'], edge['id'])
            endpoint = '/edges/%s' % edge['id']
            response = self.delete(endpoint=endpoint)
            if response.status_code != 200:
                print "ERROR: reponse status code %s" % response.status_code

    def cleanup_all(self):
        self.cleanup_logical_switch()
        self.cleanup_firewall_section()
        self.cleanup_security_group()
        self.cleanup_spoofguard_policies()
        self.cleanup_edge()


def ceil(a, b):
    if b == 0:
        return 0
    div = a / b
    mod = 0 if a % b is 0 else 1
    return div + mod


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
