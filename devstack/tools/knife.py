#!/usr/bin/env python

"""
Purpose of this script is to build a framework which can be leveraged
to build utilities to help the on-field ops in system debugging.

We support the following functions for now:
* Be able to read the database and configuration files.
* Be able to access the backend via API
* Compare data from different sources and decide next course of 
  action.

If you have any comment or find a bug, please contact
Akash Gangil <gangila@vmware.com>  
"""

import abc
import base64
import json
import math
import requests
import six
import sys

import neutron.db.api as db
from neutron.db import model_base

requests.packages.urllib3.disable_warnings()

vsm_client = None

#Options code here

class VSMDBClient(object):
    def __init__(self):
        self.session = db.get_session()
    
    def get_resource_by_id(model, resource_filter, resource_filter_id):
        return session.query(model).filter_by(
            resource_filter=resource_filter_id).all()


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


# Callback functions
def cleanup(self, BaseResource):
    print "Clean up %s(s) on NSX manager\n" % BaseResource.NAME
    resource_list = self.query_all(BaseResource)
    print "There are total %d %s(s)\n" % (len(resource_list), BaseResource.NAME)
    for each_resource in resource_list:
        print "Deleting %s %s (%s) ..." %(BaseResource.NAME, BaseResource.name(each_resource), BaseResource.id(each_resource))
        response = self.delete(endpoint= (BaseResource.delete_endpoint() % BaseResource.id(each_resource)))
        if response.status_code != 200:
            print "ERROR: response status code %s" % response.status_code


def query(self, BaseResource):
    resource_list = []
    self.set_api_version(BaseResource.API_VERSION)
    response = self.get(BaseResource.read_endpoint())
    if response.status_code is 200:
        resource_list = BaseResource.process_response(response)
    else:
        print "ERROR: wrong response status code! Exiting..."
        sys.exit()
    return resource_list



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
    parser.add_option("-r", "--resource", dest="resource", 
                      help="Resource you want to investigate")
    parser.add_option("-o", "--operation", dest="operation",
                      help="Desired Operation")


    (options, args) = parser.parse_args()
    print "vsm-ip: %s" % options.vsm_ip
    print "username: %s" % options.username
    print "password: %s" % options.password
    print "force: %s" % options.force
    print "resource: %s" % options.resource
    print "operation: %s" % options.operation

    # Get VSM REST client
    if options.force:
        vsm_client = VSMClient(options.vsm_ip, options.username,
                               options.password, force=options.force)
    else:
        vsm_client = VSMClient(options.vsm_ip, options.username,
                               options.password)
    # Clean all objects created by OpenStack
    vsm_client.cleanup_all()
