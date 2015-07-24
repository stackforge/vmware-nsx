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

import base64
import requests

import pymysql
import pymysql.cursors

from sets import Set

from optparse import OptionParser

requests.packages.urllib3.disable_warnings()

nsxm_rest_client = None
nsxm_db_client = None

parser = OptionParser()


class NSXMDBClient(object):
    """ DB Client """

    db_results = {}
    db_property_result = {}

    def __init__(self, host, user, password, db):
        # Connect to the database
        self.connection = pymysql.connect(host=host,
                                     user=user,
                                     password=password,
                                     db=db,
                                     charset='utf8mb4',
                                     cursorclass=pymysql.cursors.DictCursor)

    def _process_db_response(self, cursor, table, columns):
        result_set = cursor.fetchall()
        self.db_results[table] = []
        for column in columns:
            column_vals = Set()
            for result in result_set:
                column_vals.add(result[column])
            self.db_property_result[column] = column_vals
        self.db_results[table] = self.db_property_result
        return self.db_results

    def get(self, table):
        try:
            with self.connection.cursor() as cursor:
                # Read a single record
                sql = "SELECT * FROM %s" % (table)
                cursor.execute(sql)
                column_names = [column[0] for column in cursor.description]
                return self._process_db_response(cursor, table, column_names)
        finally:
            self.connection.close()


class NSXMRestClient(object):
    """ REST client """

    api_results = {}
    api_property_result = {}

    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.content_type = "application/json"
        self.accept_type = "application/json"
        self.verify = False
        self.secure = True
        self.interface = "json"
        self.url = None
        self.headers = None
        self.__set_headers()

    def get_endpoint(self, secure=None, host=None, endpoint=None):
        secure = self.secure if secure is None else secure
        host = self.host if host is None else host
        http_type = 'https' if secure else 'http'
        return '%s://%s/api/v1/%s' % (http_type, host, endpoint)

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
        url = self.get_endpoint(endpoint=endpoint)
        response = requests.get(url, headers=self.headers,
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

    def process_api_response(self, response):
        response["results"]


# The reason I am not using CfgOpt is I dont want
# the utility to be dependent on eutron packages
# to be installed on the users box


def init_options():
    parser.add_option("--nsxm-ip", dest="nsxm_ip",
                      help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Manager username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Manager password")
    parser.add_option("-r", "--resource-db", dest="resource_db",
                      help="Resource you want to investigate")
    parser.add_option("-o", "--operation", dest="operation",
                      default="get", help="Desired Operation")
    parser.add_option("-l", "--db-host", default="localhost",
                      dest="db_host", help="IP addess of MySQL node")
    parser.add_option("-i", "--db-user", default="root",
                      dest="db_user", help="MySQL db username")
    parser.add_option("-j", "--db-pass", default="password",
                      dest="db_pass", help="MySQL db password")
    parser.add_option("-k", "--db-name", default="neutron",
                      dest="db_name", help="MySQL db name")
    parser.add_option("-m", "--datasource", default="all",
                      dest="data_source", help="NSX or Neutron db")
    parser.add_option("-n", "--resource-api-endpoint",
                      dest="resource_api_endpoint",
                      help="Resource API endpoint")


def query_db(utility, options):
    return utility.get_db_client().get(options.resource_db)


def query_api(utility, options):
    r = utility.get_rest_client().get(options.resource_api_endpoint)
    return r.json()


def extract_db_ids(db_result, options):
    return db_result[options.resource_db]["id"]


def extract_api_ids(api_response, options):
    ids = Set()
    for result in api_response["results"]:
        ids.add(result["id"])
    return ids

# TODO(gangila): Fix this
# def cleanup_resource(utility, api_ids, db_ids)
#    difference = api_ids - db_ids
#    utility.get_rest_client.delete(options.resource_api_endpoint, difference)


class Init(object):
    def __init__(self, options, args):
        self.nsxm_rest_client = NSXMRestClient(options.nsxm_ip,
                                               options.username,
                                               options.password)

        self.nsxm_db_client = NSXMDBClient(options.db_host,
                                           options.db_user,
                                           options.db_pass,
                                           options.db_name)

    def get_db_client(self):
        return self.nsxm_db_client

    def get_rest_client(self):
        return self.nsxm_rest_client

if __name__ == "__main__":
    init_options()
    (options, args) = parser.parse_args()
    utility = Init(options, args)

    print "db ids"
    print extract_db_ids(query_db(utility, options), options)
    print "api ids"
    print extract_api_ids(query_api(utility, options), options)
