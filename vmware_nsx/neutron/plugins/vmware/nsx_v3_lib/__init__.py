# Copyright 2015 OpenStack Foundation
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

import json

from oslo_config import cfg
import requests
from requests import auth


def _get_controller():
    # For now only work with one controller
    controller = cfg.CONF.nsx_v3.nsx_controllers[0]
    return "https://" + controller


def create_logical_switch(display_name, transport_zone_id,
                          replication_mode="MTEP", admin_state="UP"):

    controller = _get_controller()
    url = controller + "/api/v1/logical-switches"
    headers = {'Content-Type': 'application/json'}
    body = {'transport_zone_id': transport_zone_id,
            'replication_mode': replication_mode,
            'admin_state': admin_state,
            'display_name': display_name}

    # XXXX error handling
    result = requests.post(url, auth=auth.HTTPBasicAuth('admin', 'default'),
                           verify=False, headers=headers,
                           data=json.dumps(body))
    if result.status_code != requests.codes.created:
        raise Exception("ERROR")
    return result.json()


def delete_logical_switch(lswitch_id):
    controller = _get_controller()
    url = controller + "/api/v1/logical-switches/%s/" % lswitch_id
    headers = {'Content-Type': 'application/json'}
    result = requests.delete(url, auth=auth.HTTPBasicAuth('admin', 'default'),
                             verify=False, headers=headers)

    if result.status_code != requests.codes.ok:
        raise Exception("ERROR")


def create_logical_port(id, lswitch_id, vif_uuid, attachment_type="VIF",
                        admin_state="UP"):

    controller = _get_controller()
    url = controller + "/api/v1/logical-ports"
    headers = {'Content-Type': 'application/json'}
    body = {'logical_switch_id': lswitch_id,
            'id': id,
            'attachment': {"attachment_type": attachment_type,
                           "id": vif_uuid},
            'admin_state': admin_state}

    # XXXX error handling
    result = requests.post(url, auth=auth.HTTPBasicAuth('admin', 'default'),
                           verify=False, headers=headers,
                           data=json.dumps(body))
    if result.status_code != requests.codes.created:
        raise Exception("ERROR")
    return result.json()


def delete_logical_port(logical_port):
    controller = _get_controller()
    url = controller + "/api/v1/logical-ports/%s?detach=true" % logical_port
    headers = {'Content-Type': 'application/json'}
    result = requests.delete(url, auth=auth.HTTPBasicAuth('admin', 'default'),
                             verify=False, headers=headers)

    if result.status_code != requests.codes.ok:
        raise Exception("ERROR")


def create_logical_router(display_name, router_id, router_type,
                          edge_cluster_uuid):
    controller = _get_controller()
    url = controller + "/api/v1/logical-routers"
    headers = {'Content-Type': 'application/json'}
    body = {'id': router_id,
            'edge_cluster_id': edge_cluster_uuid,
            'display_name': display_name,
            'router_type': router_type}

    # XXXX error handling
    result = requests.post(url, auth=auth.HTTPBasicAuth('admin', 'default'),
                           verify=False, headers=headers,
                           data=json.dumps(body))
    if result.status_code != requests.codes.created:
        print result.status_code
        raise Exception("ERROR")

    print result
    return result.json()


def create_logical_router_port(id, display_name,  resource_type,
                               edge_cluster_uuid):
    controller = _get_controller()
    url = controller + "/api/v1/logical-routers"
    headers = {'Content-Type': 'application/json'}
    body = {'id': router_id,
            'edge_cluster_id': edge_cluster_uuid,
            'display_name': display_name,
            'router_type': router_type}

    # XXXX error handling
    result = requests.post(url, auth=auth.HTTPBasicAuth('admin', 'default'),
                           verify=False, headers=headers,
                           data=json.dumps(body))
    if result.status_code != requests.codes.created:
        print result.status_code
        raise Exception("ERROR")

    print result
    return result.json()

