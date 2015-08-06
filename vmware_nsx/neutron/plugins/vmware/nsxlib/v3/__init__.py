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

from oslo_log import log

from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import nsx_constants
from vmware_nsx.neutron.plugins.vmware.common import utils
from vmware_nsx.neutron.plugins.vmware.nsxlib.v3 import client

LOG = log.getLogger(__name__)


def get_edge_cluster(edge_cluster_uuid):
    resource = "edge-clusters/%s" % edge_cluster_uuid
    return client.get_resource(resource)


@utils.retry_upon_exception_nsxv3(nsx_exc.StaleRevision,
                                  max_attempts=10)
def update_resource_with_retry(resource, payload):
    revised_payload = client.get_resource(resource)
    for key_name in payload.keys():
        revised_payload[key_name] = payload[key_name]
    return client.update_resource(resource, revised_payload)


def create_logical_switch(display_name, transport_zone_id, tags,
                          replication_mode=nsx_constants.MTEP,
                          admin_state=nsx_constants.ADMIN_STATE_UP):
    # TODO(salv-orlando): Validate Replication mode and admin_state
    # NOTE: These checks might be moved to the API client library if one that
    # performs such checks in the client is available

    resource = 'logical-switches'
    body = {'transport_zone_id': transport_zone_id,
            'replication_mode': replication_mode,
            'admin_state': admin_state,
            'display_name': display_name,
            'tags': tags}

    return client.create_resource(resource, body)


def delete_logical_switch(lswitch_id):
    resource = 'logical-switches/%s?detach=true&cascade=true' % lswitch_id
    client.delete_resource(resource)


def create_logical_port(lswitch_id, vif_uuid, tags,
                        attachment_type=nsx_constants.ATTACHMENT_VIF,
                        admin_state=True, name=None, address_bindings=None):

    resource = 'logical-ports'
    body = {'logical_switch_id': lswitch_id,
            'attachment': {'attachment_type': attachment_type,
                           'id': vif_uuid},
            'tags': tags}
    if name:
        body['display_name'] = name
    if admin_state:
        body['admin_state'] = nsx_constants.ADMIN_STATE_UP
    else:
        body['admin_state'] = nsx_constants.ADMIN_STATE_DOWN

    if address_bindings:
        body['address_bindings'] = address_bindings

    return client.create_resource(resource, body)


def delete_logical_port(logical_port_id):
    resource = 'logical-ports/%s?detach=true' % logical_port_id
    client.delete_resource(resource)


def create_logical_router(display_name, tags,
                          edge_cluster_uuid=None, tier_0=False):
    # TODO(salv-orlando): If possible do not manage edge clusters in the main
    # plugin logic.
    router_type = (nsx_constants.ROUTER_TYPE_TIER0 if tier_0 else
                   nsx_constants.ROUTER_TYPE_TIER1)
    resource = 'logical-routers'
    body = {'display_name': display_name,
            'router_type': router_type,
            'tags': tags}
    if edge_cluster_uuid:
        body['edge_cluster_uuid'] = edge_cluster_uuid
    return client.create_resource(resource, body)


def get_logical_router(lrouter_id):
    resource = 'logical-routers/%s' % lrouter_id
    return client.get_resource(resource)


def update_logical_router(lrouter_id, **kwargs):
    resource = 'logical-routers/%s' % lrouter_id
    return update_resource_with_retry(resource, kwargs)


def delete_logical_router(lrouter_id):
    resource = 'logical-routers/%s/' % lrouter_id

    # TODO(salv-orlando): Must handle connection exceptions
    return client.delete_resource(resource)


def get_logical_router_ports_by_name(logical_router_id, display_name):
    resource = 'logical-router-ports?logical_router_id=%s' % logical_router_id
    router_ports = client.get_resource(resource)
    return [port
            for port in router_ports if port['display_name'] == display_name]


def create_logical_router_port_by_name(logical_router_id,
                                       display_name,
                                       logical_switch_port_id,
                                       resource_type,
                                       address_groups):
    ports = get_logical_router_ports_by_name(
        logical_router_id, display_name)
    if ports:
        return update_logical_router_port(ports[0]['id'],
                                          subnets=address_groups)
    resource = 'logical-router-ports'
    body = {'display_name': display_name,
            'resource_type': resource_type,
            'logical_router_id': logical_router_id,
            'subnets': address_groups,
            'linked_logical_switch_port_id': logical_switch_port_id}

    return client.create_resource(resource, body)


def create_logical_router_port(logical_router_id,
                               display_name,
                               logical_switch_port_id,
                               resource_type,
                               address_groups):
    resource = 'logical-router-ports'
    body = {'display_name': display_name,
            'resource_type': resource_type,
            'logical_router_id': logical_router_id,
            'subnets': address_groups,
            'linked_logical_switch_port_id': logical_switch_port_id}

    return client.create_resource(resource, body)


def update_logical_router_port_by_name(logical_router_id, display_name,
                                       **payload):
    ports = get_logical_router_ports_by_name(
        logical_router_id, display_name)
    if not ports:
        raise nsx_exc.ResourceNotFound(manager=None,
                                       operation="update router port")
    else:
        return update_logical_router_port(ports[0]['id'], **payload)


def update_logical_router_port(logical_port_id, **kwargs):
    resource = 'logical-router-ports/%s?detach=true' % logical_port_id
    return update_resource_with_retry(resource, kwargs)


def delete_logical_router_port_by_name(logical_router_id, display_name):
    ports = get_logical_router_ports_by_name(
        logical_router_id, display_name)
    if not ports:
        raise nsx_exc.ResourceNotFound(manager=None,
                                       operation="update router port")
    else:
        return delete_logical_router_port(ports[0]['id'])


def delete_logical_router_port(logical_port_id):
    resource = 'logical-router-ports/%s?detach=true' % logical_port_id
    client.delete_resource(resource)


def create_qos_switching_profile(qos_marking, dscp, tags, name=None,
                                 description=None):
    resource = 'switching-profiles'
    body = {"resource_type": "QosSwitchingProfile",
            "tags": tags,
            "dscp": {"priority": dscp,
                     "mode": qos_marking.upper()}}
    # TODO(abhide): Add TrafficShaper configuration.
    if name:
        body["display_name"] = name
    if description:
        body["description"] = description
    return client.create_resource(resource, body)


def get_qos_switching_profile(profile_id):
    resource = 'switching-profiles/%s' % profile_id
    return client.get_resource(resource)


def delete_qos_switching_profile(profile_id):
    resource = 'switching-profiles/%s' % profile_id
    return client.delete_resource(resource)
