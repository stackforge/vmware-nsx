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

from oslo_config import cfg
from oslo_log import log
import requests

from neutron.i18n import _LI
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import nsx_constants
from vmware_nsx.neutron.plugins.vmware.common import utils
from vmware_nsx.neutron.plugins.vmware.nsxlib.v3 import client

LOG = log.getLogger(__name__)


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

    result = client.create_resource(resource, body)
    return result.json()


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

    result = client.create_resource(resource, body)
    return result.json()


def delete_logical_port(logical_port_id):
    resource = 'logical-ports/%s?detach=true' % logical_port_id
    client.delete_resource(resource)


def get_logical_port(logical_port_id):
    resource = "logical-ports/%s" % logical_port_id
    result = client.get_resource(resource)
    return result.json()


@utils.retry_upon_exception_nsxv3(requests.exceptions.HTTPError,
                                  max_attempts=cfg.CONF.nsx_v3.retries)
def retry_update_logical_port(payload):
    revised_payload = get_logical_port(payload.get('id'))
    resource = "logical-ports/%s" % payload.get('id')
    revised_payload['display_name'] = payload['display_name']
    revised_payload['admin_state'] = payload['admin_state']
    result = client.update_resource(resource, payload)
    return result.json()


def update_logical_port(lport_id, payload,
                        name=None, admin_state=None):
    resource = "logical-ports/%s" % lport_id
    if name is not None:
        payload['display_name'] = name
    if admin_state is not None:
        if admin_state:
            payload['admin_state'] = "UP"
        else:
            payload['admin_state'] = "DOWN"
    # If revision_id of the payload that we send is older than what NSX has
    # then we will get a 412: Precondition Failed. In that case we need to
    # re-fetch, patch the response and send it again with the new revision_id
    try:
        result = client.update_resource(resource, payload)
        return result.json
    except requests.exceptions.HTTPError:
        return retry_update_logical_port(payload)


def create_logical_router(display_name, edge_cluster_uuid, tags, tier_0=False):
    # TODO(salv-orlando): If possible do not manage edge clusters in the main
    # plugin logic.
    router_type = (nsx_constants.ROUTER_TYPE_TIER0 if tier_0 else
                   nsx_constants.ROUTER_TYPE_TIER1)
    resource = 'logical-routers'
    body = {'edge_cluster_id': edge_cluster_uuid,
            'display_name': display_name,
            'router_type': router_type,
            'tags': tags}
    result = client.create_resource(resource, body)
    return result.json()


def delete_logical_router(lrouter_id):
    resource = 'logical-routers/%s/' % lrouter_id

    # TODO(salv-orlando): Must handle connection exceptions
    result = client.delete_resource(resource)
    if result.status_code == requests.codes.not_found:
        LOG.info(_LI("Logical router %s not found on NSX backend"), lrouter_id)
        raise nsx_exc.LogicalRouterNotFound(entity_id=lrouter_id)


def create_logical_router_port(logical_router_id,
                               logical_switch_port_id,
                               resource_type,
                               cidr_length,
                               ip_address):
    resource = 'logical-router-ports'
    body = {'resource_type': resource_type,
            'logical_router_id': logical_router_id,
            'subnets': [{"prefix_length": cidr_length,
                         "ip_addresses": [ip_address]}],
            'linked_logical_switch_port_id': logical_switch_port_id}

    return client.create_resource(resource, body)


def delete_logical_router_port(logical_port_id):
    resource = 'logical-router-ports/%s?detach=true' % logical_port_id
    client.delete_resource(resource)
