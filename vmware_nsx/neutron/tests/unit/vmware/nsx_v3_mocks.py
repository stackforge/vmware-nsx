# Copyright (c) 2015 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from oslo_utils import uuidutils

from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.common import nsx_constants


FAKE_NAME = "fake_name"
DEFAULT_TIER0_ROUTER_UUID = "fake_default_tier0"
FAKE_MANAGER = "fake_manager_ip"


def create_logical_switch(display_name, transport_zone_id, tags,
                          replication_mode=nsx_constants.MTEP,
                          admin_state=nsx_constants.ADMIN_STATE_UP):
    FAKE_TZ_UUID = uuidutils.generate_uuid()
    FAKE_SWITCH_UUID = uuidutils.generate_uuid()

    FAKE_SWITCH = {
        "id": FAKE_SWITCH_UUID,
        "display_name": FAKE_NAME,
        "resource_type": "LogicalSwitch",
        "address_bindings": [],
        "transport_zone_id": FAKE_TZ_UUID,
        "replication_mode": nsx_constants.MTEP,
        "admin_state": nsx_constants.ADMIN_STATE_UP,
        "vni": 50056,
        "switching_profile_ids": [
            {
                "value": "64814784-7896-3901-9741-badeff705639",
                "key": "IpDiscoverySwitchingProfile"
            },
            {
                "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
                "key": "SpoofGuardSwitchingProfile"
            },
            {
                "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
                "key": "PortMirroringSwitchingProfile"
            },
            {
                "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
                "key": "SwitchSecuritySwitchingProfile"
            },
            {
                "value": "f313290b-eba8-4262-bd93-fab5026e9495",
                "key": "QosSwitchingProfile"
            }
        ],
    }
    return FAKE_SWITCH


def create_logical_port(lswitch_id, vif_uuid, tags,
                        attachment_type=nsx_constants.ATTACHMENT_VIF,
                        admin_state=True, name=None, address_bindings=None):
    FAKE_SWITCH_UUID = uuidutils.generate_uuid()
    FAKE_PORT_UUID = uuidutils.generate_uuid()
    FAKE_PORT = {
        "id": FAKE_PORT_UUID,
        "display_name": FAKE_NAME,
        "resource_type": "LogicalPort",
        "address_bindings": [],
        "logical_switch_id": FAKE_SWITCH_UUID,
        "admin_state": nsx_constants.ADMIN_STATE_UP,
        "attachment": {
            "id": "9ca8d413-f7bf-4276-b4c9-62f42516bdb2",
            "attachment_type": "VIF"
        },
        "switching_profile_ids": [
            {
                "value": "64814784-7896-3901-9741-badeff705639",
                "key": "IpDiscoverySwitchingProfile"
            },
            {
                "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
                "key": "SpoofGuardSwitchingProfile"
            },
            {
                "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
                "key": "PortMirroringSwitchingProfile"
            },
            {
                "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
                "key": "SwitchSecuritySwitchingProfile"
            },
            {
                "value": "f313290b-eba8-4262-bd93-fab5026e9495",
                "key": "QosSwitchingProfile"
            }
        ]
    }
    return FAKE_PORT


def get_logical_port(lport_id):
    FAKE_SWITCH_UUID = uuidutils.generate_uuid()
    FAKE_PORT = {
        "id": lport_id,
        "display_name": FAKE_NAME,
        "resource_type": "LogicalPort",
        "address_bindings": [],
        "logical_switch_id": FAKE_SWITCH_UUID,
        "admin_state": nsx_constants.ADMIN_STATE_UP,
        "attachment": {
            "id": "9ca8d413-f7bf-4276-b4c9-62f42516bdb2",
            "attachment_type": "VIF"
        },
        "switching_profile_ids": [
            {
                "value": "64814784-7896-3901-9741-badeff705639",
                "key": "IpDiscoverySwitchingProfile"
            },
            {
                "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
                "key": "SpoofGuardSwitchingProfile"
            },
            {
                "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
                "key": "PortMirroringSwitchingProfile"
            },
            {
                "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
                "key": "SwitchSecuritySwitchingProfile"
            },
            {
                "value": "f313290b-eba8-4262-bd93-fab5026e9495",
                "key": "QosSwitchingProfile"
            }
        ]
    }
    return FAKE_PORT


def update_logical_port(lport_id, name=None, admin_state=None):
    lport = get_logical_port(lport_id)
    if name:
        lport['display_name'] = name
    if admin_state is not None:
        if admin_state:
            lport['admin_state'] = nsx_constants.ADMIN_STATE_UP
        else:
            lport['admin_state'] = nsx_constants.ADMIN_STATE_DOWN
    return lport


class NsxV3Mock(object):
    def __init__(self, default_tier0_router_uuid=DEFAULT_TIER0_ROUTER_UUID):
        self.logical_routers = {}
        self.logical_router_ports = {}
        self.logical_ports = {}
        if default_tier0_router_uuid:
            self.create_logical_router(
                DEFAULT_TIER0_ROUTER_UUID, None,
                edge_cluster_uuid="fake_edge_cluster_uuid",
                tier_0=True)

    def get_edge_cluster(self, edge_cluster_uuid):
        FAKE_CLUSTER = {
            "id": edge_cluster_uuid,
            "members": [
                {"member_index": 0},
                {"member_index": 1}]}
        return FAKE_CLUSTER

    def create_logical_router(self, display_name, tags,
                              edge_cluster_uuid=None,
                              tier_0=False):
        router_type = (nsx_constants.ROUTER_TYPE_TIER0 if tier_0 else
                       nsx_constants.ROUTER_TYPE_TIER1)
        if display_name == DEFAULT_TIER0_ROUTER_UUID:
            fake_router_uuid = DEFAULT_TIER0_ROUTER_UUID
        else:
            fake_router_uuid = uuidutils.generate_uuid()
        result = {'display_name': display_name,
                  'router_type': router_type,
                  'tags': tags,
                  'id': fake_router_uuid}
        if edge_cluster_uuid:
            result['edge_cluster_uuid'] = edge_cluster_uuid
        self.logical_routers[fake_router_uuid] = result
        return result

    def get_logical_router(self, lrouter_id):
        if lrouter_id in self.logical_routers.keys():
            return self.logical_routers[lrouter_id]
        else:
            raise nsx_exc.ResourceNotFound(manager=FAKE_MANAGER,
                                           operation="get_logical_router")

    def update_logical_router(self, lrouter_id, **kwargs):
        if lrouter_id in self.logical_routers.keys():
            payload = self.logical_routers[lrouter_id]
            for key_name in kwargs.keys():
                payload[key_name] = kwargs[key_name]
            return payload
        else:
            raise nsx_exc.ResourceNotFound(manager=FAKE_MANAGER,
                                           operation="update_logical_router")

    def delete_logical_router(self, lrouter_id):
        if lrouter_id in self.logical_routers.keys():
            del self.logical_routers[lrouter_id]
        else:
            raise nsx_exc.ResourceNotFound(manager=FAKE_MANAGER,
                                           operation="delete_logical_router")

    def get_logical_router_port_by_ls_id(self, logical_switch_id):
        router_ports = []
        for router_port in self.logical_router_ports.values():
            ls_port_id = router_port['linked_logical_switch_port_id']
            port = self.get_logical_port(ls_port_id)
            if port['logical_switch_id'] == logical_switch_id:
                router_ports.append(router_port)
        if len(router_ports) >= 2:
            raise nsx_exc.NsxPluginException(
                err_msg=_("Can't support more than one logical router ports "
                          "on same logical switch %s ") % logical_switch_id)
        elif len(router_ports) == 1:
            return router_ports[0]

    def create_logical_port(self, lswitch_id, vif_uuid, tags,
                            attachment_type=nsx_constants.ATTACHMENT_VIF,
                            admin_state=True, name=None,
                            address_bindings=None):
        FAKE_PORT_UUID = uuidutils.generate_uuid()
        FAKE_PORT = {
            "id": FAKE_PORT_UUID,
            "display_name": FAKE_NAME,
            "resource_type": "LogicalPort",
            "address_bindings": [],
            "logical_switch_id": lswitch_id,
            "admin_state": "UP",
        }
        self.logical_ports[FAKE_PORT_UUID] = FAKE_PORT
        return FAKE_PORT

    def get_logical_port(self, logical_port_id):
        if logical_port_id in self.logical_ports.keys():
            return self.logical_ports[logical_port_id]
        else:
            raise nsx_exc.ResourceNotFound(
                manager=FAKE_MANAGER, operation="get_logical_port")

    def create_logical_router_port(self, logical_router_id,
                                   display_name,
                                   logical_switch_port_id,
                                   resource_type,
                                   address_groups):
        fake_router_port_uuid = uuidutils.generate_uuid()
        body = {'id': fake_router_port_uuid,
                'display_name': display_name,
                'resource_type': resource_type,
                'logical_router_id': logical_router_id,
                'subnets': address_groups,
                'linked_logical_switch_port_id': logical_switch_port_id}
        self.logical_router_ports[fake_router_port_uuid] = body
        return body

    def update_logical_router_port(self, logical_port_id, **kwargs):
        if logical_port_id in self.logical_router_ports.keys():
            payload = self.logical_router_ports[logical_port_id]
            for key_name in kwargs.keys():
                payload[key_name] = kwargs[key_name]
            return payload
        else:
            raise nsx_exc.ResourceNotFound(
                manager=FAKE_MANAGER, operation="update_logical_router_port")

    def delete_logical_router_port(self, logical_port_id):
        if logical_port_id in self.logical_router_ports.keys():
            del self.logical_router_ports[logical_port_id]
        else:
            raise nsx_exc.ResourceNotFound(
                manager=FAKE_MANAGER, operation="update_logical_router_port")
