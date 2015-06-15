from oslo.utils import uuidutils

FAKE_NAME = "fake_name"
FAKE_UUID = uuidutils.generate_uuid()

FAKE_SWITCH = {
    "id": FAKE_UUID,
    "display_name": FAKE_NAME,
    "resource_type": "LogicalSwitch",
    "address_bindings": [],
    "transport_zone_id": "dc9ffa3b-3f7b-4e06-b55e-07ec3ebd5a56",
    "replication_mode": "MTEP",
    "admin_state": "UP",
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

FAKE_PORT_UUID = uuidutils.generate_uuid()
FAKE_PORT = {
    "id": FAKE_PORT_UUID,
    "display_name": FAKE_NAME,
    "resource_type": "LogicalPort",
    "address_bindings": [],
    "logical_switch_id": "e3360f8a-3392-413e-972c-7aa91647693f",
    "admin_state": "UP",
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

