import uuid

FAKE_NAME = "fake_name"
FAKE_UUID = str(uuid.uuid4())

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

