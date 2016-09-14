# Copyright 2016 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

# Admin statuses
ADMIN_STATE_UP = "UP"
ADMIN_STATE_DOWN = "DOWN"

# Replication modes
MTEP = "MTEP"

# Port attachment types
ATTACHMENT_VIF = "VIF"
ATTACHMENT_CIF = "CIF"
ATTACHMENT_LR = "LOGICALROUTER"
ATTACHMENT_DHCP = "DHCP_SERVICE"
ATTACHMENT_MDPROXY = "METADATA_PROXY"

CIF_RESOURCE_TYPE = "CifAttachmentContext"

# NSXv3 L2 Gateway constants
BRIDGE_ENDPOINT = "BRIDGEENDPOINT"

# Router type
ROUTER_TYPE_TIER0 = "TIER0"
ROUTER_TYPE_TIER1 = "TIER1"

LROUTERPORT_UPLINK = "LogicalRouterUplinkPort"
LROUTERPORT_DOWNLINK = "LogicalRouterDownLinkPort"
LROUTERPORT_LINKONTIER0 = "LogicalRouterLinkPortOnTIER0"
LROUTERPORT_LINKONTIER1 = "LogicalRouterLinkPortOnTIER1"

# NSX service type
SERVICE_DHCP = "dhcp"


# NSX-V3 Distributed Firewall constants
class SecurityConstants(object):
    # firewall section types
    LAYER3 = 'LAYER3'

    INSERT_BEFORE = 'insert_before'
    INSERT_BOTTOM = 'insert_bottom'
    INSERT_TOP = 'insert_top'

    # firewall rule actions
    ALLOW = 'ALLOW'
    DROP = 'DROP'
    REJECT = 'REJECT'

    # filtering operators and expressions
    EQUALS = 'EQUALS'
    NSGROUP_SIMPLE_EXP = 'NSGroupSimpleExpression'
    NSGROUP_TAG_EXP = 'NSGroupTagExpression'

    # nsgroup members update actions
    ADD_MEMBERS = 'ADD_MEMBERS'
    REMOVE_MEMBERS = 'REMOVE_MEMBERS'

    NSGROUP = 'NSGroup'
    LOGICAL_SWITCH = 'LogicalSwitch'
    LOGICAL_PORT = 'LogicalPort'
    IPV4ADDRESS = 'IPv4Address'
    IPV6ADDRESS = 'IPv6Address'

    IN = 'IN'
    OUT = 'OUT'
    IN_OUT = 'IN_OUT'

    # NSServices resource types
    L4_PORT_SET_NSSERVICE = 'L4PortSetNSService'
    ICMP_TYPE_NSSERVICE = 'ICMPTypeNSService'
    IP_PROTOCOL_NSSERVICE = 'IPProtocolNSService'

    TCP = 'TCP'
    UDP = 'UDP'
    ICMPV4 = 'ICMPv4'
    ICMPV6 = 'ICMPv6'

    IPV4 = 'IPV4'
    IPV6 = 'IPV6'
    IPV4_IPV6 = 'IPV4_IPV6'

    LOCAL_IP_PREFIX = 'local_ip_prefix'

    LOGGING = 'logging'
