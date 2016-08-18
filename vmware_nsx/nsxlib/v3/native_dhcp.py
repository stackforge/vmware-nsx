# Copyright 2016 VMware, Inc.
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

import netaddr
from neutron_lib.api import validators
from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx._i18n import _LE
from vmware_nsx.common import utils

LOG = logging.getLogger(__name__)


def build_dhcp_server_config(network, subnet, port, project_name):
    # Prepare the configutation for a new logical DHCP server.
    server_ip = "%s/%u" % (port['fixed_ips'][0]['ip_address'],
                           netaddr.IPNetwork(subnet['cidr']).prefixlen)
    dns_servers = subnet['dns_nameservers']
    if not dns_servers or not validators.is_attr_set(dns_servers):
        dns_servers = cfg.CONF.nsx_v3.nameservers
    gateway_ip = subnet['gateway_ip']
    if not validators.is_attr_set(gateway_ip):
        gateway_ip = None

    # The following code is based on _generate_opts_per_subnet() in
    # neutron/agent/linux/dhcp.py. It prepares DHCP options for a subnet.

    # Add route for directly connected network.
    host_routes = [{'network': subnet['cidr'], 'next_hop': '0.0.0.0'}]
    # Copy routes from subnet host_routes attribute.
    LOG.error(_LE("===> ZLATAN ROCK - %s"), hr)
    for hr in subnet['host_routes']:
        if hasattr(hr, 'destination'):
            if hr.destination == constants.IPv4_ANY:
                if not gateway_ip:
                    gateway_ip = hr.nexthop
            else:
                host_routes.append({'network': hr.destination,
                                    'next_hop': hr.nexthop})
        else:
            LOG.error(_LE("======> MISSING - %s"), hr)
    # If gateway_ip is defined, add default route via this gateway.
    if gateway_ip:
        host_routes.append({'network': constants.IPv4_ANY,
                            'next_hop': gateway_ip})

    options = {'option121': {'static_routes': host_routes}}
    name = utils.get_name_and_uuid(network['name'] or 'dhcpserver',
                                   network['id'])
    tags = utils.build_v3_tags_payload(
        network, resource_type='os-neutron-net-id', project_name=project_name)
    return {'name': name,
            'dhcp_profile_id': cfg.CONF.nsx_v3.dhcp_profile_uuid,
            'server_ip': server_ip,
            'dns_servers': dns_servers,
            'domain_name': cfg.CONF.nsx_v3.dns_domain,
            'gateway_ip': gateway_ip,
            'options': options,
            'tags': tags}
