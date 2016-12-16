# Copyright 2015 VMware, Inc.
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
from neutron_lib import constants

from vmware_nsx.common import locking
from vmware_nsx.plugins.nsx_v.vshield import edge_utils

MEMBER_ID_PFX = 'member-'


def get_lb_resource_id(lb_id):
    return ('lbaas-' + lb_id)[:36]


def get_lb_interface(context, plugin, lb_id, subnet_id):
    filters = {'fixed_ips': {'subnet_id': [subnet_id]},
               'device_id': [lb_id],
               'device_owner': [constants.DEVICE_OWNER_NEUTRON_PREFIX + 'LB']}

    lb_ports = plugin.get_ports(context.elevated(), filters=filters)
    return lb_ports


def create_lb_interface(context, plugin, lb_id, subnet_id, tenant_id,
                        vip_addr=None, subnet=None):
    if not subnet:
        subnet = plugin.get_subnet(context, subnet_id)
    network_id = subnet.get('network_id')

    port_dict = {'name': 'lb_if-' + lb_id,
                 'admin_state_up': True,
                 'network_id': network_id,
                 'tenant_id': tenant_id,
                 'fixed_ips': [{'subnet_id': subnet['id']}],
                 'device_owner': constants.DEVICE_OWNER_NEUTRON_PREFIX + 'LB',
                 'device_id': lb_id,
                 'mac_address': constants.ATTR_NOT_SPECIFIED
                 }
    port = plugin.base_create_port(context, {'port': port_dict})
    ip_addr = port['fixed_ips'][0]['ip_address']
    net = netaddr.IPNetwork(subnet['cidr'])
    resource_id = get_lb_resource_id(lb_id)

    address_groups = [{'primaryAddress': ip_addr,
                       'subnetPrefixLength': str(net.prefixlen),
                       'subnetMask': str(net.netmask)}]

    if vip_addr:
        address_groups[0]['secondaryAddresses'] = {
            'type': 'secondary_addresses', 'ipAddress': [vip_addr]}

    edge_utils.update_internal_interface(
        plugin.nsx_v, context, resource_id,
        network_id, address_groups)


def delete_lb_interface(context, plugin, lb_id, subnet_id):
    resource_id = get_lb_resource_id(lb_id)
    subnet = plugin.get_subnet(context, subnet_id)
    network_id = subnet.get('network_id')
    lb_ports = get_lb_interface(context, plugin, lb_id, subnet_id)
    for lb_port in lb_ports:
        plugin.delete_port(context, lb_port['id'])

    edge_utils.delete_interface(plugin.nsx_v, context, resource_id, network_id,
                                dist=False)


def extract_resource_id(location_uri):
    """
    Edge assigns an ID for each resource that is being created:
    it is postfixes the uri specified in the Location header.
    This ID should be used while updating/deleting this resource.
    """
    uri_elements = location_uri.split('/')
    return uri_elements[-1]


def set_lb_firewall_default_rule(vcns, edge_id, action):
    with locking.LockManager.get_lock(edge_id):
        vcns.update_firewall_default_policy(edge_id, {'action': action})


def add_vip_fw_rule(vcns, edge_id, vip_id, ip_address):
    fw_rule = {
        'firewallRules': [
            {'action': 'accept', 'destination': {
                'ipAddress': [ip_address]},
             'enabled': True,
             'name': vip_id}]}

    with locking.LockManager.get_lock(edge_id):
        h = vcns.add_firewall_rule(edge_id, fw_rule)[0]
    fw_rule_id = extract_resource_id(h['location'])

    return fw_rule_id


def del_vip_fw_rule(vcns, edge_id, vip_fw_rule_id):
    with locking.LockManager.get_lock(edge_id):
        vcns.delete_firewall_rule(edge_id, vip_fw_rule_id)
