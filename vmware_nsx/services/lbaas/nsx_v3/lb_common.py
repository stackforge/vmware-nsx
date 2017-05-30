# Copyright 2017 VMware, Inc.
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

from neutron.db import l3_db
from neutron.services.flavors import flavors_plugin
from neutron_lib import constants
from neutron_lib import exceptions as n_exc

from vmware_nsx._i18n import _
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import lb_const
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils


def get_tags(plugin, resource_id, resource_type, project_id, project_name):
    resource = {'project_id': project_id,
                'id': resource_id}
    tags = plugin.nsxlib.build_v3_tags_payload(
        resource, resource_type=resource_type,
        project_name=project_name)
    return tags


def get_nsx_resource_binding(client, name, id):
    """
    :param client: nsx resource client
    :param name: name of neutron object
    :param id: id of neutron object
    :return: return the nsx resource id
    """
    nsx_name = utils.get_name_and_uuid(name, id)
    nsx_resource = client.find_by_display_name(nsx_name)
    if nsx_resource:
        return nsx_resource[0]['id']


def get_network_from_subnet(context, plugin, subnet_id):
    subnet = plugin.get_subnet(context, subnet_id)
    if subnet:
        return plugin.get_network(context, subnet['network_id'])


def get_router_from_network(context, plugin, subnet_id):
    subnet = plugin.get_subnet(context, subnet_id)
    network_id = subnet['network_id']
    port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                    'network_id': [network_id]}
    ports = plugin.get_ports(context, filters=port_filters)
    if ports:
        return ports[0]['device_id']


def create_lb_router_interface(context, plugin, lb_id, subnet_id, tenant_id,
                               router_id, vip_address=None, subnet=None):
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
                 'mac_address': constants.ATTR_NOT_SPECIFIED}
    port = plugin.create_port(context, {'port': port_dict})

    ip_addr = port['fixed_ips'][0]['ip_address']
    prefix_len = str(netaddr.IPNetwork(subnet['cidr']).prefixlen)
    display_name = utils.get_name_and_uuid(subnet['name'] or 'subnet',
                                           subnet_id)
    tags = get_tags(plugin, port['id'], lb_const.LR_PORT_TYPE, tenant_id,
                    context.tenant_name)
    tags.append({'scope': 'os-subnet-id', 'tag': subnet['id']})
    nsx_router_id = nsx_db.get_nsx_router_id(context.session, router_id)
    nsx_net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
        context.session, port['id'])
    address_groups = [{'ip_addresses': [ip_addr],
                      'prefix_length': prefix_len}]
    plugin._routerlib.create_logical_router_intf_port_by_ls_id(
        logical_router_id=nsx_router_id,
        display_name=display_name,
        tags=tags,
        ls_id=nsx_net_id,
        logical_switch_port_id=nsx_port_id,
        address_groups=address_groups)


def get_lb_router_id(context, plugin, lb):
    router_client = plugin.nsxlib.logical_router
    name = utils.get_name_and_uuid(lb.name, lb.id)
    tags = get_tags(plugin, lb.id, lb_const.LB_RESOURCE_TYPE, lb.tenant_id,
                    context.project_name)
    edge_cluster_uuid = plugin._get_edge_cluster(plugin._default_tier0_router)
    lb_router = router_client.create(name, tags, edge_cluster_uuid)

    create_lb_router_interface(context, plugin, lb.id, lb.vip_subnet_id,
                               lb.tenant_id, lb_router['id'],
                               vip_address=lb.vip_address)

    return lb_router


def get_lb_flavor_size(flavor_plugin, context, flavor_id):
    if not flavor_id:
        return lb_const.DEFAULT_LB_SIZE
    else:
        flavor = flavors_plugin.FlavorsPlugin.get_flavor(
            flavor_plugin, context, flavor_id)
        flavor_size = flavor['name']
        if flavor_size in lb_const.LB_FLAVOR_SIZES:
            return flavor_size.upper()
        else:
            err_msg = (_("Invalid flavor name %(flavor)s, only 'small', "
                         "'medium', or 'large' are supported") %
                       {'flavor': flavor_size})
            raise n_exc.InvalidInput(error_message=err_msg)


def validate_lb_subnet(context, plugin, subnet_id):
    network = get_network_from_subnet(context, plugin, subnet_id)
    router_id = get_router_from_network(
        context, plugin, subnet_id)
    if network.get('router:external') or router_id:
        return True