# Copyright 2017 VMware, Inc.  All rights reserved.
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

from oslo_config import cfg
from oslo_log import log as logging
from neutron_lib.callbacks import registry
from neutron_lib import context as neutron_context
from neutron_dynamic_routing.db import bgp_db
from vmware_nsx.common import nsxv_constants
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vsh_constants
from vmware_nsx.plugins.nsx_v.vshield import vcns_driver
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
import vmware_nsx.shell.resources as shell


LOG = logging.getLogger(__name__)
bgpdb = bgp_db.BgpDbMixin()
nsxv = vcns_driver.VcnsDriver([])


def get_ip_prefix(name, ip_address):
    return {'ipPrefix': {'name': name, 'ipAddress': ip_address}}


def get_redistribution_rule(prefix_name, learner_protocol, from_bgp, from_ospf,
                            from_static, from_connected, action):
    rule = {
        'action': action,
        'from': {
            'ospf': from_ospf,
            'bgp': from_bgp,
            'connected': from_connected,
            'static': from_static
        }
    }
    if prefix_name:
        rule['prefixName'] = prefix_name
    return {'rule': rule}


def _extract_interface_info(info):
    portgroup, address = info.split(':')
    network = netaddr.IPNetwork(address)
    subnet_mask = str(network.netmask)
    ip_address = str(network.ip)
    return portgroup, ip_address, subnet_mask


def _assemble_gw_edge(name, external_iface_info, internal_iface_info):
    datacenter_moid = cfg.CONF.nsxv.datacenter_moid
    datastore_moid = cfg.CONF.nsxv.datastore_id
    resource_pool_moid = cfg.CONF.nsxv.resource_pool_id

    edge = nsxv._assemble_edge(
        name, datacenter_moid=datacenter_moid,
        deployment_container_id=datastore_moid,
        appliance_size=nsxv_constants.LARGE,
        remote_access=False, edge_ha=False)
    appliances = [nsxv._assemble_edge_appliance(
        resource_pool_moid, datastore_moid)]
    edge['appliances']['appliances'] = appliances

    portgroup, ip_address, subnet_mask = (
        _extract_interface_info(external_iface_info))
    vnic_external = nsxv._assemble_edge_vnic(vsh_constants.EXTERNAL_VNIC_NAME,
                                             vsh_constants.EXTERNAL_VNIC_INDEX,
                                             portgroup,
                                             primary_address=ip_address,
                                             subnet_mask=subnet_mask,
                                             type="uplink")

    portgroup, gateway_ip, subnet_mask = (
        _extract_interface_info(internal_iface_info))
    vnic_internal = nsxv._assemble_edge_vnic(vsh_constants.INTERNAL_VNIC_NAME,
                                             vsh_constants.INTERNAL_VNIC_INDEX,
                                             portgroup,
                                             primary_address=gateway_ip,
                                             subnet_mask=subnet_mask,
                                             type="internal")

    if (cfg.CONF.nsxv.edge_appliance_user and
        cfg.CONF.nsxv.edge_appliance_password):
        edge['cliSettings'].update({
            'userName': cfg.CONF.nsxv.edge_appliance_user,
            'password': cfg.CONF.nsxv.edge_appliance_password})

    edge['vnics']['vnics'].append(vnic_external)
    edge['vnics']['vnics'].append(vnic_internal)

    header = nsxv.vcns.deploy_edge(edge)[0]
    edge_id = header.get('location', '/').split('/')[-1]
    disable_fw_req = {'featureType': 'firewall_4.0',
                      'enabled': False}
    nsxv.vcns.update_firewall(edge_id, disable_fw_req)
    return edge_id, gateway_ip


@admin_utils.output_header
def create_bgp_gw(resource, event, trigger, **kwargs):
    """Creates a new BGP GW edge"""
    usage = ("nsxadmin -r bgp-gw-edge -o create "
             "--property name=<GW_EDGE_NAME> "
             "--property bgp-speaker-id=<Neutron BGP speaker id> "
             "--property external-iface=<PORTGROUP>:<IP_ADDRESS/PREFIX_LEN>"
             "--property internal-iface=<PORTGROUP>:<IP_ADDRESS/PREFIX_LEN>")
    required_params = ('name', 'bgp-speaker-id',
                       'internal-iface', 'external-iface')
    properties = admin_utils.parse_multi_keyval_opt(kwargs.get('property', []))
    if not properties or set(required_params) == set(properties.keys()):
            LOG.error(usage)
    bgp_speaker_id = properties['bgp-speaker-id']
    edge_id, gateway_ip = _assemble_gw_edge(properties['name'],
                                            properties['external-iface'],
                                            properties['internal-iface'])
    speaker = bgpdb.get_bgp_speaker(neutron_context.get_admin_context(),
                                    bgp_speaker_id)
    nsxv.add_bgp_speaker_config(edge_id, gateway_ip,
                                speaker['local_as'], True, [], [], [])
    res = {'name': properties['name'],
           'edge_id': edge_id,
           'bgp_identifier': gateway_ip,
           'local_as': speaker['local_as']}
    headers = ['name', 'edge_id', 'bgp_identifier', 'local_as']
    LOG.info(formatters.output_formatter('BGP GW Edge', [res], headers))


def delete_bgp_gw(resource, event, trigger, **kwargs):
    usage = ("nsxadmin -r bgp-gw-edge -o delete "
             "--property edge-id=<EDGE_ID>")
    required_params = ('edge-id', )
    properties = admin_utils.parse_multi_keyval_opt(kwargs.get('property', []))
    if not properties or set(required_params) == set(properties.keys()):
        LOG.error(usage)
    nsxv.vcns.delete_edge(properties['edge-id'])


@admin_utils.output_header
def create_redis_rule(resource, event, trigger, **kwargs):
    usage = ("nsxadmin -r routing-redistribution-rule -o create "
             "--property edge-ids=<GW_EDGE_ID>[,...]"
             "[--property prefix=<NAME:CIDR>] "
             "--property learner-protocol=<ospf/bgp> "
             "--property learn-from=ospf,bgp,connected,static "
             "--property action=<permit/deny>")
    required_params = ('edge-id', 'learner-protocol', 'learn-from', 'action')
    properties = admin_utils.parse_multi_keyval_opt(kwargs.get('property', []))
    if not properties or set(required_params) == set(properties.keys()):
        LOG.error(usage)

    prefix = properties.get('prefix')
    if prefix:
        prefix_name, cidr = prefix.split(':')
        prefixes = [get_ip_prefix(prefix_name, cidr)] if cidr else []
    else:
        prefix_name = None
        prefixes = []

    learn_from = properties['learn-from'].split(',')

    rule = get_redistribution_rule(prefix_name,
                                   properties['learner-protocol'],
                                   'bgp' in learn_from,
                                   'ospf' in learn_from,
                                   'static' in learn_from,
                                   'connected' in learn_from,
                                   properties['action'])

    edge_ids = properties['edge-ids'].split(',')
    for edge_id in edge_ids:
        nsxv.add_bgp_redistribution_rules(edge_id, prefixes, [rule])

    res = [{'edge_id': edge_id,
           'prefix': prefix_name if prefix_name else 'ANY',
           'learner-protocol': properties['learner_protocol'],
           'learn-from': ', '.join(set(learn_from)),
           'action': properties['action']} for edge_id in edge_ids]

    headers = ['edge_id', 'prefix', 'learner-protocol', 'learn-from', 'action']
    LOG.info(formatters.output_formatter(
        'Routing redistribution rule', res, headers))


def delete_redis_rule(resource, event, trigger, **kwargs):
    usage = ("nsxadmin -r routing-redistribution-rule -o delete "
             "--property edge-ids=<GW_EDGE_ID>[,...]"
             "[--property prefix-name=<NAME>]")
    required_params = ('edge-id', )
    properties = admin_utils.parse_multi_keyval_opt(kwargs.get('property', []))
    if not properties or set(required_params) == set(properties.keys()):
        LOG.error(usage)

    edge_ids = properties['edge-ids'].split(',')
    # If no prefix-name is given then remove rules configured 'ANY' for prefix.
    prefixes = [properties.get('prefix-name')]
    for edge_id in edge_ids:
        nsxv.remove_bgp_redistribution_rules(edge_id, prefixes)


registry.subscribe(create_bgp_gw,
                   constants.BGP_GW_EDGE,
                   shell.Operations.CREATE.value)
registry.subscribe(delete_bgp_gw,
                   constants.BGP_GW_EDGE,
                   shell.Operations.DELETE.value)
registry.subscribe(create_redis_rule,
                   constants.ROUTING_REDIS_RULE,
                   shell.Operations.CREATE.value)
registry.subscribe(delete_redis_rule,
                   constants.ROUTING_REDIS_RULE,
                   shell.Operations.DELETE.value)
