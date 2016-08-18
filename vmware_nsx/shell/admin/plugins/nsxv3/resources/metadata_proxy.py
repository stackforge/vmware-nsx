# Copyright 2016 VMware, Inc.  All rights reserved.
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

import logging

from neutron.callbacks import registry
from neutron_lib import constants as const
from oslo_config import cfg

from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils as nsx_utils
from vmware_nsx.dhcp_meta import rpc as nsx_rpc
from vmware_nsx.nsxlib import v3 as nsxlib
from vmware_nsx.nsxlib.v3 import client
from vmware_nsx.nsxlib.v3 import cluster
from vmware_nsx.nsxlib.v3 import resources
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
import vmware_nsx.shell.resources as shell

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


@admin_utils.output_header
def nsx_update_metadata_proxy(resource, event, trigger, **kwargs):
    """Update Metadata proxy for NSXv3 CrossHairs."""

    nsx_version = nsxlib.get_version()
    if not nsx_utils.is_nsx_version_1_1_0(nsx_version):
        LOG.info(_LI("This utility is not available for NSX version %s"),
                 nsx_version)
        return

    if not cfg.CONF.nsx_v3.metadata_proxy_uuid:
        LOG.error(_LE("metadata_proxy_uuid is not defined"))
        return

    plugin = utils.NsxV3PluginWrapper()
    cluster_api = cluster.NSXClusteredAPI()
    nsx_client = client.NSX3Client(cluster_api)
    client._set_default_api_cluster(cluster_api)
    port_resource = resources.LogicalPort(nsx_client)

    # For each Neutron network, check if it is an internal metadata network,
    # i.e. has only one subnet with 169.254.169.252/30 CIDR.
    # If yes, delete the network and associated router interface.
    # Otherwise, create a logical switch port with MD-Proxy attachment.
    for network in neutron_client.get_networks():
        if (len(network.subnets) == 1 and
            network.subnets[0]['cidr'] == nsx_rpc.METADATA_SUBNET_CIDR):
            # It is a metadata network, find the attached router,
            # remove the router interface and the network.
            filters = {'network_id': network['id'],
                       'device_owner': const.ROUTER_INTERFACE_OWNERS,
                       'fixed_ips': {
                           'ip_address': [nsx_rpc.METADATA_GATEWAY_IP]}}
            ports = neutron_client.get_ports(filters=filters)
            if not ports:
                continue
            router_id = ports[0]['device_id']
            interface = {'subnet_id': network.subnets[0]['id']}
            plugin.remove_router_interface(router_id, interface)
            LOG.debug("Removed metadata interface on router %s", router_id)
            plugin.delete_network(network['id'])
            LOG.debug("Removed metadata network %s", network['id'])
        else:
            lswitch_id = neutron_client.net_id_to_lswitch_id(network['id'])
            if not lswitch_id:
                continue
            tags = nsx_utils.build_v3_tags_payload(
                network, resource_type='os-neutron-net-id',
                project_name='admin')
            name = nsx_utils.get_name_and_uuid('%s-%s' % (
                'mdproxy', network['name'] or 'network'), network['id'])
            port_resource.create(
                lswitch_id, cfg.CONF.nsx_v3.metadata_proxy_uuid,
                tags=tags, name=name,
                attachment_type=nsx_constants.ATTACHMENT_MDPROXY)
            LOG.debug("Enabled native metadata proxy for network %s",
                      network['id'])


registry.subscribe(nsx_update_metadata_proxy,
                   constants.METADATA_PROXY,
                   shell.Operations.NSX_UPDATE.value)
