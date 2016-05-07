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

from vmware_nsx._i18n import _LE
from vmware_nsx.common import nsx_constants
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
import vmware_nsx.shell.admin.plugins.common.utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils
import vmware_nsx.shell.nsxadmin as shell

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


@admin_utils.output_header
def list_dhcp_bindings(resource, event, trigger, **kwargs):
    """List DHCP bindings in neutron."""

    ports = neutron_client.get_ports()
    comp_ports = [port for port in ports if port['device_owner'].startswith(
        const.DEVICE_OWNER_COMPUTE_PREFIX)]
    LOG.info(formatters.output_formatter(constants.DHCP_BINDING, comp_ports,
                                         ['id', 'mac_address', 'fixed_ips']))


@admin_utils.output_header
def nsx_update_dhcp_bindings(resource, event, trigger, **kwargs):
    """Resync DHCP bindings on NSXv3 CrossHairs."""

    if not kwargs['property']:
        LOG.error(_LE("Need to specify NSX manager"))
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    if 'mgr-ip' not in properties:
        LOG.error(_LE("Need to specify mgr-ip"))
        return
    if 'dhcp-profile' not in properties:
        LOG.error(_LE("Need to specify dhcp-profile"))
        return
    mgr_ip = properties['mgr-ip']
    mgr_user = properties.get('mgr-user', 'admin')
    mgr_passwd = properties.get('mgr-passwd', 'default')
    dhcp_profile = properties.get('dhcp-profile', 'default')
    nsx_client = utils.NSXClient(mgr_ip, mgr_user, mgr_passwd)

    port_bindings = {}    # lswitch_id: [mac_ip_binding]
    server_bindings = {}  # lswitch_id: dhcp_server_id
    ports = neutron_client.get_ports()
    for port in ports:
        network_id = port['network_id']
        device_owner = port['device_owner']
        if device_owner == const.DEVICE_OWNER_DHCP:
            # For each DHCP-enabled network, create a logical DHCP server
            # and a logical switch port with DHCP attachment.
            lswitch_id = neutron_client.net_id_to_lswitch_id(network_id)
            server_ip = port['fixed_ips'][0]['ip_address']
            dhcp_server = nsx_client.create_logical_dhcp_server(dhcp_profile,
                                                                server_ip)
            attachment = {'attachment_type': nsx_constants.ATTACHMENT_DHCP,
                          'id': dhcp_server['id']}
            nsx_client.create_logical_switch_port(lswitch_id, attachment)
            server_bindings[lswitch_id] = dhcp_server['id']
        elif device_owner.startswith(const.DEVICE_OWNER_COMPUTE_PREFIX):
            lswitch_id = neutron_client.net_id_to_lswitch_id(network_id)
            bindings = port_bindings.get(lswitch_id, [])
            bindings.append((port['mac_address'],
                             port['fixed_ips'][0]['ip_address']))
            port_bindings[lswitch_id] = bindings

    # Populate mac/IP bindings in each logical DHCP server.
    for lswitch_id, bindings in port_bindings.items():
        dhcp_server_id = server_bindings[lswitch_id]
        for binding in bindings:
            nsx_client.create_static_binding(dhcp_server_id, binding[0],
                                             binding[1])


registry.subscribe(list_dhcp_bindings,
                   constants.DHCP_BINDING,
                   shell.Operations.LIST.value)
registry.subscribe(nsx_update_dhcp_bindings,
                   constants.DHCP_BINDING,
                   shell.Operations.NSX_UPDATE.value)
