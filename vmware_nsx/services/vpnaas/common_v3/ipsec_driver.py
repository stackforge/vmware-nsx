# Copyright 2019 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
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
from oslo_utils import excutils

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context as n_context
from neutron_lib import exceptions as nexception
from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn import service_drivers

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils
from vmware_nsx.services.vpnaas.nsxp import ipsec_validator
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as consts
from vmware_nsxlib.v3 import vpn_ipsec

LOG = logging.getLogger(__name__)
IPSEC = 'ipsec'


class NSXcommonIPsecVpnDriver(service_drivers.VpnDriver):

    def __init__(self, service_plugin, validator):
        self.vpn_plugin = service_plugin
        self._core_plugin = directory.get_plugin()
        if self._core_plugin.is_tvd_plugin():
            self._core_plugin = self._core_plugin.get_plugin_by_type(
                projectpluginmap.NsxPlugins.NSX_T)
        super(NSXcommonIPsecVpnDriver, self).__init__(service_plugin, validator)

    @property
    def l3_plugin(self):
        return self._core_plugin

    @property
    def service_type(self):
        return IPSEC

    def _get_dpd_profile_name(self, connection):
        return (connection['name'] or connection['id'])[:240] + '-dpd-profile'

    def _find_vpn_service_port(self, context, router_id):
        """Look for the neutron port created for the vpnservice of a router"""
        filters = {'device_id': ['router-' + router_id],
                   'device_owner': [ipsec_utils.VPN_PORT_OWNER]}
        ports = self.l3_plugin.get_ports(context, filters=filters)
        if ports:
            return ports[0]

    def _get_tier0_uuid(self, context, router_id):
        router_db = self._core_plugin._get_router(context, router_id)
        return self._core_plugin._get_tier0_uuid_by_router(context, router_db)

    def _get_service_local_address(self, context, vpnservice):
        """Find/Allocate a port on the external network
        to allocate the ip to be used as the local ip of this service
        """
        router_id = vpnservice['router_id']
        # check if this router already have an IP
        port = self._find_vpn_service_port(context, router_id)
        if not port:
            # create a new port, on the external network of the router
            # Note(asarfaty): using a unique device owner and device id to
            # make sure tis port will be ignored in certain queries
            ext_net = vpnservice['router']['gw_port']['network_id']
            port_data = {
                'port': {
                    'network_id': ext_net,
                    'name': 'VPN local address port',
                    'admin_state_up': True,
                    'device_id': 'router-' + router_id,
                    'device_owner': ipsec_utils.VPN_PORT_OWNER,
                    'fixed_ips': constants.ATTR_NOT_SPECIFIED,
                    'mac_address': constants.ATTR_NOT_SPECIFIED,
                    'port_security_enabled': False,
                    'tenant_id': vpnservice['tenant_id']}}
            port = self.l3_plugin.base_create_port(context, port_data)
        # return the port ip as the local address
        return port['fixed_ips'][0]['ip_address']

    def _update_status(self, context, vpn_service_id, ipsec_site_conn_id,
                       status, updated_pending_status=True):
        vpn_status = {'id': vpn_service_id,
                      'updated_pending_status': updated_pending_status,
                      'status': status,
                      'ipsec_site_connections': {}}
        if ipsec_site_conn_id:
            ipsec_site_conn = {
                'status': status,
                'updated_pending_status': updated_pending_status}
            vpn_status['ipsec_site_connections'] = {
                ipsec_site_conn_id: ipsec_site_conn}
        status_list = [vpn_status]
        self.service_plugin.update_status_by_agent(context, status_list)
