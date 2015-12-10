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

from eventlet import greenthread
import netaddr
from oslo_config import cfg
from oslo_log import log as logging

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants as const
from neutron.common import exceptions as ntn_exc
from neutron.db import db_base_plugin_v2
from neutron.db import models_v2
from vmware_nsx.api_client import exception as api_exc
from vmware_nsx._i18n import _, _LE, _LI, _LW
from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc

LOG = logging.getLogger(__name__)

METADATA_DEFAULT_PREFIX = 30
METADATA_SUBNET_CIDR = '169.254.169.252/%d' % METADATA_DEFAULT_PREFIX
METADATA_GATEWAY_IP = '169.254.169.253'
METADATA_DHCP_ROUTE = '169.254.169.254/32'


class NsxV3MetadataProxyHandler:
    def __init__(self, plugin):
        self.plugin = plugin

    def handle_port_metadata_access(self, context, port, is_delete=False):
        # For instances supporting DHCP option 121 and created in a
        # DHCP-enabled but isolated network.
        if (cfg.CONF.NSX.metadata_mode != config.MetadataModes.INDIRECT or
            port.get('device_owner') != const.DEVICE_OWNER_DHCP):
            return
        if port.get('fixed_ips', []) or is_delete:
            fixed_ip = port['fixed_ips'][0]
            query = context.session.query(models_v2.Subnet)
            subnet = query.filter(
                models_v2.Subnet.id == fixed_ip['subnet_id']).one()
            # If subnet does not have a gateway do not create metadata
            # route. This is done via the enable_isolated_metadata
            # option if desired.
            if not subnet.get('gateway_ip'):
                LOG.info(_LI('Subnet %s does not have a gateway, the '
                             'metadata route will not be created'),
                         subnet['id'])
                return
            metadata_routes = [r for r in subnet.routes
                               if r['destination'] == METADATA_DHCP_ROUTE]
            if metadata_routes:
                # We should have only a single metadata route at any time
                # because the route logic forbids two routes with the same
                # destination. Update next hop with the provided IP address.
                if not is_delete:
                    metadata_routes[0].nexthop = fixed_ip['ip_address']
                else:
                    context.session.delete(metadata_routes[0])
            else:
                # Add the metadata route.
                route = models_v2.SubnetRoute(
                    subnet_id=subnet.id,
                    destination=METADATA_DHCP_ROUTE,
                    nexthop=fixed_ip['ip_address'])
                context.session.add(route)

    def handle_router_metadata_access(self, context, router_id,
                                      is_delete=False):
        # For instances created in a DHCP-disabled network but
        # connected to a router.
        if cfg.CONF.NSX.metadata_mode != config.MetadataModes.DIRECT:
            LOG.debug("Metadata access network is disabled")
            return
        if not cfg.CONF.allow_overlapping_ips:
            LOG.warn(_LW("Overlapping IPs must be enabled in order to setup "
                         "the metadata access network"))
            return
        ctx_elevated = context.elevated()
        device_filter = {'device_id': [router_id],
                         'device_owner': const.ROUTER_INTERFACE_OWNERS}
        # Retrieve ports calling database plugin.
        ports = db_base_plugin_v2.NeutronDbPluginV2.get_ports(
            self.plugin, ctx_elevated, filters=device_filter)
        if not ports:
            LOG.debug("No router interface found for router '%s'. "
                      "No metadata access network should be "
                      "created or destroyed", router_id)
            return

        try:
            if (not is_delete and
                not self._find_metadata_port(ctx_elevated, ports)):
                self._create_metadata_access_network(ctx_elevated, router_id)
            elif is_delete and len(ports) == 1:
                # The only port left might be the metadata port.
                self._destroy_metadata_access_network(
                    ctx_elevated, router_id, ports)
        # TODO(salvatore-orlando): A better exception handling in the
        # NSX plugin would allow us to improve error handling here.
        except (ntn_exc.NeutronException, nsx_exc.NsxPluginException,
                api_exc.NsxApiException):
            # Any exception here should be regarded as non-fatal.
            LOG.exception(_LE("An error occurred while operating on the "
                              "metadata access network for router:'%s'"),
                          router_id)

    def _find_metadata_port(self, context, ports):
        for port in ports:
            for fixed_ip in port['fixed_ips']:
                cidr = netaddr.IPNetwork(self.plugin.get_subnet(
                    context, fixed_ip['subnet_id'])['cidr'])
                if cidr in netaddr.IPNetwork(METADATA_SUBNET_CIDR):
                    return port

    def _create_metadata_access_network(self, context, router_id):
        # Add an internal metadata network.
        net_data = {'network':
                    {'name': 'meta-%s' % router_id,
                     'tenant_id': '',  # intentionally not set
                     'admin_state_up': True,
                     'port_security_enabled': False,
                     'shared': False,
                     'status': const.NET_STATUS_ACTIVE}}
        meta_net = self.plugin.create_network(context, net_data)
        greenthread.sleep(0)  # yield
        self.plugin.schedule_network(context, meta_net)
        greenthread.sleep(0)  # yield
        # From this point on there will be resources to garbage-collect
        # in case of failures.
        try:
            # Add a DHCP-enabled metadata subnet.
            subnet_data = {'subnet':
                           {'network_id': meta_net['id'],
                            'tenant_id': '',  # intentionally not set
                            'name': 'meta-sub-%s' % router_id,
                            'ip_version': 4,
                            'shared': False,
                            'cidr': METADATA_SUBNET_CIDR,
                            'enable_dhcp': True,
                            # Ensure default allocation pool is generated
                            'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                            'gateway_ip': METADATA_GATEWAY_IP,
                            'dns_nameservers': [],
                            'host_routes': []}}
            meta_subnet = self.plugin.create_subnet(context, subnet_data)
            greenthread.sleep(0)  # yield
            self.plugin.add_router_interface(context, router_id,
                                             {'subnet_id': meta_subnet['id']})
            greenthread.sleep(0)  # yield
            # Tell to start the metadata proxy, only if we had success.
            self._notify_rpc_agent(context, {'subnet': meta_subnet},
                                   'subnet.create.end')
        except (ntn_exc.NeutronException,
                nsx_exc.NsxPluginException,
                api_exc.NsxApiException):
            # It is not necessary to explicitly delete the subnet
            # as it will be removed with the network.
            self.plugin.delete_network(context, meta_net['id'])

    def _destroy_metadata_access_network(self, context, router_id, ports):
        meta_port = self._find_metadata_port(context, ports)
        if not meta_port:
            return
        meta_net_id = meta_port['network_id']
        meta_sub_id = meta_port['fixed_ips'][0]['subnet_id']
        self.plugin.remove_router_interface(
            context, router_id, {'port_id': meta_port['id']})
        greenthread.sleep(0)  # yield
        context.session.expunge_all()
        try:
            # Remove network (this will remove the subnet too).
            self.plugin.delete_network(context, meta_net_id)
            greenthread.sleep(0)  # yield
        except (ntn_exc.NeutronException, nsx_exc.NsxPluginException,
                api_exc.NsxApiException):
            # Must re-add the router interface.
            self.plugin.add_router_interface(context, router_id,
                                             {'subnet_id': meta_sub_id})
        # Tell to stop the metadata proxy.
        self._notify_rpc_agent(context, {'network': {'id': meta_net_id}},
                               'network.delete.end')

    def _notify_rpc_agent(self, context, payload, event):
        if cfg.CONF.dhcp_agent_notification:
            dhcp_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
            dhcp_notifier.notify(context, payload, event)
