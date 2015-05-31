# Copyright 2014 VMware, Inc
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

from oslo_utils import excutils

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as n_exc

from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_db
from vmware_nsx.neutron.plugins.vmware.plugins import nsx_v
from vmware_nsx.neutron.plugins.vmware.plugins.nsx_v_drivers import (
    abstract_router_driver as router_driver)
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    constants as vcns_const)
from vmware_nsx.neutron.plugins.vmware.vshield import edge_utils

METADATA_CIDR = '169.254.169.254/32'


class RouterDistributedDriver(router_driver.RouterBaseDriver):

    def get_type(self):
        return "distributed"

    def _update_routes_on_plr(self, context, router_id, plr_id, newnexthop):
        lswitch_id = edge_utils.get_internal_lswitch_id_of_plr_tlr(
            context, router_id)
        subnets = self.plugin._find_router_subnets_cidrs(
            context.elevated(), router_id)
        routes = []
        for subnet in subnets:
            routes.append({
                'destination': subnet,
                'nexthop': (vcns_const.INTEGRATION_LR_IPADDRESS.
                            split('/')[0]),
                'network_id': lswitch_id
            })

        # Add extra routes referring to external network on plr
        extra_routes = self.plugin._prepare_edge_extra_routes(
            context, router_id)
        routes.extend([route for route in extra_routes
                       if route.get('external')])
        edge_utils.update_routes(self.nsx_v, context,
                                 plr_id, routes, newnexthop)

    def _update_routes_on_tlr(
        self, context, router_id,
        newnexthop=vcns_const.INTEGRATION_EDGE_IPADDRESS,
        metadata_gateway=None):
        internal_vnic_index = None
        if newnexthop:
            internal_vnic_index = (
                edge_utils.get_internal_vnic_index_of_plr_tlr(
                    context, router_id))
        routes = []

        # If metadata service is configured, add a static route to direct
        # metadata requests to a DHCP Edge on one of the attached networks
        if metadata_gateway:
            routes.append({'destination': METADATA_CIDR,
                           'nexthop': metadata_gateway['ip_address'],
                           'network_id': metadata_gateway['network_id']})

        # Add extra routes referring to internal network on tlr
        extra_routes = self.plugin._prepare_edge_extra_routes(
            context, router_id)
        routes.extend([route for route in extra_routes
                       if not route.get('external')])
        edge_utils.update_routes(self.nsx_v, context,
                                 router_id, routes, newnexthop,
                                 gateway_vnic_index=internal_vnic_index)

    def create_router(self, context, lrouter, allow_metadata=True):
        self.edge_manager.create_lrouter(context, lrouter, dist=True)

    def update_router(self, context, router_id, router):
        r = router['router']
        gw_info = self.plugin._extract_external_gw(context, router,
                                                   is_extract=True)
        super(nsx_v.NsxVPluginV2, self.plugin).update_router(
            context, router_id, router)
        if gw_info != attr.ATTR_NOT_SPECIFIED:
            self._update_router_gw_info(context, router_id, gw_info)
        else:
            # here is used to handle routes which tenant updates.
            router_db = self.plugin._get_router(context, router_id)
            nexthop = self.plugin._get_external_attachment_info(
                context, router_db)[2]
            self.update_routes(context, router_id, nexthop)
        if 'admin_state_up' in r:
            self.plugin._update_router_admin_state(
                context, router_id, self.get_type(), r['admin_state_up'])
        return self.plugin.get_router(context, router_id)

    def delete_router(self, context, router_id):
        self.edge_manager.delete_lrouter(context, router_id, dist=True)

    def update_routes(self, context, router_id, newnexthop):
        plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
        if plr_id:
            self._update_routes_on_plr(context, router_id, plr_id, newnexthop)
            self._update_routes_on_tlr(context, router_id)
        else:
            self._update_routes_on_tlr(context, router_id, newnexthop=None)

    def _update_router_gw_info(self, context, router_id, info):
        router = self.plugin._get_router(context, router_id)
        org_ext_net_id = router.gw_port_id and router.gw_port.network_id
        org_enable_snat = router.enable_snat
        orgaddr, orgmask, orgnexthop = (
            self.plugin._get_external_attachment_info(
                context, router))

        super(nsx_v.NsxVPluginV2, self.plugin)._update_router_gw_info(
            context, router_id, info, router=router)

        new_ext_net_id = router.gw_port_id and router.gw_port.network_id
        new_enable_snat = router.enable_snat
        newaddr, newmask, newnexthop = (
            self.plugin._get_external_attachment_info(
                context, router))

        plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
        if not new_ext_net_id:
            if plr_id:
                # delete all plr relative conf
                self.edge_manager.delete_plr_by_tlr_id(
                    context, plr_id, router_id)
        else:
            # Connecting plr to the tlr if new_ext_net_id is not None.
            if not plr_id:
                plr_id = self.edge_manager.create_plr_with_tlr_id(
                    context, router_id, router.get('name'))
            if new_ext_net_id != org_ext_net_id and orgnexthop:
                # network changed, so need to remove default gateway
                # and all static routes before vnic can be configured
                edge_utils.clear_gateway(self.nsx_v, context, plr_id)
                # Delete SNAT rules
                if org_enable_snat:
                    edge_utils.clear_nat_rules(self.nsx_v, context,
                                               plr_id)

            # Update external vnic if addr or mask is changed
            if orgaddr != newaddr or orgmask != newmask:
                edge_utils.update_external_interface(
                    self.nsx_v, context, plr_id,
                    new_ext_net_id, newaddr, newmask)

            # Update SNAT rules if ext net changed and snat enabled
            # or ext net not changed but snat is changed.
            if ((new_ext_net_id != org_ext_net_id and
                 newnexthop and new_enable_snat) or
                (new_ext_net_id == org_ext_net_id and
                 new_enable_snat != org_enable_snat)):
                self.plugin._update_nat_rules(context, router, plr_id)
                # Open firewall flows on plr
                self.plugin._update_subnets_and_dnat_firewall(
                    context, router, router_id=plr_id)

        # update static routes in all
        self.update_routes(context, router_id, newnexthop)

    def add_router_interface(self, context, router_id, interface_info):
        info = super(nsx_v.NsxVPluginV2, self.plugin).add_router_interface(
            context, router_id, interface_info)

        router_db = self.plugin._get_router(context, router_id)
        subnet = self.plugin.get_subnet(context, info['subnet_id'])
        network_id = subnet['network_id']
        address_groups = self.plugin._get_address_groups(
            context, router_id, network_id)
        try:
            edge_utils.add_vdr_internal_interface(self.nsx_v, context,
                                                  router_id, network_id,
                                                  address_groups,
                                                  router_db.admin_state_up)
        except n_exc.BadRequest:
            with excutils.save_and_reraise_exception():
                super(nsx_v.NsxVPluginV2, self.plugin).remove_router_interface(
                    context, router_id, interface_info)
        # Update edge's firewall rules to accept subnets flows.
        self.plugin._update_subnets_and_dnat_firewall(context, router_db)

        if router_db.gw_port and router_db.enable_snat:
            plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
            self.plugin._update_nat_rules(context, router_db, plr_id)
            # Open firewall flows on plr
            self.plugin._update_subnets_and_dnat_firewall(
                context, router_db, router_id=plr_id)
            # Update static routes of plr
            nexthop = self.plugin._get_external_attachment_info(
                context, router_db)[2]
            self.update_routes(context, router_id, nexthop)

        # If metadata is configured, setup metadata via DHCP Edge
        if self.plugin.metadata_proxy_handler:
            self.edge_manager.configure_dhcp_for_vdr_network(
                context, network_id, router_id)

            if self._metadata_cfg_required_after_port_add(
                    context, router_id, subnet):
                self._metadata_route_setup(context, router_id)

        return info

    def _metadata_route_setup(self, context, router_id):
        md_route = self._get_metadata_gw_data(context, router_id)

        if md_route:
            # Setup metadata route on VDR
            md_gw_ip, md_gw_net = md_route
            self._update_routes_on_tlr(
                context, router_id, newnexthop=None,
                metadata_gateway={'ip_address': md_gw_ip,
                                  'network_id': md_gw_net})
        else:
            # No more DHCP interfaces on VDR. Remove DHCP binding
            nsxv_db.delete_vdr_dhcp_binding(context.session, router_id)

    def _get_metadata_gw_data(self, context, router_id):
        # Get all subnets which are attached to the VDR and have DHCP enabled
        vdr_ports = self.plugin.get_ports(
            context,
            filters={'device_id': [router_id]},
            fields=['fixed_ips'])
        vdr_subnets = [port['fixed_ips'][0]['subnet_id'] for port in vdr_ports]

        # Choose the 1st subnet, and get the DHCP interface IP address
        if vdr_subnets:
            dhcp_ports = self.plugin.get_ports(
                context,
                filters={'device_owner': ['network:dhcp'],
                         'fixed_ips': {'subnet_id': [vdr_subnets[0]]}},
                fields=['fixed_ips'])

            if(dhcp_ports
               and dhcp_ports[0].get('fixed_ips')
               and dhcp_ports[0]['fixed_ips'][0]):
                ip_subnet = dhcp_ports[0]['fixed_ips'][0]
                ip_address = ip_subnet['ip_address']
                network_id = self.plugin.get_subnet(
                    context, ip_subnet['subnet_id']).get('network_id')

                return ip_address, network_id

    def _metadata_cfg_required_after_port_add(
            self, context, router_id, subnet):
        # On VDR, metadata is supported by applying metadata LB on DHCP
        # Edge, and routing the metadata requests from VDR to the DHCP Edge.
        #
        # If DHCP is enabled on this subnet, we can, potentially, use it
        # for metadata.
        # Verify if there are networks which are connected to DHCP and to
        # this router. If so, one of these is serving metadata.
        # If not, route metadata requests to DHCP on this subnet
        if self.plugin.metadata_proxy_handler and subnet['enable_dhcp']:
            vdr_ports = self.plugin.get_ports(
                context,
                filters={'device_id': [router_id]})
            if vdr_ports:
                for port in vdr_ports:
                    subnet_id = port['fixed_ips'][0]['subnet_id']
                    port_subnet = self.plugin.get_subnet(
                        context, subnet_id)
                    if(port_subnet['id'] != subnet['id']
                       and port_subnet['enable_dhcp']):
                        # We already have a subnet which is connected to
                        # DHCP - hence no need to change the metadata route
                        return False
            return True
        # Metadata routing change is irrelevant if this point is reached
        return False

    def _metadata_cfg_required_after_port_remove(
            self, context, router_id, subnet):
        # When a VDR is detached from a subnet, verify if the subnet is used
        # to transfer metadata requests to the assigned DHCP Edge.
        routes = edge_utils.get_routes(self.nsx_v, context, router_id)

        for route in routes:
            if(route['destination'] == METADATA_CIDR
               and subnet['network_id'] == route['network_id']):

                # Metadata requests are transferred via this port
                return True
        return False

    def _metadata_route_remove(self, context, router_id):
        self._update_routes_on_tlr(context, router_id, newnexthop=None)

    def remove_router_interface(self, context, router_id, interface_info):
        info = super(nsx_v.NsxVPluginV2, self.plugin).remove_router_interface(
            context, router_id, interface_info)
        router_db = self.plugin._get_router(context, router_id)
        subnet = self.plugin.get_subnet(context, info['subnet_id'])
        network_id = subnet['network_id']

        # If DHCP is disabled, this remove cannot trigger metadata change
        # as metadata is served via DHCP Edge
        if subnet['enable_dhcp'] and self.plugin.metadata_proxy_handler:
            md_cfg_required = self._metadata_cfg_required_after_port_remove(
                context, router_id, subnet)

            if md_cfg_required:
                self._metadata_route_remove(context, router_id)
        else:
            md_cfg_required = False

        if router_db.gw_port and router_db.enable_snat:
            plr_id = self.edge_manager.get_plr_by_tlr_id(
                context, router_id)
            self.plugin._update_nat_rules(context, router_db, plr_id)
            # Open firewall flows on plr
            self.plugin._update_subnets_and_dnat_firewall(
                context, router_db, router_id=plr_id)
            # Update static routes of plr
            nexthop = self.plugin._get_external_attachment_info(
                context, router_db)[2]
            self.update_routes(context, router_id, nexthop)

        self.plugin._update_subnets_and_dnat_firewall(context, router_db)
        # Safly remove interface, VDR can have interface to only one subnet in
        # a given network.
        edge_utils.delete_interface(
            self.nsx_v, context, router_id, network_id, dist=True)

        if self.plugin.metadata_proxy_handler:
            # Detach network from VDR-dedicated DHCP Edge
            vdr_dhcp_binding = nsxv_db.get_vdr_dhcp_binding_by_vdr(
                context.session, router_id)
            self.edge_manager.remove_network_from_dhcp_edge(
                context, network_id, vdr_dhcp_binding['dhcp_edge_id'])

            # Reattach to regular DHCP Edge
            self.edge_manager.create_dhcp_edge_service(
                context, network_id, subnet)

            address_groups = self.plugin._create_network_dhcp_address_group(
                context, network_id)
            self.edge_manager.update_dhcp_edge_service(
                context, network_id, address_groups=address_groups)

            if md_cfg_required:
                self._metadata_route_setup(context, router_id)
        return info

    def _update_edge_router(self, context, router_id):
        router = self.plugin._get_router(context, router_id)
        plr_id = self.edge_manager.get_plr_by_tlr_id(context, router_id)
        self.plugin._update_external_interface(
            context, router, router_id=plr_id)
        self.plugin._update_nat_rules(context, router, router_id=plr_id)
        self.plugin._update_subnets_and_dnat_firewall(context, router,
                                                      router_id=plr_id)
