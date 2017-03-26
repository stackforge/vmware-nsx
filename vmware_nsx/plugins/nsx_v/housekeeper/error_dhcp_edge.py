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

from neutron_lib import constants
from oslo_log import log
from oslo_utils import uuidutils

from vmware_nsx.common import locking
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.common.housekeeper import base_job
from vmware_nsx.plugins.nsx_v.vshield.common import constants as vcns_const

LOG = log.getLogger(__name__)


class ErrorDhcpEdgeJob(base_job.BaseJob):
    def get_name(self):
        return 'error_dhcp_edge'

    def get_description(self):
        return 'revalidate DHCP Edge appliances in ERROR state'

    def run(self, context):
        super(ErrorDhcpEdgeJob, self).run(context)

        # Gather ERROR state DHCP edges into dict
        filters = {'status': [constants.ERROR]}
        error_edge_bindings = nsxv_db.get_nsxv_router_bindings(
            context.session, filters=filters)

        with locking.LockManager.get_lock('nsx-dhcp-edge-pool'):
            edge_dict = {}
            for binding in error_edge_bindings:
                if binding['router_id'].startswith(
                        vcns_const.DHCP_EDGE_PREFIX):
                    bind_list = edge_dict.get(binding['edge_id'],
                                              [])
                    bind_list.append(binding)
                    edge_dict[binding['edge_id']] = bind_list

        # Get valid neutron networks and create a prefix dict.
        networks = [net['id'] for net in
                    self.plugin.get_networks(context, fields=['id'])]
        pfx_dict = {net[:36 - len(vcns_const.DHCP_EDGE_PREFIX)]: net
                    for net in networks}

        for edge_id in edge_dict.keys():
            # Also metadata network should be a valid network for the edge
            az_name = self.plugin.get_availability_zone_name_by_edge(context,
                                                                     edge_id)

            with locking.LockManager.get_lock(edge_id):
                vnic_binds = nsxv_db.get_edge_vnic_bindings_by_edge(
                    context.session, edge_id)
                edge_networks = [bind['network_id'] for bind in vnic_binds]

                # Step (A)
                # Find router bindings which are mapped to dead networks, or
                # do not have interfaces registered in nsxv tables
                for binding in edge_dict[edge_id]:
                    router_id = binding['router_id']

                    net_pfx = router_id[len(vcns_const.DHCP_EDGE_PREFIX):]
                    net_id = pfx_dict.get(net_pfx)

                    if net_id is None:
                        # Delete router binding as we do not have such network
                        # in Neutron
                        LOG.info('Housekeeping: router binding %s for edge %s '
                                 'has no matching neutron network',
                                 router_id, edge_id)
                        if not self.readonly:
                            nsxv_db.delete_nsxv_router_binding(
                                context.session, binding['router_id'])
                    else:
                        if net_id not in edge_networks:
                            # Create vNic bind here
                            LOG.info('Housekeeping: edge  %s vnic binding '
                                     'missing for network %s', edge_id, net_id)
                            if not self.readonly:
                                nsxv_db.allocate_edge_vnic_with_tunnel_index(
                                    context.session, edge_id, net_id,
                                    az_name)

                # Step (B)
                # Find vNic bindings which reference invalid networks or aren't
                # bound to any router binding

                # Reread vNic binds as we might created more or deleted some in
                #  step (A)
                vnic_binds = nsxv_db.get_edge_vnic_bindings_by_edge(
                    context.session, edge_id)

                for bind in vnic_binds:
                    if bind['network_id'] not in networks:
                        LOG.info('Housekeeping: edge vnic binding for edge %s '
                                 'is for invalid network id %s',
                                 edge_id, bind['network_id'])
                        if not self.readonly:
                            nsxv_db.free_edge_vnic_by_network(
                                context.session, edge_id, bind['network_id'])

                # Step (C)
                # Verify that backend is in sync with Neutron

                # Reread vNic binds as we might deleted some in step (B)
                vnic_binds = nsxv_db.get_edge_vnic_bindings_by_edge(
                    context.session, edge_id)

                # Transform to network-keyed dict
                vnic_dict = {vnic['network_id']: {
                    'vnic_index': vnic['vnic_index'],
                    'tunnel_index': vnic['tunnel_index']
                } for vnic in vnic_binds}

                backend_vnics = self.plugin.nsx_v.vcns.get_interfaces(
                    edge_id)[1].get('vnics', [])
                if_changed = {}
                self._validate_edge_subinterfaces(
                    context, edge_id, backend_vnics, vnic_dict, if_changed)
                self._add_missing_subinterfaces(
                    context, edge_id, vnic_binds, backend_vnics, if_changed)

                for vnic in backend_vnics:
                    if if_changed[vnic['index']]:
                        self.plugin.nsx_v.vcns.update_interface(edge_id, vnic)

    def _validate_edge_subinterfaces(
            self, context, edge_id, backend_vnics, vnic_dict, if_changed):
        # Validate that all the interfaces on the Edge
        # appliance are registered in nsxv_edge_vnic_bindings
        for vnic in backend_vnics:
            if_changed[vnic['index']] = False
            if (vnic['isConnected'] and vnic['type'] == 'trunk'
                and vnic['subInterfaces']):

                for sub_if in vnic['subInterfaces']['subInterfaces']:
                    # Subinterface name field contains the net id
                    vnic_bind = vnic_dict.get(sub_if['logicalSwitchName'])
                    if (vnic_bind
                        and vnic_bind['vnic_index'] == vnic['index']
                        and vnic_bind['tunnel_index'] == sub_if['tunnelId']):
                        pass
                    else:
                        LOG.info('Housekeeping: subinterface %s for vnic %s '
                                 'on edge %s is not defined in '
                                 'nsxv_edge_vnic_bindings', sub_if['tunnelId'],
                                 vnic['index'], edge_id)
                        if_changed[vnic['index']] = True
                        vnic['subInterfaces']['subInterfaces'].remove(sub_if)

    def _add_missing_subinterfaces(
            self, context, edge_id, vnic_binds, backend_vnics, if_changed):
        # Verify that all the entries in
        # nsxv_edge_vnic_bindings are attached on the Edge
        for vnic_bind in vnic_binds:
            for vnic in backend_vnics:
                if (vnic['isConnected'] and vnic['type'] == 'trunk'
                    and vnic['subInterfaces']
                    and vnic['index'] == vnic_bind['vnic_index']):
                    found = False
                    tunnel_index = vnic_bind['tunnel_index']
                    network_id = vnic_bind['network_id']
                    for sub_if in (
                            vnic['subInterfaces']['subInterfaces']):
                        if sub_if['tunnelId'] == tunnel_index:
                            found = True
                            if sub_if.get('logicalSwitchName') != network_id:
                                LOG.info('Housekeeping: subinterface %s on '
                                         'vnic %s on edge %s should be '
                                         'connected to network %s',
                                         tunnel_index, vnic['index'],
                                         edge_id, network_id)
                                if_changed[vnic['index']] = True
                                if not self.readonly:
                                    self._recreate_vnic_subinterface(
                                        context, network_id, edge_id, vnic,
                                        tunnel_index)
                                sub_if['name'] = network_id
                    if not found:
                        LOG.info('Housekeeping: subinterface %s on vnic '
                                 '%s on edge %s should be connected to '
                                 'network %s but is missing', tunnel_index,
                                 vnic['index'], edge_id, network_id)
                        if_changed[vnic['index']] = True
                        if not self.readonly:
                            self._recreate_vnic_subinterface(
                                context, network_id, edge_id, vnic,
                                tunnel_index)

    def _recreate_vnic_subinterface(
            self, context, network_id, edge_id, vnic, tunnel_index):

        vnic_index = vnic['index']
        network_name_item = [edge_id, str(vnic_index), str(tunnel_index)]
        network_name = ('-'.join(network_name_item) +
                        uuidutils.generate_uuid())[:36]
        port_group_id = vnic.get('portgroupId')

        address_groups = self.plugin._create_network_dhcp_address_group(
            context, network_id)
        port_group_id, iface = self.plugin.edge_manager._create_sub_interface(
            context, network_id, network_name, tunnel_index,
            address_groups, port_group_id)

        vnic['subInterfaces']['subInterfaces'].append(iface)
