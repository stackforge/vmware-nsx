# Copyright 2014 VMware, Inc.
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

import time

from oslo.config import cfg
from oslo.utils import excutils
from sqlalchemy.orm import exc as sa_exc

from neutron.common import exceptions as n_exc
from neutron import context as q_context
from neutron.extensions import l3
from neutron.i18n import _LE, _LW
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as plugin_const
from vmware_nsx.neutron.plugins.vmware.common import nsxv_constants
from vmware_nsx.neutron.plugins.vmware.dbexts import db as nsx_db
from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_db
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    constants as vcns_const)
from vmware_nsx.neutron.plugins.vmware.vshield.tasks import (
    constants as task_const)
from vmware_nsx.neutron.plugins.vmware.vshield.tasks import tasks


LOG = logging.getLogger(__name__)

_uuid = uuidutils.generate_uuid


def parse_backup_edge_pool_opt():
    """Parse edge pool opts and returns result."""
    edge_pool_opts = cfg.CONF.nsxv.backup_edge_pool
    res = []
    for edge_pool_def in edge_pool_opts:
        split = edge_pool_def.split(':')
        try:
            (edge_type, edge_size, minimum_pooled_edges,
             maximum_pooled_edges) = split[:4]
        except ValueError:
            raise n_exc.Invalid(_("Invalid edge pool format"))
        if edge_type not in vcns_const.ALLOWED_EDGE_TYPES:
            msg = (_("edge type '%(edge_type)s' is not allowed, "
                     "allowed types: %(allowed)s") %
                   {'edge_type': edge_type,
                    'allowed': vcns_const.ALLOWED_EDGE_TYPES})
            LOG.error(msg)
            raise n_exc.Invalid(msg)
        edge_size = edge_size or nsxv_constants.LARGE
        if edge_size not in vcns_const.ALLOWED_EDGE_SIZES:
            msg = (_("edge size '%(edge_size)s' is not allowed, "
                     "allowed types: %(allowed)s") %
                   {'edge_type': edge_size,
                    'allowed': vcns_const.ALLOWED_EDGE_SIZES})
            LOG.error(msg)
            raise n_exc.Invalid(msg)
        res.append({'edge_type': edge_type,
                    'edge_size': edge_size,
                    'minimum_pooled_edges': int(minimum_pooled_edges),
                    'maximum_pooled_edges': int(maximum_pooled_edges)})

    edge_pool_dicts = {}
    for edge_type in vcns_const.ALLOWED_EDGE_TYPES:
        edge_pool_dicts[edge_type] = {}
    for r in res:
        edge_pool_dict = edge_pool_dicts[r['edge_type']]
        if r['edge_size'] in edge_pool_dict.keys():
            raise n_exc.Invalid(_("Duplicate edge pool configuration"))
        else:
            edge_pool_dict[r['edge_size']] = {
                'minimum_pooled_edges': r['minimum_pooled_edges'],
                'maximum_pooled_edges': r['maximum_pooled_edges']}
    return edge_pool_dicts


class EdgeManager(object):
    """Edge Appliance Management.
    EdgeManager provides a pool of edge appliances which we can use
    to support DHCP&metadata, L3&FIP and LB&FW&VPN services.
    """

    def __init__(self, nsxv_manager):
        LOG.debug("Start Edge Manager initialization")
        self.nsxv_manager = nsxv_manager
        self.dvs_id = cfg.CONF.nsxv.dvs_id
        self.edge_pool_dicts = parse_backup_edge_pool_opt()
        self.nsxv_plugin = nsxv_manager.callbacks.plugin
        self._check_backup_edge_pools()

    def _deploy_edge(self, context, lrouter,
                     lswitch=None, appliance_size=nsxv_constants.LARGE,
                     edge_type=nsxv_constants.SERVICE_EDGE):
        """Create an edge for logical router support."""
        router_id = lrouter['id']
        # deploy edge
        jobdata = {
            'router_id': router_id,
            'lrouter': lrouter,
            'lswitch': lswitch,
            'context': context
        }

        task = self.nsxv_manager.deploy_edge(
            lrouter['id'], lrouter['name'], internal_network=None,
            jobdata=jobdata, wait_for_exec=True,
            appliance_size=appliance_size,
            dist=(edge_type == nsxv_constants.VDR_EDGE))
        return task

    def _deploy_backup_edges(self, context, num,
                             appliance_size=nsxv_constants.LARGE,
                             edge_type=nsxv_constants.SERVICE_EDGE):
        """Asynchronously deploy edges to populate edge pool."""
        router_ids = [(vcns_const.BACKUP_ROUTER_PREFIX +
                       _uuid())[:vcns_const.EDGE_NAME_LEN]
                      for i in xrange(num)]
        with context.session.begin(subtransactions=True):
            for router_id in router_ids:
                nsxv_db.add_nsxv_router_binding(
                    context.session, router_id, None, None,
                    plugin_const.PENDING_CREATE,
                    appliance_size=appliance_size, edge_type=edge_type)
        for router_id in router_ids:
            fake_router = {
                'id': router_id,
                'name': router_id}
            self._deploy_edge(context, fake_router,
                              appliance_size=appliance_size,
                              edge_type=edge_type)

    def _delete_edge(self, context, router_binding):
        if router_binding['status'] == plugin_const.ERROR:
            LOG.warning(_LW("Start deleting %(router_id)s  corresponding"
                            "edge: %(edge_id)s due to status error"),
                        {'router_id': router_binding['router_id'],
                         'edge_id': router_binding['edge_id']})
        jobdata = {'context': context}
        nsxv_db.update_nsxv_router_binding(
            context.session, router_binding['router_id'],
            status=plugin_const.PENDING_DELETE)
        self.nsxv_manager.delete_edge(
            router_binding['router_id'], router_binding['edge_id'],
            jobdata=jobdata,
            dist=(router_binding['edge_type'] == nsxv_constants.VDR_EDGE))

    def _delete_backup_edges(self, context, backup_router_bindings, num):
        with context.session.begin(subtransactions=True):
            for binding in backup_router_bindings[:num]:
                nsxv_db.update_nsxv_router_binding(
                    context.session, binding['router_id'],
                    status=plugin_const.PENDING_DELETE)
        for binding in backup_router_bindings:
            # delete edge
            LOG.debug("Start deleting extra edge: %s in pool",
                      binding['edge_id'])
            jobdata = {
                'context': context
            }
            self.nsxv_manager.delete_edge(
                binding['router_id'], binding['edge_id'], jobdata=jobdata,
                dist=(binding['edge_type'] == nsxv_constants.VDR_EDGE))

    def _clean_all_error_edge_bindings(self, context):
        router_bindings = nsxv_db.get_nsxv_router_bindings(context.session)
        for binding in router_bindings:
            if (binding['router_id'].startswith(
                    vcns_const.BACKUP_ROUTER_PREFIX) and
                binding['status'] == plugin_const.ERROR):
                self._delete_edge(context, binding)

    def _get_backup_edge_bindings(self, context,
                                  appliance_size=nsxv_constants.LARGE,
                                  edge_type=nsxv_constants.SERVICE_EDGE):
        router_bindings = nsxv_db.get_nsxv_router_bindings(context.session)
        return [router_binding for router_binding in router_bindings
                if router_binding[
                    'router_id'].startswith(vcns_const.BACKUP_ROUTER_PREFIX)
                and router_binding['appliance_size'] == appliance_size
                and router_binding['edge_type'] == edge_type
                and router_binding['status'] != plugin_const.PENDING_DELETE
                and router_binding['status'] != plugin_const.ERROR]

    def _check_backup_edge_pools(self):
        admin_ctx = q_context.get_admin_context()
        self._clean_all_error_edge_bindings(admin_ctx)
        for edge_type, v in self.edge_pool_dicts.items():
            for edge_size in vcns_const.ALLOWED_EDGE_SIZES:
                if edge_size in v.keys():
                    edge_pool_range = v[edge_size]
                    self._check_backup_edge_pool(
                        edge_pool_range['minimum_pooled_edges'],
                        edge_pool_range['maximum_pooled_edges'],
                        appliance_size=edge_size, edge_type=edge_type)
                else:
                    self._check_backup_edge_pool(
                        0, 0,
                        appliance_size=edge_size, edge_type=edge_type)

    def _check_backup_edge_pool(self,
                                minimum_pooled_edges,
                                maximum_pooled_edges,
                                appliance_size=nsxv_constants.LARGE,
                                edge_type=nsxv_constants.SERVICE_EDGE):
        """Check edge pool's status and return one available edge for use."""
        admin_ctx = q_context.get_admin_context()
        backup_router_bindings = self._get_backup_edge_bindings(
            admin_ctx, appliance_size=appliance_size, edge_type=edge_type)
        backup_num = len(backup_router_bindings)
        if backup_num > maximum_pooled_edges:
            self._delete_backup_edges(admin_ctx, backup_router_bindings,
                                      backup_num - maximum_pooled_edges)
        elif backup_num < minimum_pooled_edges:
            self._deploy_backup_edges(admin_ctx,
                                      minimum_pooled_edges - backup_num,
                                      appliance_size=appliance_size,
                                      edge_type=edge_type)

    def check_edge_active_at_backend(self, edge_id):
        try:
            status = self.nsxv_manager.get_edge_status(edge_id)
            return (status == vcns_const.RouterStatus.ROUTER_STATUS_ACTIVE)
        except Exception:
            return False

    def _get_available_router_binding(self, context,
                                      appliance_size=nsxv_constants.LARGE,
                                      edge_type=nsxv_constants.SERVICE_EDGE):
        backup_router_bindings = self._get_backup_edge_bindings(
            context, appliance_size=appliance_size, edge_type=edge_type)
        for router_binding in backup_router_bindings:
            if (router_binding['status'] == plugin_const.ACTIVE):
                if not self.check_edge_active_at_backend(
                    router_binding['edge_id']):
                    self._delete_edge(context, router_binding)
                else:
                    return router_binding

    def _get_physical_provider_network(self, context, network_id):
        phy_net = nsxv_db.get_network_bindings(context.session, network_id)
        return (phy_net[0]['phy_uuid'] if (
            phy_net and phy_net[0]['phy_uuid'] != '') else self.dvs_id)

    def _create_sub_interface(self, context, network_id, network_name,
                              tunnel_index, address_groups,
                              port_group_id=None):
        # Get the physical port group /wire id of the network id
        mappings = nsx_db.get_nsx_switch_ids(context.session, network_id)
        if mappings:
            vcns_network_id = mappings[0]
        if port_group_id is None:
            portgroup = {'vlanId': 0,
                         'networkName': network_name,
                         'networkBindingType': 'Static',
                         'networkType': 'Isolation'}
            config_spec = {'networkSpec': portgroup}
            dvs_id = self._get_physical_provider_network(context, network_id)
            _, port_group_id = self.nsxv_manager.vcns.create_port_group(
                dvs_id, config_spec)

        interface = {
            'name': _uuid(),
            'tunnelId': tunnel_index,
            'logicalSwitchId': vcns_network_id,
            'isConnected': True
        }
        interface['addressGroups'] = {'addressGroups': address_groups}
        return port_group_id, interface

    def _getvnic_config(self, edge_id, vnic_index):
        _, vnic_config = self.nsxv_manager.get_interface(edge_id,
                                                         vnic_index)
        return vnic_config

    def _delete_dhcp_internal_interface(self, context, edge_id, vnic_index,
                                        tunnel_index, network_id):
        """Delete the dhcp internal interface."""

        LOG.debug("Query the vnic %s for DHCP Edge %s", vnic_index, edge_id)
        resource_id = (vcns_const.DHCP_EDGE_PREFIX + network_id)[:36]
        vnic_config = self._getvnic_config(edge_id, vnic_index)
        sub_interfaces = (vnic_config['subInterfaces']['subInterfaces'] if
                          'subInterfaces' in vnic_config else [])
        port_group_id = (vnic_config['portgroupId'] if 'portgroupId' in
                         vnic_config else None)
        for sub_interface in sub_interfaces:
            if tunnel_index == sub_interface['tunnelId']:
                LOG.debug("Delete the tunnel %d on vnic %d",
                          tunnel_index, vnic_index)
                (vnic_config['subInterfaces']['subInterfaces'].
                 remove(sub_interface))
                break

        # Clean the vnic if there is no sub-interface attached
        if len(sub_interfaces) == 0:
            header, _ = self.nsxv_manager.vcns.delete_interface(edge_id,
                                                                vnic_index)
            if port_group_id:
                objuri = header['location']
                job_id = objuri[objuri.rfind("/") + 1:]
                dvs_id = self._get_physical_provider_network(context,
                                                             network_id)
                self.nsxv_manager.delete_portgroup(dvs_id,
                                                   port_group_id,
                                                   job_id)
        else:
            self.nsxv_manager.vcns.update_interface(edge_id, vnic_config)

        # Delete the router binding or clean the edge appliance
        bindings = nsxv_db.get_nsxv_router_bindings(context.session)
        all_dhcp_edges = {binding['router_id']: binding['edge_id'] for
                          binding in bindings if binding['router_id'].
                          startswith(vcns_const.DHCP_EDGE_PREFIX)}
        for router_id in all_dhcp_edges:
            if (router_id != resource_id and
                all_dhcp_edges[router_id] == edge_id):
                nsxv_db.delete_nsxv_router_binding(context.session,
                                                   resource_id)
                return
        self._free_dhcp_edge_appliance(context, network_id)

    def _update_dhcp_internal_interface(self, context, edge_id, vnic_index,
                                        tunnel_index, network_id,
                                        address_groups):
        """Update the dhcp internal interface:
           1. Add a new vnic tunnel with the address groups
           2. Update the address groups to an existing tunnel
        """
        LOG.debug("Query the vnic %s for DHCP Edge %s", vnic_index, edge_id)
        _, vnic_config = self.nsxv_manager.get_interface(edge_id, vnic_index)
        sub_iface_dict = vnic_config.get('subInterfaces')
        port_group_id = vnic_config.get('portgroupId')
        new_tunnel_creation = True
        iface_list = []

        # Update the sub interface address groups for specific tunnel
        if sub_iface_dict:
            sub_interfaces = sub_iface_dict.get('subInterfaces')
            for sb in sub_interfaces:
                if tunnel_index == sb['tunnelId']:
                    new_tunnel_creation = False
                    sb['addressGroups']['addressGroups'] = address_groups
                    break
            iface_list = sub_interfaces

        # The first DHCP service creation, not update
        if new_tunnel_creation:
            network_name_item = [edge_id, str(vnic_index), str(tunnel_index)]
            network_name = ('-'.join(network_name_item) + _uuid())[:36]
            port_group_id, iface = self._create_sub_interface(
                context, network_id, network_name, tunnel_index,
                address_groups, port_group_id)

            iface_list.append(iface)

        LOG.debug("Update the vnic %d for DHCP Edge %s", vnic_index, edge_id)
        self.nsxv_manager.update_interface('fake_router_id', edge_id,
                                           vnic_index, port_group_id,
                                           tunnel_index,
                                           address_groups=iface_list)

    def _allocate_edge_appliance(self, context, resource_id, name,
                                 appliance_size=nsxv_constants.LARGE,
                                 dist=False):
        """Try to allocate one avaliable edge from pool."""

        edge_type = (nsxv_constants.VDR_EDGE if dist else
                     nsxv_constants.SERVICE_EDGE)
        lrouter = {'id': resource_id,
                   'name': name}
        edge_pool_range = self.edge_pool_dicts[edge_type].get(appliance_size)
        if edge_pool_range is None:
            nsxv_db.add_nsxv_router_binding(
                context.session, resource_id, None, None,
                plugin_const.PENDING_CREATE,
                appliance_size=appliance_size,
                edge_type=edge_type)
            task = self._deploy_edge(context, lrouter,
                                     appliance_size=appliance_size,
                                     edge_type=edge_type)
            task.wait(task_const.TaskState.RESULT)
            return

        self._clean_all_error_edge_bindings(context)
        available_router_binding = self._get_available_router_binding(
            context, appliance_size=appliance_size, edge_type=edge_type)
        # Synchronously deploy an edge if no avaliable edge in pool.
        if not available_router_binding:
            # store router-edge mapping binding
            nsxv_db.add_nsxv_router_binding(
                context.session, resource_id, None, None,
                plugin_const.PENDING_CREATE,
                appliance_size=appliance_size,
                edge_type=edge_type)
            task = self._deploy_edge(context, lrouter,
                                     appliance_size=appliance_size,
                                     edge_type=edge_type)
            task.wait(task_const.TaskState.RESULT)
        else:
            LOG.debug("Select edge: %(edge_id)s from pool for %(name)s",
                      {'edge_id': available_router_binding['edge_id'],
                       'name': name})
            # select the first avaliable edge in pool.
            nsxv_db.delete_nsxv_router_binding(
                context.session, available_router_binding['router_id'])
            nsxv_db.add_nsxv_router_binding(
                context.session,
                lrouter['id'],
                available_router_binding['edge_id'],
                None,
                plugin_const.PENDING_CREATE,
                appliance_size=appliance_size,
                edge_type=edge_type)
            fake_jobdata = {
                'context': context,
                'router_id': lrouter['id']}
            fake_userdata = {'jobdata': fake_jobdata,
                             'router_name': lrouter['name'],
                             'edge_id': available_router_binding['edge_id'],
                             'dist': dist}
            fake_task = tasks.Task(name='fake-deploy-edge-task',
                                   resource_id='fake-resource_id',
                                   execute_callback=None,
                                   userdata=fake_userdata)
            fake_task.status = task_const.TaskStatus.COMPLETED
            self.nsxv_manager.callbacks.edge_deploy_result(fake_task)
            # change edge's name at backend
            task = self.nsxv_manager.update_edge(
                resource_id, available_router_binding['edge_id'],
                name, None, appliance_size=appliance_size, dist=dist)
            task.wait(task_const.TaskState.RESULT)
        backup_num = len(self._get_backup_edge_bindings(
            context, appliance_size=appliance_size, edge_type=edge_type))
        self._deploy_backup_edges(
            context, edge_pool_range['minimum_pooled_edges'] - backup_num,
            appliance_size=appliance_size, edge_type=edge_type)

    def _free_edge_appliance(self, context, router_id):
        """Try to collect one edge to pool."""
        binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
        if not binding:
            LOG.warning(_LW("router binding for router: %s "
                            "not found"), router_id)
            return
        dist = (binding['edge_type'] == nsxv_constants.VDR_EDGE)
        edge_pool_range = self.edge_pool_dicts[binding['edge_type']].get(
            binding['appliance_size'])
        if (not self.check_edge_active_at_backend(binding['edge_id']) or
            not edge_pool_range):
            nsxv_db.update_nsxv_router_binding(
                context.session, router_id,
                status=plugin_const.PENDING_DELETE)
            # delete edge
            jobdata = {
                'context': context,
                'router_id': router_id
            }
            self.nsxv_manager.delete_edge(
                router_id, binding['edge_id'], jobdata=jobdata, dist=dist)
            return

        self._clean_all_error_edge_bindings(context)
        backup_router_bindings = self._get_backup_edge_bindings(
            context, appliance_size=binding['appliance_size'],
            edge_type=binding['edge_type'])
        backup_num = len(backup_router_bindings)
        # collect the edge to pool if pool not full
        if backup_num < edge_pool_range['maximum_pooled_edges']:
            LOG.debug("Collect edge: %s to pool", binding['edge_id'])
            nsxv_db.delete_nsxv_router_binding(
                context.session, router_id)
            backup_router_id = (vcns_const.BACKUP_ROUTER_PREFIX +
                                _uuid())[:vcns_const.EDGE_NAME_LEN]
            nsxv_db.add_nsxv_router_binding(
                context.session,
                backup_router_id,
                binding['edge_id'],
                None,
                plugin_const.ACTIVE,
                appliance_size=binding['appliance_size'],
                edge_type=binding['edge_type'])
            # change edge's name at backend
            task = self.nsxv_manager.update_edge(
                router_id, binding['edge_id'], backup_router_id, None,
                appliance_size=binding['appliance_size'], dist=dist)
            task.wait(task_const.TaskState.RESULT)

            # Refresh edge_vnic_bindings
            if not dist and binding['edge_id']:
                nsxv_db.clean_edge_vnic_binding(
                    context.session, binding['edge_id'])
                nsxv_db.init_edge_vnic_binding(
                    context.session, binding['edge_id'])
        else:
            nsxv_db.update_nsxv_router_binding(
                context.session, router_id,
                status=plugin_const.PENDING_DELETE)
            # delete edge
            jobdata = {
                'context': context,
                'router_id': router_id
            }
            self.nsxv_manager.delete_edge(
                router_id, binding['edge_id'], jobdata=jobdata, dist=dist)

    def _allocate_dhcp_edge_appliance(self, context, resource_id):
        resource_name = resource_id
        self._allocate_edge_appliance(
            context, resource_id, resource_name,
            appliance_size=vcns_const.SERVICE_SIZE_MAPPING['dhcp'])

    def _free_dhcp_edge_appliance(self, context, network_id):
        router_id = (vcns_const.DHCP_EDGE_PREFIX + network_id)[:36]
        self._free_edge_appliance(context, router_id)

    def create_lrouter(self, context, lrouter, lswitch=None, dist=False):
        """Create an edge for logical router support."""
        router_name = lrouter['name'] + '-' + lrouter['id']
        self._allocate_edge_appliance(
            context, lrouter['id'], router_name,
            appliance_size=vcns_const.SERVICE_SIZE_MAPPING['router'],
            dist=dist)

    def delete_lrouter(self, context, router_id, dist=False):
        self._free_edge_appliance(context, router_id)

    def update_dhcp_service_config(self, context, edge_id):
        """Reconfigure the DHCP to the edge."""
        # Get all networks attached to the edge
        edge_vnic_bindings = nsxv_db.get_edge_vnic_bindings_by_edge(
            context.session, edge_id)
        dhcp_networks = [edge_vnic_binding.network_id
                         for edge_vnic_binding in edge_vnic_bindings]
        ports = self.nsxv_plugin.get_ports(
            context, filters={'network_id': dhcp_networks})
        inst_ports = [port
                      for port in ports
                      if port['device_owner'].startswith("compute")]
        static_bindings = []
        for port in inst_ports:
            static_bindings.extend(
                self.nsxv_plugin._create_static_binding(context, port))
        dhcp_request = {
            'featureType': "dhcp_4.0",
            'enabled': True,
            'staticBindings': {'staticBindings': static_bindings}}
        self.nsxv_manager.vcns.reconfigure_dhcp_service(edge_id, dhcp_request)
        bindings_get = get_dhcp_binding_mappings(self.nsxv_manager, edge_id)
        # Refresh edge_dhcp_static_bindings attached to edge
        nsxv_db.clean_edge_dhcp_static_bindings_by_edge(
            context.session, edge_id)
        for mac_address, binding_id in bindings_get.items():
            nsxv_db.create_edge_dhcp_static_binding(context.session, edge_id,
                                                    mac_address, binding_id)

    def create_dhcp_edge_service(self, context, network_id,
                                 conflict_networks=None):
        """
        Create an edge if there is no available edge for dhcp service,
        Update an edge if there is available edge for dhcp service

        If new edge was allocated, return resource_id, else return None
        """
        if conflict_networks is None:
            conflict_networks = []
        # Query all conflict edges and available edges first
        conflict_edge_ids = []
        available_edge_ids = []
        router_bindings = nsxv_db.get_nsxv_router_bindings(context.session)
        all_dhcp_edges = {binding['router_id']: binding['edge_id'] for
                          binding in router_bindings if (binding['router_id'].
                          startswith(vcns_const.DHCP_EDGE_PREFIX) and
                          binding['status'] == plugin_const.ACTIVE)}
        if all_dhcp_edges:
            for net_id in conflict_networks:
                router_id = (vcns_const.DHCP_EDGE_PREFIX + net_id)[:36]
                edge_id = all_dhcp_edges.get(router_id)
                if (edge_id and edge_id not in conflict_edge_ids):
                    conflict_edge_ids.append(edge_id)

            for x in all_dhcp_edges.values():
                if (x not in conflict_edge_ids and
                    x not in available_edge_ids):
                    available_edge_ids.append(x)

        LOG.debug('The available edges %s, the conflict edges %s',
                  available_edge_ids, conflict_edge_ids)
        # Check if the network has one related dhcp edge
        resource_id = (vcns_const.DHCP_EDGE_PREFIX + network_id)[:36]
        dhcp_edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                            resource_id)

        # case 1: update a subnet to an existing dhcp edge
        if dhcp_edge_binding:
            edge_id = dhcp_edge_binding['edge_id']
            # Delete the existing vnic interface if there is overlap subnet
            if edge_id in conflict_edge_ids:
                old_binding = nsxv_db.get_edge_vnic_binding(
                    context.session, edge_id, network_id)
                old_vnic_index = old_binding['vnic_index']
                old_tunnel_index = old_binding['tunnel_index']
                # Cut off the port group/virtual wire connection
                nsxv_db.free_edge_vnic_by_network(context.session, edge_id,
                                                  network_id)
                # update dhcp service config on edge_id
                self.update_dhcp_service_config(context, edge_id)

                try:
                    self._delete_dhcp_internal_interface(context, edge_id,
                                                         old_vnic_index,
                                                         old_tunnel_index,
                                                         network_id)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_LE('Failed to delete vnic '
                                          '%(vnic_index)d tunnel '
                                          '%(tunnel_index)d on edge '
                                          '%(edge_id)s'),
                                      {'vnic_index': old_vnic_index,
                                       'tunnel_index': old_tunnel_index,
                                       'edge_id': edge_id})
                #Move the network to anther Edge and update vnic:
                #1. Find an available existing edge or create a new one
                #2. For the existing one, cut off the old port group connection
                #3. Create the new port group connection to the existing one
                #4. Update the address groups to the vnic
                if available_edge_ids:
                    new_id = available_edge_ids.pop()
                    nsxv_db.add_nsxv_router_binding(
                        context.session, resource_id,
                        new_id, None, plugin_const.ACTIVE,
                        appliance_size=vcns_const.SERVICE_SIZE_MAPPING['dhcp'])
                    nsxv_db.allocate_edge_vnic_with_tunnel_index(
                        context.session, new_id, network_id)
                else:
                    self._allocate_dhcp_edge_appliance(context, resource_id)
                    new_edge = nsxv_db.get_nsxv_router_binding(
                        context.session, resource_id)
                    nsxv_db.allocate_edge_vnic_with_tunnel_index(
                        context.session, new_edge['edge_id'], network_id)

                    # If a new Edge was allocated, return resource_id
                    return resource_id

        # case 2: attach the subnet to a new edge and update vnic
        else:
            # There is available one
            if available_edge_ids:
                new_id = available_edge_ids.pop()
                nsxv_db.add_nsxv_router_binding(
                    context.session, resource_id,
                    new_id, None, plugin_const.ACTIVE,
                    appliance_size=vcns_const.SERVICE_SIZE_MAPPING['dhcp'])
                nsxv_db.allocate_edge_vnic_with_tunnel_index(
                    context.session, new_id, network_id)
            else:
                self._allocate_dhcp_edge_appliance(context, resource_id)
                new_edge = nsxv_db.get_nsxv_router_binding(context.session,
                                                           resource_id)
                nsxv_db.allocate_edge_vnic_with_tunnel_index(
                    context.session, new_edge['edge_id'], network_id)

                # If a new Edge was allocated, return resource_id
                return resource_id

    def update_dhcp_edge_service(self, context, network_id,
                                 address_groups=None):
        """Update the subnet to the dhcp edge vnic."""
        if address_groups is None:
            address_groups = []

        resource_id = (vcns_const.DHCP_EDGE_PREFIX + network_id)[:36]
        edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                       resource_id)
        dhcp_binding = nsxv_db.get_edge_vnic_binding(context.session,
                                                     edge_binding['edge_id'],
                                                     network_id)
        if dhcp_binding:
            edge_id = dhcp_binding['edge_id']
            vnic_index = dhcp_binding['vnic_index']
            tunnel_index = dhcp_binding['tunnel_index']
            LOG.debug('Update the dhcp service for %s on vnic %d tunnel %d',
                      edge_id, vnic_index, tunnel_index)
            try:
                self._update_dhcp_internal_interface(
                    context, edge_id, vnic_index, tunnel_index, network_id,
                    address_groups)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE('Failed to update the dhcp service for '
                                      '%(edge_id)s  on vnic %(vnic_index)d '
                                      'tunnel %(tunnel_index)d'),
                                  {'edge_id': edge_id,
                                   'vnic_index': vnic_index,
                                   'tunnel_index': tunnel_index})
            ports = self.nsxv_plugin.get_ports(
                context, filters={'network_id': [network_id]})
            inst_ports = [port
                          for port in ports
                          if port['device_owner'].startswith("compute")]
            if inst_ports:
                # update dhcp service config for the new added network
                self.update_dhcp_service_config(context, edge_id)

    def delete_dhcp_edge_service(self, context, network_id):
        """Delete an edge for dhcp service."""
        resource_id = (vcns_const.DHCP_EDGE_PREFIX + network_id)[:36]
        edge_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                       resource_id)
        if edge_binding:
            dhcp_binding = nsxv_db.get_edge_vnic_binding(
                context.session, edge_binding['edge_id'], network_id)
            if dhcp_binding:
                edge_id = dhcp_binding['edge_id']
                vnic_index = dhcp_binding['vnic_index']
                tunnel_index = dhcp_binding['tunnel_index']

                LOG.debug("Delete the tunnel %d on vnic %d from DHCP Edge %s",
                          tunnel_index, vnic_index, edge_id)
                nsxv_db.free_edge_vnic_by_network(context.session,
                                                  edge_id,
                                                  network_id)
                try:
                    self._delete_dhcp_internal_interface(context, edge_id,
                                                         vnic_index,
                                                         tunnel_index,
                                                         network_id)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_LE('Failed to delete the tunnel '
                                          '%(tunnel_index)d on vnic '
                                          '%(vnic_index)d'
                                          'from DHCP Edge %(edge_id)s'),
                                      {'tunnel_index': tunnel_index,
                                       'vnic_index': vnic_index,
                                       'edge_id': edge_id})

    def get_plr_by_tlr_id(self, context, router_id):
        lswitch_id = nsxv_db.get_nsxv_router_binding(
            context.session, router_id).lswitch_id
        if lswitch_id:
            edge_vnic_bindings = nsxv_db.get_edge_vnic_bindings_by_int_lswitch(
                context.session, lswitch_id)
            if edge_vnic_bindings:
                for edge_vnic_binding in edge_vnic_bindings:
                    plr_router_id = nsxv_db.get_nsxv_router_bindings_by_edge(
                        context.session,
                        edge_vnic_binding.edge_id)[0].router_id
                    if plr_router_id != router_id:
                        return plr_router_id

    def create_plr_with_tlr_id(self, context, router_id, router_name):
        # Add an internal network preparing for connecting the VDR
        # to a PLR
        tlr_edge_id = nsxv_db.get_nsxv_router_binding(
            context.session, router_id).edge_id
        # First create an internal lswitch
        lswitch_name = ('int-' + router_name + router_id)[:36]
        virtual_wire = {"name": lswitch_name,
                        "tenantId": "virtual wire tenant"}
        config_spec = {"virtualWireCreateSpec": virtual_wire}
        vdn_scope_id = cfg.CONF.nsxv.vdn_scope_id
        h, lswitch_id = self.nsxv_manager.vcns.create_virtual_wire(
            vdn_scope_id, config_spec)

        # add vdr's external interface to the lswitch
        tlr_vnic_index = self.nsxv_manager.add_vdr_internal_interface(
            tlr_edge_id, lswitch_id,
            address=vcns_const.INTEGRATION_LR_IPADDRESS.split('/')[0],
            netmask=vcns_const.INTEGRATION_SUBNET_NETMASK,
            type="uplink")
        nsxv_db.create_edge_vnic_binding(
            context.session, tlr_edge_id, tlr_vnic_index, lswitch_id)
        # store the lswitch_id into nsxv_router_binding
        nsxv_db.update_nsxv_router_binding(
            context.session, router_id,
            lswitch_id=lswitch_id)

        # Handle plr relative op
        plr_router = {'name': router_name,
                      'id': (vcns_const.PLR_EDGE_PREFIX + _uuid())[:36]}
        self.create_lrouter(context, plr_router)
        binding = nsxv_db.get_nsxv_router_binding(
            context.session, plr_router['id'])
        plr_edge_id = binding['edge_id']
        plr_vnic_index = nsxv_db.allocate_edge_vnic(
            context.session, plr_edge_id, lswitch_id).vnic_index
        #TODO(berlin): the internal ip should change based on vnic_index
        self.nsxv_manager.update_interface(
            plr_router['id'], plr_edge_id, plr_vnic_index, lswitch_id,
            address=vcns_const.INTEGRATION_EDGE_IPADDRESS,
            netmask=vcns_const.INTEGRATION_SUBNET_NETMASK)
        return plr_router['id']

    def delete_plr_by_tlr_id(self, context, plr_id, router_id):
        # Delete plr's internal interface which connects to internal switch
        tlr_binding = nsxv_db.get_nsxv_router_binding(
            context.session, router_id)
        lswitch_id = tlr_binding.lswitch_id
        tlr_edge_id = tlr_binding.edge_id
        plr_edge_id = nsxv_db.get_nsxv_router_binding(
            context.session, plr_id).edge_id
        plr_vnic_index = nsxv_db.get_edge_vnic_binding(
            context.session, plr_edge_id, lswitch_id).vnic_index
        # Clear static routes before delete internal vnic
        task = self.nsxv_manager.update_routes(
            plr_id, plr_edge_id, None, [])
        task.wait(task_const.TaskState.RESULT)
        # Delete internal vnic
        task = self.nsxv_manager.delete_interface(
            plr_id, plr_edge_id, plr_vnic_index)
        task.wait(task_const.TaskState.RESULT)
        nsxv_db.free_edge_vnic_by_network(
            context.session, plr_edge_id, lswitch_id)
        # Delete the PLR
        self.delete_lrouter(context, plr_id)

        # Clear static routes of vdr
        task = self.nsxv_manager.update_routes(
            router_id, tlr_edge_id, None, [])
        task.wait(task_const.TaskState.RESULT)
        #First delete the vdr's external interface
        tlr_vnic_index = nsxv_db.get_edge_vnic_binding(
            context.session, tlr_edge_id, lswitch_id).vnic_index
        self.nsxv_manager.delete_vdr_internal_interface(
            tlr_edge_id, tlr_vnic_index)
        nsxv_db.delete_edge_vnic_binding_by_network(
            context.session, tlr_edge_id, lswitch_id)
        try:
            # Then delete the internal lswitch
            self.nsxv_manager.vcns.delete_virtual_wire(lswitch_id)
        except Exception:
            LOG.warning(_LW("Failed to delete virtual wire: %s"), lswitch_id)

    def get_routers_on_same_edge(self, context, router_id):
        edge_binding = nsxv_db.get_nsxv_router_binding(
            context.session, router_id)
        if edge_binding:
            return [
                binding['router_id']
                for binding in nsxv_db.get_nsxv_router_bindings_by_edge(
                    context.session, edge_binding['edge_id'])]
        else:
            return []

    def bind_router_on_available_edge(
        self, context, target_router_id,
        optional_router_ids, conflict_router_ids,
        conflict_network_ids, network_number):
        """Bind logical router on an available edge.
        Return True if the logical router is bound to a new edge.
        """
        optional_edge_ids = []
        conflict_edge_ids = []
        for router_id in optional_router_ids:
            binding = nsxv_db.get_nsxv_router_binding(
                context.session, router_id)
            if binding and binding.edge_id not in optional_edge_ids:
                optional_edge_ids.append(binding.edge_id)

        for router_id in conflict_router_ids:
            binding = nsxv_db.get_nsxv_router_binding(
                context.session, router_id)
            if binding and binding.edge_id not in conflict_edge_ids:
                conflict_edge_ids.append(binding.edge_id)
        optional_edge_ids = list(
            set(optional_edge_ids) - set(conflict_edge_ids))

        max_net_number = 0
        available_edge_id = None
        for edge_id in optional_edge_ids:
            edge_vnic_bindings = nsxv_db.get_edge_vnic_bindings_by_edge(
                context.session, edge_id)
            # one vnic is used to provide external access.
            net_number = vcns_const.MAX_VNIC_NUM - len(edge_vnic_bindings) - 1
            if net_number > max_net_number and net_number >= network_number:
                net_ids = [vnic_binding.network_id
                           for vnic_binding in edge_vnic_bindings]
                if not (set(conflict_network_ids) & set(net_ids)):
                    max_net_number = net_number
                    available_edge_id = edge_id
        if available_edge_id:
            edge_binding = nsxv_db.get_nsxv_router_bindings_by_edge(
                context.session, edge_id)[0]
            nsxv_db.add_nsxv_router_binding(
                context.session, target_router_id,
                edge_binding.edge_id, None,
                edge_binding.status,
                edge_binding.appliance_size,
                edge_binding.edge_type)
        else:
            router_name = ('shared' + '-' + _uuid())[:vcns_const.EDGE_NAME_LEN]
            self._allocate_edge_appliance(
                context, target_router_id, router_name,
                appliance_size=vcns_const.SERVICE_SIZE_MAPPING['router'])
            return True

    def unbind_router_on_edge(self, context, router_id):
        """Unbind a logical router from edge.
        Return True if no logical router bound to the edge.
        """
        # free edge if no other routers bound to the edge
        router_ids = self.get_routers_on_same_edge(context, router_id)
        if router_ids == [router_id]:
            self._free_edge_appliance(context, router_id)
            return True
        else:
            nsxv_db.delete_nsxv_router_binding(context.session, router_id)

    def is_router_conflict_on_edge(self, context, router_id,
                                   conflict_router_ids,
                                   conflict_network_ids,
                                   intf_num=0):
        router_ids = self.get_routers_on_same_edge(context, router_id)
        if set(router_ids) & set(conflict_router_ids):
            return True
        router_binding = nsxv_db.get_nsxv_router_binding(context.session,
                                                         router_id)
        edge_vnic_bindings = nsxv_db.get_edge_vnic_bindings_by_edge(
            context.session, router_binding.edge_id)
        if vcns_const.MAX_VNIC_NUM - len(edge_vnic_bindings) - 1 < intf_num:
            LOG.debug("There isn't available edge vnic for the router: %s",
                      router_id)
            return True
        for binding in edge_vnic_bindings:
            if binding.network_id in conflict_network_ids:
                return True
        return False


def create_lrouter(nsxv_manager, context, lrouter, lswitch=None, dist=False):
    """Create an edge for logical router support."""
    router_id = lrouter['id']
    router_name = lrouter['name'] + '-' + router_id
    appliance_size = vcns_const.SERVICE_SIZE_MAPPING['router']
    # store router-edge mapping binding
    nsxv_db.add_nsxv_router_binding(
        context.session, router_id, None, None,
        plugin_const.PENDING_CREATE,
        appliance_size=appliance_size)

    # deploy edge
    jobdata = {
        'router_id': router_id,
        'lrouter': lrouter,
        'lswitch': lswitch,
        'context': context
    }

    # deploy and wait until the deploy request has been requested
    # so we will have edge_id ready. The wait here should be fine
    # as we're not in a database transaction now
    task = nsxv_manager.deploy_edge(
        router_id, router_name, internal_network=None,
        dist=dist, jobdata=jobdata, appliance_size=appliance_size)
    task.wait(task_const.TaskState.RESULT)


def delete_lrouter(nsxv_manager, context, router_id, dist=False):
    binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
    if binding:
        nsxv_db.update_nsxv_router_binding(
            context.session, router_id,
            status=plugin_const.PENDING_DELETE)
        edge_id = binding['edge_id']
        # delete edge
        jobdata = {
            'context': context
        }
        task = nsxv_manager.delete_edge(router_id, edge_id,
                                        jobdata=jobdata, dist=dist)
        task.wait(task_const.TaskState.RESULT)
    else:
        LOG.warning(_LW("router binding for router: %s not found"), router_id)


def create_dhcp_service(context, nsxv_manager, network):
    """Create an Edge for dhcp service."""
    edge_name = "%s-%s" % (network['name'], network['id'])
    jobdata = {'network_id': network['id'], 'context': context}
    # port group id for vlan or virtual wire id for vxlan
    nsx_network_id = nsx_db.get_nsx_switch_ids(context.session,
                                               network['id'])[0]
    # Deploy an Edge for dhcp service
    return nsxv_manager.deploy_edge(
        network['id'], edge_name, nsx_network_id, jobdata=jobdata,
        appliance_size=vcns_const.SERVICE_SIZE_MAPPING['dhcp'])


def delete_dhcp_service(context, nsxv_manager, network_id):
    """Delete the Edge of dhcp service."""
    task = None
    binding = nsxv_db.get_dhcp_edge_network_binding(context.session,
                                                    network_id)
    if binding:
        dhcp_edge_id = binding['edge_id']
        vnic_index = binding['vnic_index']
        jobdata = {'context': context, 'network_id': network_id}

        edge_id = dhcp_edge_id

        LOG.debug("Delete the vnic %d from DHCP Edge %s",
                  vnic_index, edge_id)
        nsxv_manager.vcns.delete_interface(edge_id, vnic_index)
        nsxv_db.free_edge_vnic_by_network(
            context.session, edge_id, network_id)
        LOG.debug("Delete the DHCP Edge service %s", edge_id)
        task = nsxv_manager.delete_edge(network_id, edge_id, jobdata)

    return task


def get_dhcp_edge_id(context, network_id):
    # Query edge id
    resource_id = (vcns_const.DHCP_EDGE_PREFIX + network_id)[:36]
    binding = nsxv_db.get_nsxv_router_binding(context.session,
                                              resource_id)
    if binding:
        edge_id = binding['edge_id']
        return edge_id


def create_dhcp_bindings(context, nsxv_manager, network_id, bindings):
    edge_id = get_dhcp_edge_id(context, network_id)
    if edge_id:
        for binding in bindings:
            nsxv_manager.vcns.create_dhcp_binding(edge_id, binding)
        bindings_get = get_dhcp_binding_mappings(nsxv_manager, edge_id)
        mac_address_list = [binding['macAddress'] for binding in bindings]
        for mac_address, binding_id in bindings_get.items():
            if mac_address in mac_address_list:
                nsxv_db.create_edge_dhcp_static_binding(
                    context.session, edge_id,
                    mac_address, binding_id)


def get_dhcp_binding_mappings(nsxv_manager, edge_id):
    dhcp_config = query_dhcp_service_config(nsxv_manager, edge_id)
    bindings_get = {}
    if dhcp_config:
        for binding in dhcp_config['staticBindings']['staticBindings']:
            bindings_get[binding['macAddress'].lower()] = binding['bindingId']
    return bindings_get


def delete_dhcp_binding(context, nsxv_manager, network_id, mac_address):
    edge_id = get_dhcp_edge_id(context, network_id)
    dhcp_binding = nsxv_db.get_edge_dhcp_static_binding(
        context.session, edge_id, mac_address)
    if edge_id and dhcp_binding:
        nsxv_manager.vcns.delete_dhcp_binding(edge_id, dhcp_binding.binding_id)
        nsxv_db.delete_edge_dhcp_static_binding(
            context.session, edge_id, mac_address)


def query_dhcp_service_config(nsxv_manager, edge_id):
    """Retrieve the current DHCP configuration from the edge."""
    _, dhcp_config = nsxv_manager.vcns.query_dhcp_configuration(edge_id)
    return dhcp_config


def update_dhcp_internal_interface(context, nsxv_manager,
                                   network_id, address_groups, add=True):
    # Get the physical port group /wire id of the network id
    mappings = nsx_db.get_nsx_switch_ids(context.session, network_id)
    if mappings:
        vcns_network_id = mappings[0]

    # Get the DHCP Edge to update the internal interface
    binding = nsxv_db.get_dhcp_edge_network_binding(context.session,
                                                    network_id)
    if binding:
        dhcp_edge_id = binding['edge_id']
        vnic_index = binding['vnic_index']
        edge_id = dhcp_edge_id
        LOG.debug("Query the vnic %s for DHCP Edge %s",
                  vnic_index, edge_id)
        _, vnic_config = nsxv_manager.get_interface(edge_id, vnic_index)
        for addr_group in address_groups:
            vnic_addr_grp = vnic_config['addressGroups']['addressGroups']
            if add:
                vnic_addr_grp.append(addr_group)
            else:
                if addr_group in vnic_addr_grp:
                    vnic_addr_grp.remove(addr_group)

        LOG.debug("Update the vnic %d for DHCP Edge %s", vnic_index, edge_id)
        nsxv_manager.update_interface(
            'fake_router_id', edge_id, vnic_index, vcns_network_id,
            address_groups=vnic_config['addressGroups']['addressGroups'])


def get_router_edge_id(context, router_id):
    binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
    if binding:
        return binding['edge_id']


def update_gateway(nsxv_manager, context, router_id, nexthop, routes=None):
    binding = nsxv_db.get_nsxv_router_binding(context.session,
                                              router_id)
    edge_id = binding['edge_id']
    if routes is None:
        routes = []
    task = nsxv_manager.update_routes(router_id, edge_id, nexthop, routes)
    task.wait(task_const.TaskState.RESULT)


def update_routes(edge_manager, context, router_id, routes,
                  nexthop=None,
                  gateway_vnic_index=vcns_const.EXTERNAL_VNIC_INDEX):
    binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
    edge_id = binding['edge_id']
    edge_routes = []
    for route in routes:
        if not route.get('network_id'):
            LOG.warning(_LW("There is no network info for the route %s, so "
                            "the route entry would not be executed!"), route)
            continue
        if route.get('external'):
            edge_routes.append({
                'vnic_index': vcns_const.EXTERNAL_VNIC_INDEX,
                'cidr': route['destination'],
                'nexthop': route['nexthop']})
        else:
            edge_routes.append({
                'vnic_index': nsxv_db.get_edge_vnic_binding(
                    context.session, edge_id,
                    route['network_id'])['vnic_index'],
                'cidr': route['destination'],
                'nexthop': route['nexthop']})
    task = edge_manager.update_routes(router_id, edge_id, nexthop, edge_routes,
                                      gateway_vnic_index=gateway_vnic_index)
    task.wait(task_const.TaskState.RESULT)


def get_internal_lswitch_id_of_plr_tlr(context, router_id):
    return nsxv_db.get_nsxv_router_binding(
        context.session, router_id).lswitch_id


def get_internal_vnic_index_of_plr_tlr(context, router_id):
    router_binding = nsxv_db.get_nsxv_router_binding(
        context.session, router_id)
    edge_vnic_binding = nsxv_db.get_edge_vnic_binding(
        context.session, router_binding.edge_id, router_binding.lswitch_id)
    return edge_vnic_binding.vnic_index


def clear_gateway(nsxv_manager, context, router_id):
    return update_gateway(nsxv_manager, context, router_id, None)


def update_external_interface(
    nsxv_manager, context, router_id, ext_net_id,
    ipaddr, netmask, secondary=[]):
    binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
    net_bindings = nsxv_db.get_network_bindings(context.session, ext_net_id)
    if not net_bindings:
        vcns_network_id = nsxv_manager.external_network
    else:
        vcns_network_id = net_bindings[0].phy_uuid

    nsxv_manager.update_interface(router_id, binding['edge_id'],
                                  vcns_const.EXTERNAL_VNIC_INDEX,
                                  vcns_network_id,
                                  address=ipaddr,
                                  netmask=netmask,
                                  secondary=secondary)


def update_internal_interface(
    nsxv_manager, context, router_id, int_net_id, address_groups):
    # Get the pg/wire id of the network id
    mappings = nsx_db.get_nsx_switch_ids(context.session, int_net_id)
    if mappings:
        vcns_network_id = mappings[0]
    LOG.debug("Network id %(network_id)s corresponding ref is : "
              "%(net_moref)s", {'network_id': int_net_id,
                                'net_moref': vcns_network_id})

    # Get edge id
    binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
    edge_id = binding['edge_id']
    edge_vnic_binding = nsxv_db.get_edge_vnic_binding(
        context.session, edge_id, int_net_id)
    # if edge_vnic_binding is None, then first select one avaliable
    # internal vnic for connection.
    if not edge_vnic_binding:
        edge_vnic_binding = nsxv_db.allocate_edge_vnic(
            context.session, edge_id, int_net_id)

    nsxv_manager.update_interface(router_id, edge_id,
                                  edge_vnic_binding.vnic_index,
                                  vcns_network_id,
                                  address_groups=address_groups)


def add_vdr_internal_interface(
    nsxv_manager, context, router_id, int_net_id, address_groups):
    # Get the pg/wire id of the network id
    mappings = nsx_db.get_nsx_switch_ids(context.session, int_net_id)
    if mappings:
        vcns_network_id = mappings[0]
    LOG.debug("Network id %(network_id)s corresponding ref is : "
              "%(net_moref)s", {'network_id': int_net_id,
                                'net_moref': vcns_network_id})
    # Get edge id
    binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
    edge_id = binding['edge_id']
    edge_vnic_binding = nsxv_db.get_edge_vnic_binding(
        context.session, edge_id, int_net_id)
    if not edge_vnic_binding:
        vnic_index = nsxv_manager.add_vdr_internal_interface(
            edge_id, vcns_network_id,
            address_groups=address_groups)
        nsxv_db.create_edge_vnic_binding(
            context.session, edge_id, vnic_index, int_net_id)
    else:
        msg = (_("Distributed Router doesn't support multiple subnets "
                 "with same network attached to it."))
        raise n_exc.BadRequest(resource='vdr', msg=msg)


def update_vdr_internal_interface(
    nsxv_manager, context, router_id, int_net_id, address_groups):
    # Get the pg/wire id of the network id
    mappings = nsx_db.get_nsx_switch_ids(context.session, int_net_id)
    if mappings:
        vcns_network_id = mappings[0]
    LOG.debug("Network id %(network_id)s corresponding ref is : "
              "%(net_moref)s", {'network_id': int_net_id,
                                'net_moref': vcns_network_id})

    # Get edge id
    binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
    edge_id = binding['edge_id']
    edge_vnic_binding = nsxv_db.get_edge_vnic_binding(
        context.session, edge_id, binding.network_id)
    nsxv_manager.update_vdr_internal_interface(
        edge_id, edge_vnic_binding.vnic_index,
        vcns_network_id, address_groups=address_groups)


def delete_interface(nsxv_manager, context, router_id, network_id, dist=False):
    # Get the pg/wire id of the network id
    mappings = nsx_db.get_nsx_switch_ids(context.session, network_id)
    if mappings:
        vcns_network_id = mappings[0]
    LOG.debug("Network id %(network_id)s corresponding ref is : "
              "%(net_moref)s", {'network_id': network_id,
                                'net_moref': vcns_network_id})

    # Get edge id
    binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
    edge_id = binding['edge_id']
    edge_vnic_binding = nsxv_db.get_edge_vnic_binding(
        context.session, edge_id, network_id)
    if not dist:
        task = nsxv_manager.delete_interface(
            router_id, edge_id, edge_vnic_binding.vnic_index)
        task.wait(task_const.TaskState.RESULT)
        nsxv_db.free_edge_vnic_by_network(
            context.session, edge_id, network_id)
    else:
        nsxv_manager.delete_vdr_internal_interface(
            edge_id, edge_vnic_binding.vnic_index)
        nsxv_db.delete_edge_vnic_binding_by_network(
            context.session, edge_id, network_id)


def update_nat_rules(nsxv_manager, context, router_id, snat, dnat):
    binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
    task = nsxv_manager.update_nat_rules(
        router_id, binding['edge_id'], snat, dnat)
    task.wait(task_const.TaskState.RESULT)


def update_dnat_rules(nsxv_manager, context, router_id, dnat_rules):
    rtr_binding = nsxv_db.get_nsxv_router_binding(context.session, router_id)
    edge_id = rtr_binding['edge_id']

    for dnat_rule in dnat_rules:
        vnic_binding = nsxv_db.get_edge_vnic_binding(
            context.session,
            edge_id,
            dnat_rule['network_id'])

        vnic_index = vnic_binding['vnic_index']
        dnat_rule['vnic_index'] = vnic_index

    nsxv_manager.update_dnat_rules(edge_id, dnat_rules)


def clear_nat_rules(nsxv_manager, context, router_id):
    update_nat_rules(nsxv_manager, context, router_id, [], [])


def update_firewall(nsxv_manager, context, router_id, firewall,
                    allow_external=True):
    jobdata = {'context': context}
    edge_id = nsxv_db.get_nsxv_router_binding(
        context.session, router_id)['edge_id']
    task = nsxv_manager.asyn_update_firewall(router_id, edge_id,
                                             firewall, jobdata=jobdata,
                                             allow_external=allow_external)
    task.wait(task_const.TaskState.RESULT)


def check_network_in_use_at_backend(context, network_id):
    retries = max(cfg.CONF.nsxv.retries, 1)
    delay = 0.5
    for attempt in range(1, retries + 1):
        if attempt != 1:
            time.sleep(delay)
            delay = min(2 * delay, 60)
        edge_vnic_bindings = nsxv_db.get_edge_vnic_bindings_by_int_lswitch(
            context.session, network_id)
        if not edge_vnic_bindings:
            return
        LOG.warning(_('NSXv: network is still in use at the backend'))
    LOG.error(_('NSXv: network is still in use at the backend'))


class NsxVCallbacks(object):
    """Edge callback implementation Callback functions for
    asynchronous tasks.
    """
    def __init__(self, plugin):
        self.plugin = plugin

    def edge_deploy_started(self, task):
        """callback when deployment task started."""
        jobdata = task.userdata['jobdata']
        context = jobdata['context']
        router_id = jobdata.get('router_id')
        edge_id = task.userdata.get('edge_id')
        name = task.userdata.get('router_name')
        dist = task.userdata.get('dist')
        if edge_id:
            LOG.debug("Start deploying %(edge_id)s for router %(name)s",
                      {'edge_id': edge_id,
                       'name': name})
            nsxv_db.update_nsxv_router_binding(
                context.session, router_id, edge_id=edge_id)
            if not dist:
                # Init Edge vnic binding
                nsxv_db.init_edge_vnic_binding(
                    context.session, edge_id)
        else:
            LOG.debug("Failed to deploy Edge")
            if router_id:
                nsxv_db.update_nsxv_router_binding(
                    context.session, router_id,
                    status=plugin_const.ERROR)

    def edge_deploy_result(self, task):
        """callback when deployment task finished."""
        jobdata = task.userdata['jobdata']
        context = jobdata['context']
        name = task.userdata.get('router_name')
        dist = task.userdata.get('dist')
        router_id = jobdata['router_id']
        router_db = None
        if uuidutils.is_uuid_like(router_id):
            try:
                router_db = self.plugin._get_router(
                    context, router_id)
            except l3.RouterNotFound:
                # Router might have been deleted before deploy finished
                LOG.warning(_LW("Router %s not found"), name)

        if task.status == task_const.TaskStatus.COMPLETED:
            LOG.debug("Successfully deployed %(edge_id)s for router %(name)s",
                      {'edge_id': task.userdata['edge_id'],
                       'name': name})
            if (router_db and
                router_db['status'] == plugin_const.PENDING_CREATE):
                router_db['status'] = plugin_const.ACTIVE
            nsxv_db.update_nsxv_router_binding(
                context.session, router_id,
                status=plugin_const.ACTIVE)
        else:
            LOG.debug("Failed to deploy Edge for router %s", name)
            if router_db:
                router_db['status'] = plugin_const.ERROR
            nsxv_db.update_nsxv_router_binding(
                context.session, router_id,
                status=plugin_const.ERROR)
            if not dist and task.userdata.get('edge_id'):
                nsxv_db.clean_edge_vnic_binding(
                    context.session, task.userdata['edge_id'])

    def edge_update_result(self, task):
        LOG.debug("edge_update_result %d", task.status)

    def edge_delete_result(self, task):
        jobdata = task.userdata['jobdata']
        router_id = task.userdata['router_id']
        dist = task.userdata.get('dist')
        edge_id = task.userdata['edge_id']
        context = jobdata['context']
        try:
            nsxv_db.delete_nsxv_router_binding(context.session, router_id)
            if not dist:
                nsxv_db.clean_edge_vnic_binding(context.session, edge_id)
        except sa_exc.NoResultFound:
            LOG.warning(_LW("Router Binding for %s not found"), router_id)

    def interface_update_result(self, task):
        LOG.debug("interface_update_result %d", task.status)

    def interface_delete_result(self, task):
        LOG.debug("interface_delete_result %d", task.status)

    def snat_create_result(self, task):
        LOG.debug("snat_create_result %d", task.status)

    def snat_delete_result(self, task):
        LOG.debug("snat_delete_result %d", task.status)

    def dnat_create_result(self, task):
        LOG.debug("dnat_create_result %d", task.status)

    def dnat_delete_result(self, task):
        LOG.debug("dnat_delete_result %d", task.status)

    def routes_update_result(self, task):
        LOG.debug("routes_update_result %d", task.status)

    def nat_update_result(self, task):
        LOG.debug("nat_update_result %d", task.status)

    def _create_rule_id_mapping(
        self, context, edge_id, firewall, vcns_fw):
        for rule in vcns_fw['firewallRules']['firewallRules']:
            if rule.get('ruleTag'):
                index = rule['ruleTag'] - 1
                #TODO(linb):a simple filter of the retrieved rules which may be
                #created by other operations unintentionally
                if index < len(firewall['firewall_rule_list']):
                    rule_vseid = rule['ruleId']
                    rule_id = firewall['firewall_rule_list'][index].get('id')
                    if rule_id:
                        map_info = {
                            'rule_id': rule_id,
                            'rule_vseid': rule_vseid,
                            'edge_id': edge_id
                        }
                        nsxv_db.add_nsxv_edge_firewallrule_binding(
                            context.session, map_info)

    def firewall_update_result(self, task):
        LOG.debug("firewall_update_result %d", task.status)
        context = task.userdata['jobdata']['context']
        edge_id = task.userdata['edge_id']
        fw_config = task.userdata['fw_config']
        vcns_fw_config = task.userdata['vcns_fw_config']
        nsxv_db.cleanup_nsxv_edge_firewallrule_binding(
            context.session, edge_id)
        self._create_rule_id_mapping(
            context, edge_id, fw_config, vcns_fw_config)
