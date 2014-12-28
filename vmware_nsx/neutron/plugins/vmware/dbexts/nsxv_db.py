# Copyright 2013 VMware, Inc.
#
# All Rights Reserved.
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

from oslo.db import exception as db_exc
from oslo.utils import excutils
from sqlalchemy.orm import exc

import neutron.db.api as db
from neutron.i18n import _, _LE
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.dbexts import nsxv_models
from vmware_nsx.neutron.plugins.vmware.common import nsxv_constants
from vmware_nsx.neutron.plugins.vmware.vshield.common import constants


LOG = logging.getLogger(__name__)


def add_nsxv_router_binding(session, router_id, vse_id, lswitch_id, status,
                            appliance_size=nsxv_constants.LARGE,
                            edge_type=nsxv_constants.SERVICE_EDGE):
    with session.begin(subtransactions=True):
        binding = nsxv_models.NsxvRouterBinding(
            router_id=router_id,
            edge_id=vse_id,
            lswitch_id=lswitch_id,
            status=status,
            appliance_size=appliance_size,
            edge_type=edge_type)
        session.add(binding)
        return binding


def get_nsxv_router_binding(session, router_id):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvRouterBinding).
                filter_by(router_id=router_id).first())


def get_nsxv_router_binding_by_edge(session, edge_id):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvRouterBinding).
                filter_by(edge_id=edge_id).first())


def get_nsxv_router_bindings(session):
    with session.begin(subtransactions=True):
        return session.query(nsxv_models.NsxvRouterBinding).all()


def update_nsxv_router_binding(session, router_id, **kwargs):
    with session.begin(subtransactions=True):
        binding = (session.query(nsxv_models.NsxvRouterBinding).
                   filter_by(router_id=router_id).one())
        for key, value in kwargs.iteritems():
            binding[key] = value


def delete_nsxv_router_binding(session, router_id):
    with session.begin(subtransactions=True):
        binding = (session.query(nsxv_models.NsxvRouterBinding).
                   filter_by(router_id=router_id).one())
        session.delete(binding)


def get_edge_vnic_binding(session, edge_id, network_id):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvEdgeVnicBinding).
                filter_by(edge_id=edge_id, network_id=network_id).first())


def get_edge_vnic_bindings_by_edge(session, edge_id):
    query = session.query(nsxv_models.NsxvEdgeVnicBinding)
    query = query.filter(
        nsxv_models.NsxvEdgeVnicBinding.edge_id == edge_id,
        nsxv_models.NsxvEdgeVnicBinding.network_id is not None)
    return query.all()


def get_edge_vnic_bindings_by_int_lswitch(session, lswitch_id):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvEdgeVnicBinding).
                filter_by(network_id=lswitch_id).all())


def create_edge_vnic_binding(session, edge_id, vnic_index,
                             network_id, tunnel_index=-1):
    with session.begin(subtransactions=True):
        binding = nsxv_models.NsxvEdgeVnicBinding(
            edge_id=edge_id,
            vnic_index=vnic_index,
            tunnel_index=tunnel_index,
            network_id=network_id)
        session.add(binding)


def delete_edge_vnic_binding_by_network(session, edge_id, network_id):
    with session.begin(subtransactions=True):
        binding = (session.query(nsxv_models.NsxvEdgeVnicBinding).
                   filter_by(edge_id=edge_id, network_id=network_id).one())
        session.delete(binding)


def init_edge_vnic_binding(session, edge_id):
    """Init edge vnic binding to preallocated 10 available edge vnics."""

    with session.begin(subtransactions=True):
        for vnic_index in range(constants.MAX_VNIC_NUM)[1:]:
            start = (vnic_index - 1) * constants.MAX_TUNNEL_NUM
            stop = vnic_index * constants.MAX_TUNNEL_NUM
            for tunnel_index in range(start, stop):
                binding = nsxv_models.NsxvEdgeVnicBinding(
                    edge_id=edge_id,
                    vnic_index=vnic_index,
                    tunnel_index=tunnel_index + 1)
                session.add(binding)


def clean_edge_vnic_binding(session, edge_id):
    """Clean edge vnic binding."""

    with session.begin(subtransactions=True):
        (session.query(nsxv_models.NsxvEdgeVnicBinding).
         filter_by(edge_id=edge_id).delete())


def allocate_edge_vnic(session, edge_id, network_id):
    """Allocate an avaliable edge vnic to network."""

    with session.begin(subtransactions=True):
        bindings = (session.query(nsxv_models.NsxvEdgeVnicBinding).
                    filter_by(edge_id=edge_id, network_id=None).all())
        for binding in bindings:
            if binding['tunnel_index'] % constants.MAX_TUNNEL_NUM == 1:
                binding['network_id'] = network_id
                session.add(binding)
                return binding
    msg = (_("Failed to allocate one available vnic on edge_id: "
             ":%(edge_id)s to network_id: %(network_id)s") %
           {'edge_id': edge_id, 'network_id': network_id})
    LOG.exception(msg)
    raise nsx_exc.NsxPluginException(err_msg=msg)


def allocate_edge_vnic_with_tunnel_index(session, edge_id, network_id):
    """Allocate an avaliable edge vnic with tunnel index to network."""

    with session.begin(subtransactions=True):
        binding = (session.query(nsxv_models.NsxvEdgeVnicBinding).
                   filter_by(edge_id=edge_id, network_id=None).first())
        if not binding:
            msg = (_("Failed to allocate one available vnic on edge_id: "
                     ":%(edge_id)s to network_id: %(network_id)s") %
                   {'edge_id': edge_id, 'network_id': network_id})
            LOG.exception(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)
        binding['network_id'] = network_id
        session.add(binding)
    return binding


def allocate_specific_edge_vnic(session, edge_id, vnic_index,
                                tunnel_index, network_id):
    """Allocate an specific edge vnic to network."""

    with session.begin(subtransactions=True):
        binding = (session.query(nsxv_models.NsxvEdgeVnicBinding).
                   filter_by(edge_id=edge_id,
                             vnic_index=vnic_index,
                             tunnel_index=tunnel_index).one())
        binding['network_id'] = network_id
        session.add(binding)
    return binding


def get_dhcp_edge_network_binding(session, network_id):
    with session.begin(subtransactions=True):
        dhcp_router_edges = [binding['edge_id']
                             for binding in get_nsxv_router_bindings(session)
                             if binding['router_id'].startswith(
                                 constants.DHCP_EDGE_PREFIX)]
        bindings = (session.query(nsxv_models.NsxvEdgeVnicBinding).
                    filter_by(network_id=network_id))
        for binding in bindings:
            edge_id = binding['edge_id']
            if edge_id in dhcp_router_edges:
                return binding


def free_edge_vnic_by_network(session, edge_id, network_id):
    """Free an edge vnic."""

    with session.begin(subtransactions=True):
        binding = (session.query(nsxv_models.NsxvEdgeVnicBinding).
                   filter_by(edge_id=edge_id, network_id=network_id).one())
        binding['network_id'] = None
        session.add(binding)
    return binding


def create_edge_dhcp_static_binding(session, edge_id, mac_address, binding_id):
    with session.begin(subtransactions=True):
        binding = nsxv_models.NsxvEdgeDhcpStaticBinding(
            edge_id=edge_id,
            mac_address=mac_address,
            binding_id=binding_id)
        session.add(binding)


def get_edge_dhcp_static_binding(session, edge_id, mac_address):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvEdgeDhcpStaticBinding).
                filter_by(edge_id=edge_id, mac_address=mac_address).first())


def delete_edge_dhcp_static_binding(session, edge_id, mac_address):
    with session.begin(subtransactions=True):
        session.query(nsxv_models.NsxvEdgeDhcpStaticBinding).filter_by(
            edge_id=edge_id, mac_address=mac_address).delete()


def clean_edge_dhcp_static_bindings_by_edge(session, edge_id):
    with session.begin(subtransactions=True):
        session.query(nsxv_models.NsxvEdgeDhcpStaticBinding).filter_by(
            edge_id=edge_id).delete()


def create_nsxv_internal_network(session, network_purpose, network_id):
    with session.begin(subtransactions=True):
        try:
            network = nsxv_models.NsxvInternalNetworks(
                network_purpose=network_purpose,
                network_id=network_id)
            session.add(network)
        except db_exc.DBDuplicateEntry:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Duplicate internal network for purpose %s"),
                              network_purpose)


def get_nsxv_internal_network(session, network_purpose):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvInternalNetworks).
                filter_by(network_purpose=network_purpose).all())


def delete_nsxv_internal_network(session, network_purpose):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvInternalNetworks).
                filter_by(network_purpose=network_purpose).delete())


def create_nsxv_internal_edge(session, ext_ip_address, purpose, router_id):
    with session.begin(subtransactions=True):
        try:
            internal_edge = nsxv_models.NsxvInternalEdges(
                ext_ip_address=ext_ip_address,
                purpose=purpose,
                router_id=router_id)
            session.add(internal_edge)
        except db_exc.DBDuplicateEntry:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Duplicate internal Edge IP %s"),
                              ext_ip_address)


def get_nsxv_internal_edge(session, ext_ip_address):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvInternalEdges).
                filter_by(ext_ip_address=ext_ip_address).all())


def get_nsxv_internal_edges_by_purpose(session, purpose):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvInternalEdges).
                filter_by(purpose=purpose).all())


def delete_nsxv_internal_edge(session, ext_ip_address):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvInternalEdges).
                filter_by(ext_ip_address=ext_ip_address).delete())


def add_neutron_nsx_section_mapping(session, neutron_id, ip_section_id,
                                    mac_section_id=None):
    with session.begin(subtransactions=True):
        mapping = nsxv_models.NsxvSectionMapping(
            neutron_id=neutron_id, ip_section_id=ip_section_id,
            mac_section_id=mac_section_id)
        session.add(mapping)
    return mapping


def add_neutron_nsx_rule_mapping(session, neutron_id, nsx_rule_id):
    with session.begin(subtransactions=True):
        mapping = nsxv_models.NsxvRuleMapping(neutron_id=neutron_id,
                                              nsx_rule_id=nsx_rule_id)
        session.add(mapping)
    return mapping


def add_neutron_nsx_port_vnic_mapping(session, neutron_id, nsx_id):
    with session.begin(subtransactions=True):
        mapping = nsxv_models.NsxvPortVnicMapping(
            neutron_id=neutron_id, nsx_id=nsx_id)
        session.add(mapping)
    return mapping


def get_nsx_section(session, neutron_id):
    try:
        mapping = (session.query(nsxv_models.NsxvSectionMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping
    except exc.NoResultFound:
        LOG.debug("NSX identifiers for neutron security group %s not yet "
                  "stored in Neutron DB", neutron_id)


def get_nsx_rule_id(session, neutron_id):
    try:
        mapping = (session.query(nsxv_models.NsxvRuleMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_rule_id']
    except exc.NoResultFound:
        LOG.debug("NSX identifiers for neutron rule %s not yet "
                  "stored in Neutron DB", neutron_id)


def get_nsx_vnic_id(session, neutron_id):
    try:
        mapping = (session.query(nsxv_models.NsxvPortVnicMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_id']
    except exc.NoResultFound:
        LOG.debug("NSX identifiers for neutron port %s not yet "
                  "stored in Neutron DB", neutron_id)


def get_network_bindings(session, network_id):
    session = session or db.get_session()
    return (session.query(nsxv_models.NsxvTzNetworkBinding).
            filter_by(network_id=network_id).
            all())


def get_network_bindings_by_vlanid_and_physical_net(session, vlan_id,
                                                    phy_uuid):
    session = session or db.get_session()
    return (session.query(nsxv_models.NsxvTzNetworkBinding).
            filter_by(vlan_id=vlan_id, phy_uuid=phy_uuid).
            all())


def delete_network_bindings(session, network_id):
    return (session.query(nsxv_models.NsxvTzNetworkBinding).
            filter_by(network_id=network_id).delete())


def add_network_binding(session, network_id, binding_type, phy_uuid, vlan_id):
    with session.begin(subtransactions=True):
        binding = nsxv_models.NsxvTzNetworkBinding(network_id, binding_type,
                                                   phy_uuid, vlan_id)
        session.add(binding)
    return binding


def get_network_bindings_by_vlanid(session, vlan_id):
    session = session or db.get_session()
    return (session.query(nsxv_models.NsxvTzNetworkBinding).
            filter_by(vlan_id=vlan_id).
            all())


#
# Edge Firewall binding methods
#
def add_nsxv_edge_firewallrule_binding(session, map_info):
    with session.begin(subtransactions=True):
        binding = nsxv_models.NsxvEdgeFirewallRuleBinding(
            rule_id=map_info['rule_id'],
            rule_vseid=map_info['rule_vseid'],
            edge_id=map_info['edge_id'])
        session.add(binding)
    return binding


def delete_nsxv_edge_firewallrule_binding(session, id):
    with session.begin(subtransactions=True):
        if not (session.query(nsxv_models.NsxvEdgeFirewallRuleBinding).
                filter_by(rule_id=id).delete()):
            msg = _("Rule Resource binding with id:%s not found!") % id
            raise nsx_exc.NsxPluginException(err_msg=msg)


def get_nsxv_edge_firewallrule_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        return (session.query(nsxv_models.NsxvEdgeFirewallRuleBinding).
                filter_by(rule_id=id, edge_id=edge_id).first())


def get_nsxv_edge_firewallrule_binding_by_vseid(
        session, edge_id, rule_vseid):
    with session.begin(subtransactions=True):
        try:
            return (session.query(nsxv_models.NsxvEdgeFirewallRuleBinding).
                    filter_by(edge_id=edge_id, rule_vseid=rule_vseid).one())
        except exc.NoResultFound:
            msg = _("Rule Resource binding not found!")
            raise nsx_exc.NsxPluginException(err_msg=msg)


def cleanup_nsxv_edge_firewallrule_binding(session, edge_id):
    with session.begin(subtransactions=True):
        session.query(
            nsxv_models.NsxvEdgeFirewallRuleBinding).filter_by(
                edge_id=edge_id).delete()
