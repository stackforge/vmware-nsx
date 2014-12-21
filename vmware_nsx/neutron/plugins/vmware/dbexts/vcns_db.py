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

from neutron.i18n import _, _LE
from neutron.openstack.common import log as logging
from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.dbexts import vcns_models
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    constants as vcns_const)
from vmware_nsx.neutron.plugins.vmware.vshield.common import (
    exceptions as vcns_exc)

LOG = logging.getLogger(__name__)


def add_vcns_router_binding(session, router_id, vse_id, lswitch_id, status,
                            appliance_size=vcns_const.LARGE,
                            edge_type=vcns_const.SERVICE_EDGE):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsRouterBinding(
            router_id=router_id,
            edge_id=vse_id,
            lswitch_id=lswitch_id,
            status=status,
            appliance_size=appliance_size,
            edge_type=edge_type)
        session.add(binding)
        return binding


def get_vcns_router_binding(session, router_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.VcnsRouterBinding).
                filter_by(router_id=router_id).first())


def get_vcns_router_binding_by_edge(session, edge_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.VcnsRouterBinding).
                filter_by(edge_id=edge_id).first())


def get_vcns_router_bindings(session):
    with session.begin(subtransactions=True):
        return session.query(vcns_models.VcnsRouterBinding).all()


def update_vcns_router_binding(session, router_id, **kwargs):
    with session.begin(subtransactions=True):
        binding = (session.query(vcns_models.VcnsRouterBinding).
                   filter_by(router_id=router_id).one())
        for key, value in kwargs.iteritems():
            binding[key] = value


def delete_vcns_router_binding(session, router_id):
    with session.begin(subtransactions=True):
        binding = (session.query(vcns_models.VcnsRouterBinding).
                   filter_by(router_id=router_id).one())
        session.delete(binding)


#
# Edge Firewall binding methods
#
def add_vcns_edge_firewallrule_binding(session, map_info):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsEdgeFirewallRuleBinding(
            rule_id=map_info['rule_id'],
            rule_vseid=map_info['rule_vseid'],
            edge_id=map_info['edge_id'])
        session.add(binding)
        return binding


def delete_vcns_edge_firewallrule_binding(session, id):
    with session.begin(subtransactions=True):
        if not (session.query(vcns_models.VcnsEdgeFirewallRuleBinding).
                filter_by(rule_id=id).delete()):
            msg = _("Rule Resource binding with id:%s not found!") % id
            raise nsx_exc.NsxPluginException(err_msg=msg)


def get_vcns_edge_firewallrule_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.VcnsEdgeFirewallRuleBinding).
                filter_by(rule_id=id, edge_id=edge_id).first())


def get_vcns_edge_firewallrule_binding_by_vseid(
        session, edge_id, rule_vseid):
    with session.begin(subtransactions=True):
        try:
            return (session.query(vcns_models.VcnsEdgeFirewallRuleBinding).
                    filter_by(edge_id=edge_id, rule_vseid=rule_vseid).one())
        except exc.NoResultFound:
            msg = _("Rule Resource binding not found!")
            raise nsx_exc.NsxPluginException(err_msg=msg)


def cleanup_vcns_edge_firewallrule_binding(session, edge_id):
    with session.begin(subtransactions=True):
        session.query(
            vcns_models.VcnsEdgeFirewallRuleBinding).filter_by(
                edge_id=edge_id).delete()


def add_vcns_edge_vip_binding(session, map_info):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsEdgeVipBinding(
            vip_id=map_info['vip_id'],
            edge_id=map_info['edge_id'],
            vip_vseid=map_info['vip_vseid'],
            app_profileid=map_info['app_profileid'])
        session.add(binding)

    return binding


def get_vcns_edge_vip_binding(session, id):
    with session.begin(subtransactions=True):
        try:
            qry = session.query(vcns_models.VcnsEdgeVipBinding)
            return qry.filter_by(vip_id=id).one()
        except exc.NoResultFound:
            msg = _("VIP Resource binding with id:%s not found!") % id
            LOG.exception(msg)
            raise vcns_exc.VcnsNotFound(
                resource='router_service_binding', msg=msg)


def delete_vcns_edge_vip_binding(session, id):
    with session.begin(subtransactions=True):
        qry = session.query(vcns_models.VcnsEdgeVipBinding)
        if not qry.filter_by(vip_id=id).delete():
            msg = _("VIP Resource binding with id:%s not found!") % id
            LOG.exception(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)


def add_vcns_edge_pool_binding(session, map_info):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsEdgePoolBinding(
            pool_id=map_info['pool_id'],
            edge_id=map_info['edge_id'],
            pool_vseid=map_info['pool_vseid'])
        session.add(binding)

    return binding


def get_vcns_edge_pool_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.VcnsEdgePoolBinding).
                filter_by(pool_id=id, edge_id=edge_id).first())


def get_vcns_edge_pool_binding_by_vseid(session, edge_id, pool_vseid):
    with session.begin(subtransactions=True):
        try:
            qry = session.query(vcns_models.VcnsEdgePoolBinding)
            binding = qry.filter_by(edge_id=edge_id,
                                    pool_vseid=pool_vseid).one()
        except exc.NoResultFound:
            msg = (_("Pool Resource binding with edge_id:%(edge_id)s "
                     "pool_vseid:%(pool_vseid)s not found!") %
                   {'edge_id': edge_id, 'pool_vseid': pool_vseid})
            LOG.exception(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return binding


def delete_vcns_edge_pool_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        qry = session.query(vcns_models.VcnsEdgePoolBinding)
        if not qry.filter_by(pool_id=id, edge_id=edge_id).delete():
            msg = _("Pool Resource binding with id:%s not found!") % id
            LOG.exception(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)


def add_vcns_edge_monitor_binding(session, map_info):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsEdgeMonitorBinding(
            monitor_id=map_info['monitor_id'],
            edge_id=map_info['edge_id'],
            monitor_vseid=map_info['monitor_vseid'])
        session.add(binding)

    return binding


def get_vcns_edge_monitor_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.VcnsEdgeMonitorBinding).
                filter_by(monitor_id=id, edge_id=edge_id).first())


def delete_vcns_edge_monitor_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        qry = session.query(vcns_models.VcnsEdgeMonitorBinding)
        if not qry.filter_by(monitor_id=id, edge_id=edge_id).delete():
            msg = _("Monitor Resource binding with id:%s not found!") % id
            LOG.exception(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)


def get_edge_vnic_binding(session, edge_id, network_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.EdgeVnicBinding).
                filter_by(edge_id=edge_id, network_id=network_id).first())


def get_edge_vnic_bindings_by_edge(session, edge_id):
    query = session.query(vcns_models.EdgeVnicBinding)
    query = query.filter(vcns_models.EdgeVnicBinding.edge_id == edge_id,
                         vcns_models.EdgeVnicBinding.network_id is not None)
    return query.all()


def get_edge_vnic_bindings_by_int_lswitch(session, lswitch_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.EdgeVnicBinding).
                filter_by(network_id=lswitch_id).all())


def create_edge_vnic_binding(session, edge_id, vnic_index,
                             network_id, tunnel_index=-1):
    with session.begin(subtransactions=True):
        binding = vcns_models.EdgeVnicBinding(
            edge_id=edge_id,
            vnic_index=vnic_index,
            tunnel_index=tunnel_index,
            network_id=network_id)
        session.add(binding)


def delete_edge_vnic_binding_by_network(session, edge_id, network_id):
    with session.begin(subtransactions=True):
        binding = (session.query(vcns_models.EdgeVnicBinding).
                   filter_by(edge_id=edge_id, network_id=network_id).one())
        session.delete(binding)


def init_edge_vnic_binding(session, edge_id):
    """Init edge vnic binding to preallocated 10 available edge vnics."""

    with session.begin(subtransactions=True):
        for vnic_index in range(vcns_const.MAX_VNIC_NUM)[1:]:
            start = (vnic_index - 1) * vcns_const.MAX_TUNNEL_NUM
            stop = vnic_index * vcns_const.MAX_TUNNEL_NUM
            for tunnel_index in range(start, stop):
                binding = vcns_models.EdgeVnicBinding(
                    edge_id=edge_id,
                    vnic_index=vnic_index,
                    tunnel_index=tunnel_index + 1)
                session.add(binding)


def clean_edge_vnic_binding(session, edge_id):
    """Clean edge vnic binding."""

    with session.begin(subtransactions=True):
        (session.query(vcns_models.EdgeVnicBinding).
         filter_by(edge_id=edge_id).delete())


def allocate_edge_vnic(session, edge_id, network_id):
    """Allocate an avaliable edge vnic to network."""

    with session.begin(subtransactions=True):
        bindings = (session.query(vcns_models.EdgeVnicBinding).
                    filter_by(edge_id=edge_id, network_id=None).all())
        for binding in bindings:
            if binding['tunnel_index'] % vcns_const.MAX_TUNNEL_NUM == 1:
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
        binding = (session.query(vcns_models.EdgeVnicBinding).
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
        binding = (session.query(vcns_models.EdgeVnicBinding).
                   filter_by(edge_id=edge_id,
                             vnic_index=vnic_index,
                             tunnel_index=tunnel_index).one())
        binding['network_id'] = network_id
        session.add(binding)
        return binding


def get_dhcp_edge_network_binding(session, network_id):
    with session.begin(subtransactions=True):
        dhcp_router_edges = [binding['edge_id']
                             for binding in get_vcns_router_bindings(session)
                             if binding['router_id'].startswith(
                                 vcns_const.DHCP_EDGE_PREFIX)]
        bindings = (session.query(vcns_models.EdgeVnicBinding).
                    filter_by(network_id=network_id))
        for binding in bindings:
            edge_id = binding['edge_id']
            if edge_id in dhcp_router_edges:
                return binding


def free_edge_vnic_by_network(session, edge_id, network_id):
    """Free an edge vnic."""

    with session.begin(subtransactions=True):
        binding = (session.query(vcns_models.EdgeVnicBinding).
                   filter_by(edge_id=edge_id, network_id=network_id).one())
        binding['network_id'] = None
        session.add(binding)
        return binding


def create_edge_dhcp_static_binding(session, edge_id, mac_address, binding_id):
    with session.begin(subtransactions=True):
        binding = vcns_models.EdgeDhcpStaticBinding(
            edge_id=edge_id,
            mac_address=mac_address,
            binding_id=binding_id)
        session.add(binding)


def get_edge_dhcp_static_binding(session, edge_id, mac_address):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.EdgeDhcpStaticBinding).
                filter_by(edge_id=edge_id, mac_address=mac_address).first())


def delete_edge_dhcp_static_binding(session, edge_id, mac_address):
    with session.begin(subtransactions=True):
        session.query(vcns_models.EdgeDhcpStaticBinding).filter_by(
            edge_id=edge_id, mac_address=mac_address).delete()


def clean_edge_dhcp_static_bindings_by_edge(session, edge_id):
    with session.begin(subtransactions=True):
        session.query(vcns_models.EdgeDhcpStaticBinding).filter_by(
            edge_id=edge_id).delete()


def create_nsxv_internal_network(session, network_purpose, network_id):
    with session.begin(subtransactions=True):
        try:
            network = vcns_models.NsxvInternalNetworks(
                network_purpose=network_purpose,
                network_id=network_id)
            session.add(network)
        except db_exc.DBDuplicateEntry:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Duplicate internal network for purpose %s"),
                              network_purpose)


def get_nsxv_internal_network(session, network_purpose):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.NsxvInternalNetworks).
                filter_by(network_purpose=network_purpose).all())


def delete_nsxv_internal_network(session, network_purpose):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.NsxvInternalNetworks).
                filter_by(network_purpose=network_purpose).delete())


def create_nsxv_internal_edge(session, ext_ip_address, purpose, router_id):
    with session.begin(subtransactions=True):
        try:
            internal_edge = vcns_models.NsxvInternalEdges(
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
        return (session.query(vcns_models.NsxvInternalEdges).
                filter_by(ext_ip_address=ext_ip_address).all())


def get_nsxv_internal_edges_by_purpose(session, purpose):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.NsxvInternalEdges).
                filter_by(purpose=purpose).all())


def delete_nsxv_internal_edge(session, ext_ip_address):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.NsxvInternalEdges).
                filter_by(ext_ip_address=ext_ip_address).delete())
