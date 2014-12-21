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


import sqlalchemy as sa

from neutron.db import model_base
from neutron.db import models_v2
from vmware_nsx.neutron.plugins.vmware.vshield.common import constants


class NsxvRouterBinding(model_base.BASEV2, models_v2.HasStatusDescription):
    """Represents the mapping between neutron router and vShield Edge."""

    __tablename__ = 'nsxv_router_bindings'

    # no ForeignKey to routers.id because for now, a router can be removed
    # from routers when delete_router is executed, but the binding is only
    # removed after the Edge is deleted
    router_id = sa.Column(sa.String(36),
                          primary_key=True)
    edge_id = sa.Column(sa.String(16),
                        nullable=True)
    lswitch_id = sa.Column(sa.String(36),
                           nullable=True)
    appliance_size = sa.Column(sa.Enum(constants.COMPACT,
                                       constants.LARGE,
                                       constants.XLARGE,
                                       constants.QUADLARGE))
    edge_type = sa.Column(sa.Enum(constants.SERVICE_EDGE,
                                  constants.VDR_EDGE))


class EdgeVnicBinding(model_base.BASEV2):
    """Represents mapping between vShield Edge vnic and neutron netowrk."""

    __tablename__ = 'edge_vnic_bindings'

    # every edge has at most 10 availiable vnics for network mapping
    edge_id = sa.Column(sa.String(36),
                        primary_key=True)
    vnic_index = sa.Column(sa.Integer(),
                           primary_key=True)
    tunnel_index = sa.Column(sa.Integer(),
                             primary_key=True)
    network_id = sa.Column(sa.String(36),
                           nullable=True)


class EdgeDhcpStaticBinding(model_base.BASEV2):
    """Represents mapping between mac addr and bindingId."""

    __tablename__ = 'edge_dhcp_static_bindings'

    edge_id = sa.Column(sa.String(36), primary_key=True)
    mac_address = sa.Column(sa.String(32), primary_key=True)
    binding_id = sa.Column(sa.String(36), nullable=False)


class NsxvInternalNetworks(model_base.BASEV2):
    """Represents internal networks between NSXV plugin elements."""

    __tablename__ = 'nsxv_internal_networks'

    network_purpose = sa.Column(
        sa.Enum(constants.InternalEdgePurposes.INTER_EDGE_PURPOSE),
        primary_key=True)
    network_id = sa.Column(sa.String(36), nullable=False)


class NsxvInternalEdges(model_base.BASEV2):
    """Represents internal Edge appliances for NSXV plugin operations."""

    __tablename__ = 'nsxv_internal_edges'

    ext_ip_address = sa.Column(sa.String(64), primary_key=True)
    router_id = sa.Column(sa.String(36), nullable=False)
    purpose = sa.Column(
        sa.Enum(constants.InternalEdgePurposes.INTER_EDGE_PURPOSE))
