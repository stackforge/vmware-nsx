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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes as attr
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from vmware_nsx.neutron.plugins.vmware.extensions import vnic_index as vnicidx

LOG = logging.getLogger(__name__)


class NeutronNsxPortIndexMapping(model_base.BASEV2):
    """Associates attached Neutron ports with the instance VNic index."""

    __tablename__ = 'neutron_nsx_port_index_mappings'
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    device_id = sa.Column(sa.String(255), nullable=False)
    index = sa.Column(sa.Integer, nullable=False)
    __table_args__ = (sa.UniqueConstraint(device_id, index),)

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly read port vnic-index
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("vnic_index", lazy='joined',
                            uselist=False, cascade='delete'))


class VnicIndexDbMixin(object):
    def _extend_port_vnic_index_binding(self, port_res, port_db):
        state = port_db.vnic_index
        port_res[vnicidx.VNIC_INDEX] = state.index if state else None

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.PORTS, ['_extend_port_vnic_index_binding'])

    def _get_port_vnic_index(self, context, port_id):
        """Returns the vnic index for the given port.
        If the port is not associated with any vnic then return None
        """
        session = context.session
        try:
            mapping = (session.query(NeutronNsxPortIndexMapping).
                       filter_by(port_id=port_id).one())
            return mapping['index']
        except exc.NoResultFound:
            LOG.debug("No record in DB for vnic-index of port %s", port_id)

    def _set_port_vnic_index_mapping(self, context, port_id, device_id, index):
        """Save the port vnic-index to DB."""
        session = context.session
        with session.begin(subtransactions=True):
            index_mapping_model = NeutronNsxPortIndexMapping(
                port_id=port_id, device_id=device_id, index=index)
            session.add(index_mapping_model)

    def _delete_port_vnic_index_mapping(self, context, port_id):
        """Delete the port vnic-index association."""
        session = context.session
        query = (session.query(NeutronNsxPortIndexMapping).
                 filter_by(port_id=port_id))
        query.delete()
