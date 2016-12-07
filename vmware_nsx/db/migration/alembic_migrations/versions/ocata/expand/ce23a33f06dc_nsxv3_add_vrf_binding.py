# Copyright 2016 VMware, Inc.
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

"""nsxv3_add_vrf_binding

Revision ID: ce23a33f06dc
Revises: e816d4fe9d4f
Create Date: 2016-12-01 23:20:42.293155

"""

# revision identifiers, used by Alembic.
revision = 'ce23a33f06dc'
down_revision = 'e816d4fe9d4f'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'neutron_nsx_router_vrf_bindings',
        sa.Column('router_id', sa.String(36), nullable=False),
        sa.Column('vrf_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('router_id'))
