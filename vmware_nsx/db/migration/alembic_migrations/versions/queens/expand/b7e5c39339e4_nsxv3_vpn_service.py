# Copyright 2017 VMware, Inc.
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

"""nsxv3_vpn_service

Revision ID: b7e5c39339e4
Revises: 0dbeda408e41
Create Date: 2018-01-29 13:16:40.846088

"""

# revision identifiers, used by Alembic.
revision = 'b7e5c39339e4'
down_revision = '0dbeda408e41'

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.create_table(
        'neutron_nsx_vpn_local_endpoint_mappings',
        sa.Column('neutron_id', sa.String(36), nullable=False),
        sa.Column('local_endpoint_id', sa.String(36), nullable=False),
        sa.Column('local_endpoint_ip', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True))
