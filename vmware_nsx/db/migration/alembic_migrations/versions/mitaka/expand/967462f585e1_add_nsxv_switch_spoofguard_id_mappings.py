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

"""add nsxv_switch_spoofguard_id_mappings table

Revision ID: 967462f585e1
Revises: 4c45bcadccf9
Create Date: 2016-02-23 18:22:01.998540

"""

# revision identifiers, used by Alembic.
revision = '967462f585e1'
down_revision = '4c45bcadccf9'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'nsxv_spoofguard_policy_nsx_switch_id_mappings',
        sa.Column('policy_id', sa.String(length=36), nullable=False),
        sa.Column('nsx_switch_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(
            ['policy_id'],
            ['nsxv_spoofguard_policy_network_mappings.policy_id'],
            name='nsxv_spoofguard_policy_nsx_switch_id_mappings_fk1',
            ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('policy_id')
    )
