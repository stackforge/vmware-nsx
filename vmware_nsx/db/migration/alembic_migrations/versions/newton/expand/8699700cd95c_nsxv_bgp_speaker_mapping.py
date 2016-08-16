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

"""nsxv_bgp_speaker_mapping

Revision ID: 8699700cd95c
Revises: 1b4eaffe4f31
Create Date: 2016-08-18 03:13:39.775670

"""

# revision identifiers, used by Alembic.
revision = '8699700cd95c'
down_revision = '7b5ec3caa9a4'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'nsxv_bgp_speaker_bindings',
        sa.Column('edge_id', sa.String(36), nullable=False),
        sa.Column('bgp_speaker_id', sa.String(36), nullable=False),
        sa.PrimaryKeyConstraint('edge_id'))
