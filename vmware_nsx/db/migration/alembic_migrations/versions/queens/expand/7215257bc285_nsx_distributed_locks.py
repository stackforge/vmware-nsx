# Copyright 2018 VMware, Inc.
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

"""nsx_distributed_locks

Revision ID: 7215257bc285
Revises: 0dbeda408e41
Create Date: 2018-02-07 15:00:40.111099

"""

# revision identifiers, used by Alembic.
revision = '7215257bc285'
down_revision = '0dbeda408e41'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'nsx_distributed_locks',
        sa.Column('name', sa.String(36), nullable=False),
        sa.Column('owner', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('name'))
