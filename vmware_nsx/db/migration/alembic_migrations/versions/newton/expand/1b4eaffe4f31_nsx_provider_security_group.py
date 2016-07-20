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

"""NSX Adds a 'provider' attribute to security-group

Revision ID: 1b4eaffe4f31
Revises: 633514d94b93
Create Date: 2016-07-17 11:30:31.263918

"""

# revision identifiers, used by Alembic.
revision = '1b4eaffe4f31'
down_revision = '633514d94b93'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('nsx_extended_security_group_properties',
                  sa.Column('provider', sa.Boolean(), default=False,
                            server_default=sa.false(), nullable=False))
