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

"""fix the dvs_id is too short

Revision ID: 8eda3a71ca67
Revises: 8c0a81a07691
Create Date: 2017-09-04 15:52:23.005265
"""

# revision identifiers, used by Alembic.
revision = '8eda3a71ca67'
down_revision = '8c0a81a07691'

from alembic import op
import sqlalchemy as sa


# milestone identifier, used by neutron-db-manage

def upgrade():
    op.alter_column('neutron_nsx_network_mappings', 'dvs_id',
                    nullable=True, existing_type=sa.String(length=255),
                    existing_nullable=False)
