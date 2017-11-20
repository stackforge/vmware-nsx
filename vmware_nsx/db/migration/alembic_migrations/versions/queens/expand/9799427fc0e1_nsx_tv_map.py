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


from alembic import op
import sqlalchemy as sa

"""nsx map project to plugin

Revision ID: 9799427fc0e1
Revises: ea7a72ab9643
Create Date: 2017-06-12 16:59:48.021909

"""

# revision identifiers, used by Alembic.
revision = '9799427fc0e1'
down_revision = 'ea7a72ab9643'

plugin_type_enum = sa.Enum('nsx-v', 'nsx-v3',
                           name='nsx_plugin_type')


def upgrade():
    op.create_table(
        'nsx_project_plugin_mappings',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('project_id', sa.String(36), nullable=False),
        sa.Column('plugin', plugin_type_enum, nullable=False),
        sa.PrimaryKeyConstraint('id', 'project_id'))
