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

"""NSXv add dns search domain to subnets

Revision ID: 3e4dccfe6fb4
Revises: 2c87aedb206f
Create Date: 2016-03-20 07:28:35.369938

"""

# revision identifiers, used by Alembic.
revision = '3e4dccfe6fb4'
down_revision = '2c87aedb206f'

from alembic import op
import sqlalchemy as sa


def upgrade():
    secgroup_prop_table = op.create_table(
        'nsx_extended_security_group_properties',
        sa.Column('security_group_id', sa.String(36), nullable=False),
        sa.Column('logging', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['security_group_id'],
                                ['securitygroups.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('security_group_id')
    )

    op.bulk_insert(secgroup_prop_table, get_values())
    op.drop_column('nsxv_security_group_section_mappings', 'logging')


def get_values():
    values = []
    session = sa.orm.Session(bind=op.get_bind())
    section_mapping_table = sa.Table('nsxv_security_group_section_mappings',
                                     sa.MetaData(),
                                     sa.Column('neutron_id', sa.String(36)),
                                     sa.Column('logging', sa.Boolean(),
                                               nullable=False))

    for row in session.query(section_mapping_table).all():
        values.append({'security_group_id': row.neutron_id,
                       'logging': row.logging})
    session.commit()
    return values
