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

"""update nsx binding types

Revision ID: 2161a51b2f2f
Revises: ea7a72ab9643
Create Date: 2017-09-04 23:58:22.003350
"""

# revision identifiers, used by Alembic.
revision = '2161a51b2f2f'
down_revision = 'ea7a72ab9643'

from alembic import op
import sqlalchemy as sa


old_tz_binding_type_enum = sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                                   'vxlan', 'portgroup',
                                   name='tz_network_bindings_binding_type')
all_tz_binding_type_enum = sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                                   'vxlan', 'geneve', 'portgroup', 'nsx-net',
                                   name='tz_network_bindings_binding_type')


def upgrade():
    # add the new network types to the enum
    op.alter_column(
        'tz_network_bindings',
        'binding_type',
        type_=all_tz_binding_type_enum,
        existing_type=old_tz_binding_type_enum,
        existing_nullable=False)
