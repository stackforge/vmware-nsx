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

"""NSXv add availability zone to the router bindings table instead of
the resource pool column

Revision ID: 86a55205337c
Revises: aede17d51d0f
Create Date: 2016-07-12 09:18:44.450116
"""

# revision identifiers, used by Alembic.
revision = '86a55205337c'
down_revision = 'aede17d51d0f'

from alembic import op

from vmware_nsx.common import config  # noqa


def upgrade():
    op.alter_column('nsxv_router_bindings', 'resource_pool',
                    new_column_name='availability_zone',
                    existing_server_default='default')
