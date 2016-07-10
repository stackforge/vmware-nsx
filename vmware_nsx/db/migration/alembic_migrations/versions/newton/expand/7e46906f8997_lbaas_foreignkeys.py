# Copyright 2016 VMware, Inc.
# All Rights Reserved
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

"""lbaas foreignkeys

Revision ID: 7e46906f8997
Revises: aede17d51d0f
Create Date: 2016-04-21 10:45:32.278433

"""

# revision identifiers, used by Alembic.
revision = '7e46906f8997'
down_revision = 'aede17d51d0f'

from alembic import op


def upgrade():
    op.create_foreign_key(
        'fk_lbaas_loadbalancers_id', 'nsxv_lbaas_loadbalancer_bindings',
        'lbaas_loadbalancers', ['loadbalancer_id'], ['id'], ondelete='CASCADE')

    op.create_foreign_key(
        'fk_lbaas_listeners_id', 'nsxv_lbaas_listener_bindings',
        'lbaas_listeners', ['listener_id'], ['id'], ondelete='CASCADE')

    op.create_foreign_key(
        'fk_lbaas_pools_id', 'nsxv_lbaas_pool_bindings',
        'lbaas_pools', ['pool_id'], ['id'], ondelete='CASCADE')

    op.create_foreign_key(
        'fk_lbaas_healthmonitors_id', 'nsxv_lbaas_monitor_bindings',
        'lbaas_healthmonitors', ['hm_id'], ['id'], ondelete='CASCADE')
