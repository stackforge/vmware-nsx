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

"""remove the foreign key constrain from all nsx lbaas DB tables

Revision ID: fc6308289aca
Revises: 717f7f63a219
Create Date: 2018-06-04 09-13:47:09.450116
"""

from alembic import op
from sqlalchemy.engine import reflection

# revision identifiers, used by Alembic.
revision = 'fc6308289aca'
down_revision = '717f7f63a219'


def upgrade():
    for table_name in ['nsxv3_lbaas_loadbalancers',
                       'nsxv3_lbaas_listeners',
                       'nsxv3_lbaas_pools',
                       'nsxv3_lbaas_monitors',
                       'nsxv3_lbaas_l7rules',
                       'nsxv3_lbaas_l7policies',
                       'nsxv_lbaas_loadbalancer_bindings',
                       'nsxv_lbaas_listener_bindings',
                       'nsxv_lbaas_pool_bindings',
                       'nsxv_lbaas_monitor_bindings',
                       'nsxv_lbaas_l7policy_bindings']:
        inspector = reflection.Inspector.from_engine(op.get_bind())
        fk_constraint = inspector.get_foreign_keys(table_name)[0]
        op.drop_constraint(fk_constraint.get('name'), table_name,
                           type_='foreignkey')
