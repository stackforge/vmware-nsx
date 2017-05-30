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

"""nsxv3_lbaas_mapping

Revision ID: ea7a72ab9643
Revises: 8699700cd95c
Create Date: 2017-06-12 16:59:48.021909

"""

# revision identifiers, used by Alembic.
revision = 'ea7a72ab9643'
down_revision = '8699700cd95c'


def upgrade():
    op.create_table(
        'nsxv3_lbaas_loadbalancer',
        sa.Column('loadbalancer_id', sa.String(36), nullable=False),
        sa.Column('lb_router_id', sa.String(36), nullable=False),
        sa.Column('lb_service_id', sa.String(36), nullable=False),
        sa.Column('vip_address', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('loadbalancer_id'))
    op.create_table(
        'nsxv3_lbaas_listener',
        sa.Column('loadbalancer_id', sa.String(36), nullable=False),
        sa.Column('listener_id', sa.String(36), nullable=False),
        sa.Column('app_profile_id', sa.String(36), nullable=False),
        sa.Column('lb_vs_id', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('loadbalancer_id', 'listener_id'))

    op.create_table(
        'nsxv3_lbaas_pool',
        sa.Column('loadbalancer_id', sa.String(36), nullable=False),
        sa.Column('pool_id', sa.String(36), nullable=False),
        sa.Column('lb_pool_id', sa.String(36), nullable=False),
        sa.Column('lb_vs_id', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('loadbalancer_id', 'pool_id'))

    op.create_table(
        'nsxv3_lbaas_monitor',
        sa.Column('loadbalancer_id', sa.String(36), nullable=False),
        sa.Column('pool_id', sa.String(36), nullable=False),
        sa.Column('hm_id', sa.String(36), nullable=False),
        sa.Column('lb_monitor_id', sa.String(64), nullable=False),
        sa.Column('lb_pool_id', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('loadbalancer_id', 'pool_id', 'hm_id'))
