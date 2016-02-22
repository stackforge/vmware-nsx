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

"""Add primary key constraint on nsxv_spoofguard_policy_network_mappings

Revision ID: 68a2009c1ea4
Revises: 3c88bdea3054
Create Date: 2016-02-22 06:07:58.492521

"""

# revision identifiers, used by Alembic.
revision = '68a2009c1ea4'
down_revision = '3c88bdea3054'

from alembic import op


def upgrade():
    # Foreign key constraint needed to be dropped before
    # making changes to primary key constraint.
    op.drop_constraint(
        'nsxv_spoofguard_policy_network_mappings_ibfk_1',
        'nsxv_spoofguard_policy_network_mappings',
        type_='foreignkey',
    )
    # Drop the existing primary key constraint which consisted
    # of network_id column only.
    op.drop_constraint(
        'PRIMARY',
        'nsxv_spoofguard_policy_network_mappings',
        type_='primary'
    )
    # Create the new primary key constraint consisting of both
    # the network_id and policy_id columns as primary keys.
    op.create_primary_key(
        'pk_nsxv_spoofguard_policy_network_mappings',
        'nsxv_spoofguard_policy_network_mappings',
        ['policy_id', 'network_id']
    )
    # Recreate the foreign key constraint dropped earlier.
    op.create_foreign_key(
        'nsxv_spoofguard_policy_network_mappings_ibfk_1',
        'nsxv_spoofguard_policy_network_mappings',
        'networks',
        ['network_id'], ['id']
    )
