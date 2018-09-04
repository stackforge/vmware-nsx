# Copyright 2018 VMware, Inc.
#
# All Rights Reserved.
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

from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import models_v2
from oslo_db.sqlalchemy import models


class NsxpProjectDomainMapping(model_base.BASEV2, models.TimestampMixin):
    """Represents the mapping between neutron project (tenant) and the
    NSX policy domain.
    """

    __tablename__ = 'nsxp_project_bindings'

    project_id = sa.Column(sa.String(36),
                           primary_key=True)
    domain_id = sa.Column(sa.String(36),
                          nullable=False)


# DEBUG ADIT
# class NsxpSecurityGroupSectionMapping(model_base.BASEV2,
#                                       models.TimestampMixin):
#     """Backend mappings for Neutron Rule Sections.

#     This class maps a neutron security group identifier to the corresponding
#     NSX layer 3 section.
#     """

#     __tablename__ = 'nsxv_security_group_section_mappings'
#     neutron_id = sa.Column(sa.String(36),
#                            sa.ForeignKey('securitygroups.id',
#                                          ondelete="CASCADE"),
#                            primary_key=True)
#     ip_section_id = sa.Column(sa.String(100))
