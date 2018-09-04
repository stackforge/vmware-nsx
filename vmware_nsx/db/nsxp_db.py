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

import decorator
from neutron_lib.api.definitions import portbindings as pbin
from neutron_lib import constants as lib_const
from neutron_lib.db import api as db_api
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
import six
from sqlalchemy import func
from sqlalchemy.orm import exc
from sqlalchemy.sql import expression as expr

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import nsxv_constants
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsxp_models

LOG = logging.getLogger(__name__)


def add_nsxp_project_domain_map(session, project_id, domain_id):
    with session.begin(subtransactions=True):
        binding = nsxp_models.NsxpProjectDomainMapping(
            project_id=project_id,
            domain_id=domain_id)
        session.add(binding)
    return binding


def get_nsxp_project_domain(session, project_id):
    try:
        x = session.query(nsxp_models.NsxpProjectDomainMapping)
        mapping = x.filter_by(
            project_id=project_id)
        mapping = mapping.one()
        if mapping:
            return mapping.domain_id
    except exc.NoResultFound:
        return
