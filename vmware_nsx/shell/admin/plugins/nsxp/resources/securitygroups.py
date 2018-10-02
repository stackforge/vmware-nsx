# Copyright 2018 VMware, Inc.  All rights reserved.
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

from neutron.db import securitygroups_db
from neutron_lib.callbacks import registry
from neutron_lib import context
from oslo_log import log as logging

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxp.resources import utils as p_utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc

LOG = logging.getLogger(__name__)
neutron_client = securitygroups_db.SecurityGroupDbMixin()


def _log_info(resource, data, attrs=['display_name', 'id']):
    LOG.info(formatters.output_formatter(resource, data, attrs))


@admin_utils.list_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
def list_security_groups(resource, event, trigger, **kwargs):
    """List neutron security groups

    With the policy resources and realization state.
    """
    sg_mappings = []
    nsxpolicy = p_utils.get_connected_nsxpolicy()
    ep_id = p_utils.get_enforcment_point(nsxpolicy)
    ctx = context.get_admin_context()
    sgs = neutron_client.get_security_groups(ctx)
    for sg in sgs:
        domain_id = sg['tenant_id']
        try:
            nsxpolicy.comm_map.get(domain_id, sg['id'], silent=True)
            map_status = 'Exists'
            if ep_id:
                map_status = nsxpolicy.comm_map.get_realized_state(
                    domain_id, sg['id'], ep_id)
                if not map_status:
                    map_status = 'Not deployed'
        except nsx_lib_exc.ResourceNotFound:
            map_status = 'Missing'

        try:
            nsxpolicy.group.get(domain_id, sg['id'], silent=True)
            group_status = 'Exists'
            if ep_id:
                group_status = nsxpolicy.group.get_realized_state(
                    domain_id, sg['id'], ep_id)
                if not group_status:
                    group_status = 'Not deployed'
        except nsx_lib_exc.ResourceNotFound:
            group_status = 'Missing'
        sg_mappings.append({'ID': sg['id'],
                            'Name': sg.get('name'),
                            'Project': domain_id,
                            'NSX Group': group_status,
                            'NSX Map': map_status})
    _log_info(constants.SECURITY_GROUPS,
              sg_mappings,
              attrs=['Project', 'Name', 'ID', 'NSX Group', 'NSX Map'])
    return bool(sg_mappings)


registry.subscribe(list_security_groups,
                   constants.SECURITY_GROUPS,
                   shell.Operations.LIST.value)
