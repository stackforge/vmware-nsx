# Copyright 2017 VMware, Inc.  All rights reserved.
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


from oslo_config import cfg
from oslo_log import log as logging

from neutron.callbacks import registry
from neutron import version as n_version

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import config
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc

LOG = logging.getLogger(__name__)
NSX_NEUTRON_PLUGIN = 'NSX Neutron plugin'
OS_NEUTRON_ID_SCOPE = 'os-neutron-id'


@admin_utils.output_header
def test_policy_api(resource, event, trigger, **kwargs):
    # Initialize the nsx policy api
    LOG.info("Initializing the policy API")
    client_cert_provider = None
    nsxlib_config = config.NsxLibConfig(
        username=cfg.CONF.nsx_v3.nsx_api_user,
        password=cfg.CONF.nsx_v3.nsx_api_password,
        client_cert_provider=client_cert_provider,
        retries=cfg.CONF.nsx_v3.http_retries,
        insecure=cfg.CONF.nsx_v3.insecure,
        ca_file=cfg.CONF.nsx_v3.ca_file,
        concurrent_connections=cfg.CONF.nsx_v3.concurrent_connections,
        http_timeout=cfg.CONF.nsx_v3.http_timeout,
        http_read_timeout=cfg.CONF.nsx_v3.http_read_timeout,
        conn_idle_timeout=cfg.CONF.nsx_v3.conn_idle_timeout,
        http_provider=None,
        max_attempts=cfg.CONF.nsx_v3.retries,
        nsx_api_managers=cfg.CONF.nsx_v3.nsx_api_managers,
        plugin_scope=OS_NEUTRON_ID_SCOPE,
        plugin_tag=NSX_NEUTRON_PLUGIN,
        plugin_ver=n_version.version_info.release_string(),
        dns_nameservers=cfg.CONF.nsx_v3.nameservers,
        dns_domain=cfg.CONF.nsx_v3.dns_domain)
    nsx_policy = v3.NsxPolicyLib(nsxlib_config)

    # DOMAINS:
    LOG.info("Testing domains")
    # create a domain
    domain_name = 'domain1'
    domain = nsx_policy.domain.create(domain_name, description='desc')
    LOG.info("Created domain: %s", domain_name)
    domain_id = domain['id']

    # Get domain by id
    domain = nsx_policy.domain.get(domain_id)
    if not domain:
        LOG.error("domain.get failed for %s", domain_id)

    # list domains:
    try:
        # TODO(asarfaty)currently fails. Cursor issue
        domains = nsx_policy.domain.list()
        if not domains:
            LOG.error("domain.list failed")
    except nsx_lib_exc.ManagerError as e:
        LOG.error("domain.list crashed: %s", e)

    # get domain by name
    try:
        # TODO(asarfaty)currently fails. Cursor issue
        domain = nsx_policy.domain.get_by_name(domain_name)
        if not domain:
            LOG.error("domain.get_by_name failed for %s", domain_name)
    except nsx_lib_exc.ManagerError as e:
        LOG.error("domain.get_by_name crashed for %s: %s", domain_name, e)

    # update domain description:
    updated_domain = nsx_policy.domain.update(domain_id, description='updated')
    LOG.info("Updated domain: %s", updated_domain)

    # GROUPS:
    LOG.info("Testing groups")
    # create a group
    group_name = 'group1'
    group = nsx_policy.group.create(domain_name, domain_id, description='desc')
    LOG.info("Created group: %s", group_name)
    group_id = group['id']

    # Get group by id
    group = nsx_policy.group.get(domain_id, group_id)
    if not group:
        LOG.error("group.get failed for %s", group_id)

    # list groups:
    try:
        groups = nsx_policy.group.list(domain_id)
        LOG.error("groups list: %s", groups)
        if not groups:
            LOG.error("group.list failed")
    except nsx_lib_exc.ManagerError as e:
        LOG.error("group.list crashed: %s", e)

    # get group by name
    try:
        group = nsx_policy.group.get_by_name(domain_id, group_name)
        if not group:
            LOG.error("group.get_by_name failed for %s", group_name)
    except nsx_lib_exc.ManagerError as e:
        LOG.error("group.get_by_name crashed for %s: %s", group_name, e)

    # update domain description:
    updated_group = nsx_policy.group.update(domain_id, group_id,
                                            description='updated')
    LOG.info("Updated group: %s", updated_group)

    # CleanUP
    LOG.info("Cleanup")
    # Delete the group
    nsx_policy.group.delete(domain_id, group_id)

    # delete the domain
    nsx_policy.domain.delete(domain_id)

    LOG.info("End of policy api testing")


registry.subscribe(test_policy_api,
                   constants.POLICIES,
                   shell.Operations.VALIDATE.value)
