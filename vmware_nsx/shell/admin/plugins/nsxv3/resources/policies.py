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


def init_policy_api():
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
    return v3.NsxPolicyLib(nsxlib_config)


def test_domains(nsx_policy):
    # create a domain
    domain_name = 'domain1'
    domain = nsx_policy.domain.create(domain_name, description='desc')
    LOG.info("Created domain: %s", domain_name)
    domain_id = domain['id']

    # Get domain by id
    domain = nsx_policy.domain.get(domain_id)
    if not domain:
        LOG.error("ERROR domain.get failed for %s", domain_id)

    # list domains:
    domains = nsx_policy.domain.list()
    if not domains:
        LOG.error("ERROR domain.list failed")

    # get domain by name
    domain = nsx_policy.domain.get_by_name(domain_name)
    if not domain:
        LOG.error("ERROR domain.get_by_name failed for %s", domain_name)

    # update domain description:
    updated_domain = nsx_policy.domain.update(
        domain_id, description='updated', name=domain_name + ' updated')
    if updated_domain['description'] != 'updated':
        LOG.error("ERROR domain.update didn't work for %s", domain_name)
    return domain_id


def test_groups(nsx_policy, domain_id, group_name):
    # create a group
    group = nsx_policy.group.create(group_name, domain_id, description='desc')
    LOG.info("Created group: %s", group_name)
    group_id = group['id']

    # Get group by id
    group = nsx_policy.group.get(domain_id, group_id)
    if not group:
        LOG.error("ERROR group.get failed for %s", group_id)

    # list groups:
    groups = nsx_policy.group.list(domain_id)
    if not groups:
        LOG.error("ERROR group.list failed")

    # get group by name
    group = nsx_policy.group.get_by_name(domain_id, group_name)
    if not group:
        LOG.error("ERROR group.get_by_name failed for %s", group_name)

    # update domain description:
    updated_group = nsx_policy.group.update(domain_id, group_id,
                                            description='updated',
                                            name=group_name + ' updated')
    if updated_group['description'] != 'updated':
        LOG.error("ERROR group.update didn't work for %s", group_name)

    return group_id


def test_service(nsx_policy):
    # Create a service
    service_name = 'my http'
    service = nsx_policy.service.create(
        service_name,
        description='My service',
        protocol='TCP', dest_ports=[80, 8080])
    service_id = service['id']
    LOG.info("Created service: %s", service_name)

    # Get the service by id
    service = nsx_policy.service.get(service_id)
    if not service:
        LOG.error("ERROR service.get failed for %s", service_id)

    # list services:
    services = nsx_policy.service.list()
    if not services:
        LOG.error("ERROR service.list failed")

    # get service by name
    service = nsx_policy.service.get_by_name(service_name)
    if not service:
        LOG.error("ERROR service.get_by_name failed for %s", service_name)

    # update service description:
    updated_service = nsx_policy.service.update(service_id,
                                                description='updated',
                                                name=service_name + ' updated')
    if updated_service['description'] != 'updated':
        LOG.error("ERROR service.update didn't work for %s", service_name)

    # TODO(asarfaty) - update service entry?

    return service_id


def test_contract(nsx_policy, service_id):
    # Create a contract
    contract_name = 'my contract'
    try:
        contract = nsx_policy.contract.create(
            contract_name,
            description='My contract',
            services=[service_id],
            action='DENY')
    except nsx_lib_exc.ManagerError as e:
        LOG.error("ERROR contract.create crashed for %(name)s : %(e)s",
                  {'name': contract_name, 'e': e})

    contract_id = contract['id']
    LOG.info("Created test_contract: %s", contract_name)

    # verify that the contract has entries:
    if not contract.get('contract_entries'):
        LOG.error("ERROR: contract.create didn't return the entries for %s",
                  contract_name)

    # Get the contract by id
    contract = nsx_policy.contract.get(contract_id)
    if not contract:
        LOG.error("ERROR contract.get failed for %s", contract_id)

    # list contracts:
    try:
        contracts = nsx_policy.contract.list()
        if not contracts:
            LOG.error("ERROR contract.list failed")
    except nsx_lib_exc.ManagerError as e:
        LOG.error("ERROR contract.list crashed: %s", e)

    # get contract by name
    contract = nsx_policy.contract.get_by_name(contract_name)
    if not contract:
        LOG.error("ERROR contract.get_by_name failed for %s",
                  contract_name)

    # update contract description:
    updated_contract = nsx_policy.contract.update(
        contract_id,
        description='updated',
        name=contract_name + ' updated')
    if updated_contract['description'] != 'updated':
        LOG.error("ERROR contract.update didn't work for %s", contract_name)

    # TODO(asarfaty) - update contract entry?

    return contract_id


def test_contractmap(nsx_policy, domain_id, group_ids, contract_id):
    # Create a contract map
    contractmap_name = 'my contract map1'
    try:
        contractmap = nsx_policy.contractmap.create(
            contractmap_name,
            domain_id,
            description='My contract map',
            source_groups=[group_ids[0]],
            dest_groups=[group_ids[1]],
            contract_id=contract_id)
    except nsx_lib_exc.ManagerError as e:
        LOG.error("ERROR contractmap.create crashed for %(name)s : %(e)s",
                  {'name': contractmap_name, 'e': e})
    seq_num = contractmap['sequence_number']
    contractmap_id = contractmap['id']

    # create another one, and make sure it is added after
    contractmap_name2 = 'my contract map2'
    try:
        contractmap2 = nsx_policy.contractmap.create(
            contractmap_name2,
            domain_id,
            description='My contract map',
            source_groups=[group_ids[1]],
            dest_groups=[group_ids[0]],
            contract_id=contract_id)
    except nsx_lib_exc.ManagerError as e:
        LOG.error("ERROR contractmap.create crashed for %(name)s : %(e)s",
                  {'name': contractmap_name, 'e': e})
    if contractmap2['sequence_number'] != seq_num + 1:
        LOG.error("ERROR contractmap.create created the wrong seq-num "
                  "%(seq)s for %(name)s",
                  {'name': contractmap_name2,
                   'seq': contractmap2['sequence_number']})

    # list contract maps
    contractmaps = nsx_policy.contractmap.list(domain_id)
    if len(contractmaps) != 2:
        LOG.error("ERROR contractmap.list didn't return all entries")

    # delete the 2nd contract-map
    nsx_policy.contractmap.delete(domain_id, contractmap2['id'])

    # test get
    contractmap = nsx_policy.contractmap.get(domain_id, contractmap_id)
    if not contractmap:
        LOG.error("ERROR contractmap.get failed")

    # test update
    updated_contractmap = nsx_policy.contractmap.update(
        domain_id, contractmap_id,
        description='updated',
        name=contractmap_name + ' updated',
        source_groups=[group_ids[1]],
        contract_id=contract_id)
    if updated_contractmap['description'] != 'updated':
        LOG.error("ERROR contractmap.update didn't work for %s",
            contractmap_name)

    return contractmap_id


def policy_obj_cleanup(nsx_policy, domain_id, group_ids, service_id,
                       contract_id, contractmap_id):
    # delete the contractmap
    nsx_policy.contractmap.delete(domain_id, contractmap_id)

    # delete the contract
    nsx_policy.contract.delete(contract_id)

    # delete the service
    nsx_policy.service.delete(service_id)

    # Delete the groups
    for group_id in group_ids:
        nsx_policy.group.delete(domain_id, group_id)

    # delete the domain
    nsx_policy.domain.delete(domain_id)


@admin_utils.output_header
def test_policy_api(resource, event, trigger, **kwargs):
    # Initialize the nsx policy api
    LOG.info("Initializing the policy API")
    nsx_policy = init_policy_api()

    # DOMAINS:
    LOG.info("Testing domains")
    domain_id = test_domains(nsx_policy)

    # GROUPS:
    LOG.info("Testing groups")
    group_id = test_groups(nsx_policy, domain_id, 'group1')
    another_group_id = test_groups(nsx_policy, domain_id, 'group2')
    group_ids = [group_id, another_group_id]

    # SERVICES:
    service_id = test_service(nsx_policy)

    # CONTRACT:
    contract_id = test_contract(nsx_policy, service_id)

    # CONTRACT MAPS:
    contractmap_id = test_contractmap(nsx_policy, domain_id,
                                      group_ids, contract_id)

    # CLEANUP:
    LOG.info("Cleanup")
    policy_obj_cleanup(nsx_policy, domain_id, group_ids,
                       service_id, contract_id, contractmap_id)

    LOG.info("End of policy api testing")


registry.subscribe(test_policy_api,
                   constants.POLICIES,
                   shell.Operations.VALIDATE.value)
