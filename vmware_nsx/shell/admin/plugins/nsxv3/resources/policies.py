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

import time

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
QUICK = False


def init_policy_api():
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
    return v3.NsxPolicyLib(nsxlib_config)


def test_enfocement_points(nsx_policy):
    if QUICK:
        return

    LOG.info("Testing enforcement points")
    # create an enforcement point
    ep_name = 'ep 1'
    ip_address = '10.162.48.92'
    thumbprint = '8677d6a58b0410c8756d452351888214bf30dd382632377412d6c08c87cdee78'
    edge_cluster_id = '077553f4-c75d-4883-8b62-eeec8aff2b8f'
    transport_zone_id = '81f5e1c4-507b-46f6-81ef-f09272780df0'

    # creation returns an error because the backend cannot be accessed
    # so here we use a pre-defined id, in order to use it later.
    ep_id = 'test2'
    try:
        ep = nsx_policy.enforcement_point.create_or_overwrite(
            ep_name, ep_id=ep_id, description='desc',
            username='admin', password='Admin!23Admin',
            ip_address=ip_address,thumbprint=thumbprint,
            edge_cluster_id=edge_cluster_id,
            transport_zone_id=transport_zone_id)
        LOG.info("Created enforcement point: %s", ep_name)
        ep_id = ep['id']
    except nsx_lib_exc.ManagerError as e:
        LOG.error("Enforcement point creation returned an error: %s", e)
        # continue anyway as it is created on the backend

    # Get enforcement_point by id
    ep = nsx_policy.enforcement_point.get(ep_id)
    if not ep:
        LOG.error("ERROR enforcement_point.get failed for %s", ep_id)

    # list enforcement points:
    eps = nsx_policy.enforcement_point.list()
    if not eps:
        LOG.error("ERROR enforcement_point.list failed")

    # get enforcement_point by name
    ep = nsx_policy.enforcement_point.get_by_name(ep_name)
    if not ep:
        LOG.error("ERROR enforcement_point.get_by_name failed for %s",
                  ep_name)

    # update the description:
    updated_ep = nsx_policy.enforcement_point.update(
        ep_id, description='updated', name=ep_name + ' updated',
        edge_cluster_id=edge_cluster_id,
        username='admin', password='Admin!23Admin')
    if updated_ep['description'] != 'updated':
        LOG.error("ERROR enforcement_point.update didn't work for %s",
                  ep_name)
    return ep_id


def test_domains(nsx_policy):
    LOG.info("Testing domains")
    # create a domain
    domain_name = 'domain 1'
    domain = nsx_policy.domain.create_or_overwrite(domain_name, description='desc')
    domain_id = domain['id']
    LOG.info("Created domain: %s - %s", domain_name, domain_id)

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


def test_deployment_maps(nsx_policy, domain_id, ep_id):
    if QUICK:
        return

    LOG.info("Testing deployment maps")
    # create an enforcement point
    map_name = 'deployment 1'
    dp_map = nsx_policy.deployment_map.create_or_overwrite(
        map_name, description='desc',
        domain_id=domain_id, ep_id=ep_id)
    LOG.info("Created deployment_map: %s", map_name)
    map_id = dp_map['id']

    # Get deployment_map by id
    dp_map = nsx_policy.deployment_map.get(map_id, domain_id=domain_id)
    if not dp_map:
        LOG.error("ERROR deployment_map.get failed for %s", map_id)

    # list enforcement points:
    dp_maps = nsx_policy.deployment_map.list(domain_id=domain_id)
    if not dp_maps:
        LOG.error("ERROR deployment_map.list failed")

    # get deployment_map by name
    dp_map = nsx_policy.deployment_map.get_by_name(map_name, domain_id=domain_id)
    if not dp_map:
        LOG.error("ERROR deployment_map.get_by_name failed for %s",
                  map_name)

    # update the description:
    updated_map = nsx_policy.deployment_map.update(
        map_id, description='updated', name=map_name + ' updated',
        domain_id=domain_id, ep_id=ep_id)
    if updated_map['description'] != 'updated':
        LOG.error("ERROR deployment_map.update didn't work for %s",
                  map_name)
    return map_id


def test_groups(nsx_policy, domain_id, group_name):
    # create a group
    group = nsx_policy.group.create_or_overwrite(group_name, domain_id, description='desc',
        cond_val='abc')
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

    # update group description:
    updated_group = nsx_policy.group.update(domain_id, group_id,
                                            description='updated',
                                            name=group_name + ' updated')
    if updated_group['description'] != 'updated':
        LOG.error("ERROR group.update didn't work for %s", group_name)

    # update group condition:
    updated_group = nsx_policy.group.update_condition(domain_id, group_id,
                                                      cond_val='xyz')
    # remove group condition:
    updated_group = nsx_policy.group.update_condition(domain_id, group_id,
                                                      cond_val=None)

    return group_id


def test_service(nsx_policy):
    # Create a service
    service_name = 'my http 1'
    service = nsx_policy.service.create_or_overwrite(
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
    updated_service = nsx_policy.service.update(
        service_id,
        description='updated',
        name=service_name + ' updated')
    if updated_service['description'] != 'updated':
        LOG.error("ERROR service.update didn't work for %s", service_name)

    # Update service entry
    updated_service = nsx_policy.service.update(service_id,
                                                protocol='udp',
                                                dest_ports=[555])
    if (updated_service['service_entries'][0]['l4_protocol'] !=
        'UDP'):
        LOG.error("ERROR service.update entry didn't work for %s: %s",
                  service_name, updated_service)

    return service_id


def test_icmp_service(nsx_policy):
    # Create a service
    service_name = 'my icmp 1'
    service = nsx_policy.icmp_service.create_or_overwrite(
        service_name,
        description='My service',
        icmp_type=6, icmp_code=7)
    service_id = service['id']
    LOG.info("Created icmp_service: %s", service_name)

    # Get the service by id
    service = nsx_policy.icmp_service.get(service_id)
    if not service:
        LOG.error("ERROR icmp_service.get failed for %s", service_id)

    # list services:
    services = nsx_policy.icmp_service.list()
    if not services:
        LOG.error("ERROR icmp_service.list failed")

    # get service by name
    service = nsx_policy.icmp_service.get_by_name(service_name)
    if not service:
        LOG.error("ERROR icmp_service.get_by_name failed for %s", service_name)

    # update service description:
    updated_service = nsx_policy.icmp_service.update(
        service_id,
        description='updated',
        name=service_name + ' updated')
    if updated_service['description'] != 'updated':
        LOG.error("ERROR icmp_service.update didn't work for %s", service_name)

    # Update service entry
    updated_service = nsx_policy.icmp_service.update(
        service_id, icmp_type=9, icmp_code=10)
    if (updated_service['service_entries'][0]['icmp_type'] != 9):
        LOG.error("ERROR icmp_service.update entry didn't work for %s: %s",
                  service_name, updated_service)

    nsx_policy.icmp_service.delete(service_id)


def test_communication_maps(nsx_policy, domain_id, group_ids, service_id):
    # Create a communaction map
    map_name = 'my communication map1'
    try:
        comm_map = nsx_policy.comm_map.create_or_overwrite(
            map_name,
            domain_id,
            description='My communication map',
            source_groups=[group_ids[0]],
            dest_groups=[group_ids[1]],
            service_id=service_id)
    except nsx_lib_exc.ManagerError as e:
        LOG.error("ERROR comm_map.create_or_overwrite crashed for %(name)s : %(e)s",
                  {'name': map_name, 'e': e})
    LOG.info("Created communication-map: %s", map_name)
    map_id = comm_map['id']

    # create another entry
    map_name2 = 'my communication map2'
    try:
        comm_map2 = nsx_policy.comm_map.create_or_overwrite(
            map_name2,
            domain_id,
            description='My communication map',
            source_groups=[group_ids[1]],
            dest_groups=[group_ids[0]],
            service_id=service_id)
    except nsx_lib_exc.ManagerError as e:
        LOG.error("ERROR comm_map.create_or_overwrite crashed for %(name)s : %(e)s",
                  {'name': map_name2, 'e': e})

    # list communication map entries
    maps = nsx_policy.comm_map.list(domain_id)
    if len(maps) != 2:
        LOG.error("ERROR comm_map.list didn't return all entries")

    # delete the 2nd entry
    nsx_policy.comm_map.delete(domain_id, comm_map2['id'])

    # test get
    comm_map = nsx_policy.comm_map.get(domain_id, map_id)
    if not comm_map:
        LOG.error("ERROR comm_map.get failed")

    # test update
    updated_map = nsx_policy.comm_map.update(
        domain_id, map_id,
        description='updated',
        name=map_name + ' updated',
        source_groups=[],
        service_id=service_id)
    if updated_map['description'] != 'updated':
        LOG.error("ERROR comm_map.update didn't work for %s",
                  map_name)
    if updated_map['communication_entries'][0]['description'] != 'updated':
        LOG.error("ERROR comm_map entry update didn't work for %s",
                  map_name)
    LOG.info("Updates communication-map: %s", map_id)

    return map_id


def policy_obj_cleanup(nsx_policy, ep_id, domain_id, group_ids, service_id,
                       comm_map_id, map_id):
    LOG.info("Cleanup")
    # delete the deployment map
    if map_id:
        nsx_policy.deployment_map.delete(map_id, domain_id=domain_id)
        time.sleep(2)

    # delete the communication map
    if comm_map_id:
        nsx_policy.comm_map.delete(domain_id, comm_map_id)
        time.sleep(2)

    # delete the service
    if service_id:
        nsx_policy.service.delete(service_id)
        time.sleep(2)

    # Delete the groups
    for group_id in group_ids:
        nsx_policy.group.delete(domain_id, group_id)
        time.sleep(2)

    # delete the domain
    if domain_id:
        nsx_policy.domain.delete(domain_id)
        time.sleep(2)

    # delete the enforcement point
    if ep_id:
        nsx_policy.enforcement_point.delete(ep_id)


@admin_utils.output_header
def test_policy_api(resource, event, trigger, **kwargs):
    # Initialize the nsx policy api
    nsx_policy = init_policy_api()

    # enforcement points
    ep_id = None
    ep_id = test_enfocement_points(nsx_policy)

    # domains:
    domain_id = test_domains(nsx_policy)

    # deployment maps
    map_id = None
    map_id = test_deployment_maps(nsx_policy, domain_id, ep_id)

    # groups:
    LOG.info("Testing groups")
    group_id = test_groups(nsx_policy, domain_id, 'group1')
    time.sleep(2)
    another_group_id = test_groups(nsx_policy, domain_id, 'group2')
    time.sleep(2)
    group_ids = [group_id, another_group_id]

    # services:
    service_id = None
    service_id = test_service(nsx_policy)
    test_icmp_service(nsx_policy)

    # communication maps:
    comm_map_id = None
    comm_map_id = test_communication_maps(nsx_policy, domain_id,
                                          group_ids, service_id)

    # cleanup:
    policy_obj_cleanup(nsx_policy, ep_id, domain_id, group_ids,
                       service_id, comm_map_id, map_id)

    LOG.info("End of policy api testing")


registry.subscribe(test_policy_api,
                   constants.POLICIES,
                   shell.Operations.VALIDATE.value)
