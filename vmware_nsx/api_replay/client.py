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

import logging
import six

from keystoneauth1 import identity
from keystoneauth1 import session
from neutronclient.common import exceptions as n_exc
from neutronclient.v2_0 import client
from oslo_utils import excutils

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


class ApiReplayClient(object):

    basic_ignore_fields = ['updated_at',
                           'created_at',
                           'tags',
                           'revision',
                           'revision_number']

    def __init__(self,
                 source_os_username, source_os_user_domain_id,
                 source_os_tenant_name, source_os_tenant_domain_id,
                 source_os_password, source_os_auth_url,
                 dest_os_username, dest_os_user_domain_id,
                 dest_os_tenant_name, dest_os_tenant_domain_id,
                 dest_os_password, dest_os_auth_url,
                 use_old_keystone, logfile):

        if logfile:
            f_handler = logging.FileHandler(logfile)
            f_formatter = logging.Formatter(
                '%(asctime)s %(levelname)s %(message)s')
            f_handler.setFormatter(f_formatter)
            LOG.addHandler(f_handler)

        # connect to both clients
        if use_old_keystone:
            # Since we are not sure what keystone version will be used on the
            # source setup, we add an option to use the v2 client
            self.source_neutron = client.Client(
                username=source_os_username,
                tenant_name=source_os_tenant_name,
                password=source_os_password,
                auth_url=source_os_auth_url)
        else:
            self.source_neutron = self.connect_to_client(
                username=source_os_username,
                user_domain_id=source_os_user_domain_id,
                tenant_name=source_os_tenant_name,
                tenant_domain_id=source_os_tenant_domain_id,
                password=source_os_password,
                auth_url=source_os_auth_url)

        # DEBUG ADIT
        self.dest_neutron = client.Client(
            username=dest_os_username,
            tenant_name=dest_os_tenant_name,
            password=dest_os_password,
            auth_url=dest_os_auth_url)

        # self.dest_neutron = self.connect_to_client(
        #     username=dest_os_username,
        #     user_domain_id=dest_os_user_domain_id,
        #     tenant_name=dest_os_tenant_name,
        #     tenant_domain_id=dest_os_tenant_domain_id,
        #     password=dest_os_password,
        #     auth_url=dest_os_auth_url)

        LOG.info("Starting NSX migration.")
        # Migrate all the objects
        self.migrate_security_groups()
        self.migrate_qos_policies()
        routers_routes, routers_gw_info = self.migrate_routers()
        self.migrate_networks_subnets_ports(routers_gw_info)
        self.migrate_floatingips()
        self.migrate_routers_routes(routers_routes)
        LOG.info("NSX migration is Done.")

    def connect_to_client(self, username, user_domain_id,
                          tenant_name, tenant_domain_id,
                          password, auth_url):
        auth = identity.Password(username=username,
                                 user_domain_id=user_domain_id,
                                 password=password,
                                 project_name=tenant_name,
                                 project_domain_id=tenant_domain_id,
                                 auth_url=auth_url)
        sess = session.Session(auth=auth)
        neutron = client.Client(session=sess)
        return neutron

    def find_subnet_by_id(self, subnet_id, subnets):
        for subnet in subnets:
            if subnet['id'] == subnet_id:
                return subnet

    def subnet_drop_ipv6_fields_if_v4(self, body):
        """
        Drops v6 fields on subnets that are v4 as server doesn't allow them.
        """
        v6_fields_to_remove = ['ipv6_address_mode', 'ipv6_ra_mode']
        if body['ip_version'] != 4:
            return

        for field in v6_fields_to_remove:
            if field in body:
                body.pop(field)

    def get_ports_on_network(self, network_id, ports):
        """Returns all the ports on a given network_id."""
        ports_on_network = []
        for port in ports:
            if port['network_id'] == network_id:
                ports_on_network.append(port)
        return ports_on_network

    def have_id(self, id, groups):
        """If the sg_id is in groups return true else false."""
        for group in groups:
            if id == group['id']:
                return group

        return False

    def drop_fields(self, item, drop_fields):
        body = {}
        for k, v in item.items():
            if k in drop_fields:
                continue
            body[k] = v
        return body

    def fix_description(self, body):
        # neutron doesn't like description being None even though its
        # what it returns to us.
        if 'description' in body and body['description'] is None:
            body['description'] = ''

    def migrate_qos_rule(self, dest_policy, source_rule):
        """Add the QoS rule from the source to the QoS policy

        If there is already a rule of that type, skip it since
        the QoS policy can have only one rule of each type
        """
        #TODO(asarfaty) also take rule direction into account once
        #ingress support is upstream
        rule_type = source_rule.get('type')
        dest_rules = dest_policy.get('rules')
        if dest_rules:
            for dest_rule in dest_rules:
                if dest_rule['type'] == rule_type:
                    return
        pol_id = dest_policy['id']
        drop_qos_rule_fields = ['revision', 'type', 'qos_policy_id', 'id']
        body = self.drop_fields(source_rule, drop_qos_rule_fields)
        try:
            if rule_type == 'bandwidth_limit':
                rule = self.dest_neutron.create_bandwidth_limit_rule(
                    pol_id, body={'bandwidth_limit_rule': body})
            elif rule_type == 'dscp_marking':
                rule = self.dest_neutron.create_dscp_marking_rule(
                    pol_id, body={'dscp_marking_rule': body})
            else:
                LOG.info("QoS rule type %s is not supported for policy %s",
                         rule_type, pol_id)
            LOG.info("created QoS policy %s rule %s ", pol_id, rule)
        except Exception as e:
            LOG.error("Failed to create QoS rule for policy %s: %s",
                      pol_id, e)

    def migrate_qos_policies(self):
        """Migrates QoS policies from source to dest neutron."""

        # first fetch the QoS policies from both the
        # source and destination neutron server
        try:
            dest_qos_pols = self.dest_neutron.list_qos_policies()['policies']
        except n_exc.NotFound:
            # QoS disabled on dest
            LOG.info("QoS is disabled on destination: ignoring QoS policies")
            self.dest_qos_support = False
            return
        self.dest_qos_support = True
        try:
            source_qos_pols = self.source_neutron.list_qos_policies()[
                'policies']
        except n_exc.NotFound:
            # QoS disabled on source
            return

        drop_qos_policy_fields = ['revision']

        for pol in source_qos_pols:
            dest_pol = self.have_id(pol['id'], dest_qos_pols)
            # If the policy already exists on the dest_neutron
            if dest_pol:
                # make sure all the QoS policy rules are there and
                # create them if not
                for qos_rule in pol['rules']:
                    self.migrate_qos_rule(dest_pol, qos_rule)

            # dest server doesn't have the group so we create it here.
            else:
                qos_rules = pol.pop('rules')
                try:
                    body = self.drop_fields(pol, drop_qos_policy_fields)
                    self.fix_description(body)
                    new_pol = self.dest_neutron.create_qos_policy(
                        body={'policy': body})
                except Exception as e:
                    LOG.error("Failed to create QoS policy %s: %s",
                              pol['id'], e)
                    continue
                else:
                    LOG.info("Created QoS policy %s", new_pol)
                    for qos_rule in qos_rules:
                        self.migrate_qos_rule(new_pol['policy'], qos_rule)

    def migrate_security_groups(self):
        """Migrates security groups from source to dest neutron."""

        # first fetch the security groups from both the
        # source and dest neutron server
        source_sec_groups = self.source_neutron.list_security_groups()
        dest_sec_groups = self.dest_neutron.list_security_groups()

        source_sec_groups = source_sec_groups['security_groups']
        dest_sec_groups = dest_sec_groups['security_groups']

        drop_sg_fields = self.basic_ignore_fields + ['policy']

        for sg in source_sec_groups:
            dest_sec_group = self.have_id(sg['id'], dest_sec_groups)
            # If the security group already exists on the dest_neutron
            if dest_sec_group:
                # make sure all the security group rules are there and
                # create them if not
                for sg_rule in sg['security_group_rules']:
                    if(self.have_id(sg_rule['id'],
                                    dest_sec_group['security_group_rules'])
                       is False):
                        try:
                            body = self.drop_fields(sg_rule, drop_sg_fields)
                            self.fix_description(body)
                            self.dest_neutron.create_security_group_rule(
                                    {'security_group_rule': body})
                        except n_exc.Conflict:
                            # NOTE(arosen): when you create a default
                            # security group it is automatically populated
                            # with some rules. When we go to create the rules
                            # that already exist because of a match an error
                            # is raised here but that's okay.
                            pass

            # dest server doesn't have the group so we create it here.
            else:
                sg_rules = sg.pop('security_group_rules')
                try:
                    body = self.drop_fields(sg, drop_sg_fields)
                    self.fix_description(body)
                    new_sg = self.dest_neutron.create_security_group(
                        {'security_group': body})
                    LOG.info("Created security-group %s", new_sg)
                except Exception as e:
                    LOG.error("Failed to create security group (%s): %s",
                              new_sg, e)

                # Note - policy security groups will have no rules, and will
                # be created on the destination with the default rules only
                for sg_rule in sg_rules:
                    try:
                        body = self.drop_fields(sg_rule, drop_sg_fields)
                        self.fix_description(body)
                        rule = self.dest_neutron.create_security_group_rule(
                            {'security_group_rule': body})
                        LOG.info("created security group rule %s", rule['id'])
                    except Exception:
                        # NOTE(arosen): when you create a default
                        # security group it is automatically populated
                        # with some rules. When we go to create the rules
                        # that already exist because of a match an error
                        # is raised here but that's okay.
                        pass

    def migrate_routers(self):
        """Migrates routers from source to dest neutron.

        Also return a dictionary of the routes that should be added to
        each router. Static routes must be added later, after the router
        ports are set.
        And return a dictionary of external gateway info per router
        """
        try:
            source_routers = self.source_neutron.list_routers()['routers']
        except Exception:
            # L3 might be disabled in the source
            source_routers = []

        dest_routers = self.dest_neutron.list_routers()['routers']
        update_routes = {}
        gw_info = {}

        drop_router_fields = self.basic_ignore_fields + [
            'status',
            'routes',
            'ha',
            'external_gateway_info',
            'router_type',
            'availability_zone_hints',
            'availability_zones',
            'distributed',
            'flavor_id']

        for router in source_routers:
            dest_router = self.have_id(router['id'], dest_routers)
            if dest_router is False:
                if router.get('routes'):
                    update_routes[router['id']] = router['routes']

                if router.get('external_gateway_info'):
                    gw_info[router['id']] = router['external_gateway_info']

                body = self.drop_fields(router, drop_router_fields)
                self.fix_description(body)
                new_router = (self.dest_neutron.create_router(
                    {'router': body}))
                LOG.info("created router %s", new_router)
        return update_routes, gw_info

    def migrate_routers_routes(self, routers_routes):
        """Add static routes to the created routers."""
        for router_id, routes in six.iteritems(routers_routes):
            self.dest_neutron.update_router(router_id,
                {'router': {'routes': routes}})
            LOG.info("Added routes to router %s", router_id)

    def migrate_subnetpools(self):
        source_subnetpools = self.source_neutron.list_subnetpools()[
            'subnetpools']
        dest_subnetpools = self.dest_neutron.list_subnetpools()[
            'subnetpools']
        drop_subnetpool_fields = self.basic_ignore_fields + [
            'id',
            'ip_version']

        subnetpools_map = {}
        for pool in source_subnetpools:
            # a default subnetpool (per ip-version) should be unique.
            # so do not create one if already exists
            if pool['is_default']:
                for dpool in dest_subnetpools:
                    if (dpool['is_default'] and
                        dpool['ip_version'] == pool['ip_version']):
                        subnetpools_map[pool['id']] = dpool['id']
                        break
            else:
                old_id = pool['id']
                body = self.drop_fields(pool, drop_subnetpool_fields)
                self.fix_description(body)
                if 'default_quota' in body and body['default_quota'] is None:
                    del body['default_quota']

                new_id = self.dest_neutron.create_subnetpool(
                    {'subnetpool': body})['subnetpool']['id']
                subnetpools_map[old_id] = new_id
                # refresh the list of existing subnetpools
                dest_subnetpools = self.dest_neutron.list_subnetpools()[
                    'subnetpools']
        return subnetpools_map

    def fix_port(self, body):
        # remove allowed_address_pairs if empty:
        if ('allowed_address_pairs' in body and
            not body['allowed_address_pairs']):
            del body['allowed_address_pairs']

    def fix_network(self, body, dest_default_public_net):
        # neutron doesn't like some fields being None even though its
        # what it returns to us.
        for field in ['provider:physical_network',
                      'provider:segmentation_id']:
            if field in body and body[field] is None:
                del body[field]

        # vxlan network with segmentation id should be translated to a regular
        # network in nsx-v3.
        if (body.get('provider:network_type') == 'vxlan' and
            body.get('provider:segmentation_id') is not None):
            del body['provider:network_type']
            del body['provider:segmentation_id']

        # flat network should be translated to a regular network in nsx-v3.
        if (body.get('provider:network_type') == 'flat'):
            del body['provider:network_type']
            if 'provider:physical_network' in body:
                del body['provider:physical_network']

        # external networks needs some special care
        if body.get('router:external'):
            fields_reset = False
            for field in ['provider:network_type', 'provider:segmentation_id',
                          'provider:physical_network']:
                if field in body:
                    if body[field] is not None:
                        fields_reset = True
                    del body[field]
            if fields_reset:
                LOG.warning("Ignoring provider network fields while migrating "
                            "external network %s", body['id'])
            if body.get('is_default') and dest_default_public_net:
                body['is_default'] = False
                LOG.warning("Public network %s was set to non default network",
                            body['id'])

    def migrate_networks_subnets_ports(self, routers_gw_info):
        """Migrates networks/ports/router-uplinks from src to dest neutron."""
        source_ports = self.source_neutron.list_ports()['ports']
        source_subnets = self.source_neutron.list_subnets()['subnets']
        source_networks = self.source_neutron.list_networks()['networks']
        dest_networks = self.dest_neutron.list_networks()['networks']
        dest_ports = self.dest_neutron.list_ports()['ports']

        # Remove some fields before creating the new object.
        # Some fields are not supported for a new object, and some are not
        # supported by the nsx-v3 plugin
        drop_subnet_fields = self.basic_ignore_fields + [
            'advanced_service_providers',
            'id',
            'service_types']

        drop_port_fields = self.basic_ignore_fields + [
            'status',
            'binding:vif_details',
            'binding:vif_type',
            'binding:host_id',
            'vnic_index',
            'dns_assignment']

        drop_network_fields = self.basic_ignore_fields + [
            'status',
            'subnets',
            'availability_zones',
            'availability_zone_hints',
            'ipv4_address_scope',
            'ipv6_address_scope',
            'mtu']

        if not self.dest_qos_support:
            drop_network_fields.append('qos_policy_id')
            drop_port_fields.append('qos_policy_id')

        # Find out if the destination already has a default public network
        dest_default_public_net = False
        for dest_net in dest_networks:
            if dest_net.get('is_default') and dest_net.get('router:external'):
                dest_default_public_net = True

        subnetpools_map = self.migrate_subnetpools()
        for network in source_networks:
            body = self.drop_fields(network, drop_network_fields)
            self.fix_description(body)
            self.fix_network(body, dest_default_public_net)

            # only create network if the dest server doesn't have it
            if self.have_id(network['id'], dest_networks) is False:
                try:
                    created_net = self.dest_neutron.create_network(
                        {'network': body})['network']
                    LOG.info("Created network: %s", created_net)
                except Exception as e:
                    # Print the network and exception to help debugging
                    with excutils.save_and_reraise_exception():
                        LOG.error("Failed to create network %s", str(body))
                        LOG.error("Source network: %s", str(network))
                        raise e

            subnets_map = {}
            count_dhcp_subnet = 0
            for subnet_id in network['subnets']:
                subnet = self.find_subnet_by_id(subnet_id, source_subnets)
                body = self.drop_fields(subnet, drop_subnet_fields)

                # specify the network_id that we just created above
                body['network_id'] = network['id']
                self.subnet_drop_ipv6_fields_if_v4(body)
                self.fix_description(body)
                # translate the old subnetpool id to the new one
                if body.get('subnetpool_id'):
                    body['subnetpool_id'] = subnetpools_map.get(
                        body['subnetpool_id'])
                if body['enable_dhcp']:
                    count_dhcp_subnet = count_dhcp_subnet + 1
                # disable dhcp on this subnet if there is already another
                # subnet with DHCP as the v3 plugin supports only one
                if count_dhcp_subnet > 1:
                    body['enable_dhcp'] = False
                    LOG.warning("Disabling DHCP for subnet on net %s: Plugin"
                                "doesn't support multiple subnets with DHCP",
                                network['id'])
                try:
                    created_subnet = self.dest_neutron.create_subnet(
                        {'subnet': body})['subnet']
                    LOG.info("Created subnet: %s", created_subnet['id'])
                    subnets_map[subnet_id] = created_subnet['id']
                except n_exc.BadRequest as e:
                    LOG.error("Failed to create subnet: %s", e)
                    # NOTE(arosen): this occurs here if you run the script
                    # multiple times as we don't currently
                    # perserve the subnet_id. Also, 409 would be a better
                    # response code for this in neutron :(

            # create the ports on the network
            ports = self.get_ports_on_network(network['id'], source_ports)
            for port in ports:

                body = self.drop_fields(port, drop_port_fields)
                self.fix_description(body)
                self.fix_port(body)

                # specify the network_id that we just created above
                port['network_id'] = network['id']

                old_subnet_id = port['fixed_ips'][0]['subnet_id']
                subnet_id = subnets_map.get(old_subnet_id)
                # remove the old subnet id field from fixed_ips dict
                for fixed_ips in body['fixed_ips']:
                    del fixed_ips['subnet_id']

                # only create port if the dest server doesn't have it
                if self.have_id(port['id'], dest_ports) is False:
                    if port['device_owner'] == 'network:router_gateway':
                        router_id = port['device_id']
                        enable_snat = True
                        if router_id in routers_gw_info:
                            # keep the original snat status of the router
                            enable_snat = routers_gw_info[router_id].get(
                                'enable_snat', True)
                        rtr_body = {
                            "external_gateway_info":
                                {"network_id": port['network_id'],
                                 "enable_snat": enable_snat,
                                 # keep the original GW IP
                                 "external_fixed_ips": port.get('fixed_ips')}}
                        router_uplink = self.dest_neutron.update_router(
                            router_id, {'router': rtr_body})
                        LOG.info("Uplinked router %s", router_uplink)
                        continue

                    # Let the neutron dhcp-agent recreate this on its own
                    if port['device_owner'] == 'network:dhcp':
                        continue

                    # ignore these as we create them ourselves later
                    if port['device_owner'] == 'network:floatingip':
                        continue

                    if (port['device_owner'] == 'network:router_interface' and
                        subnet_id):
                        try:
                            # uplink router_interface ports by creating the
                            # port, and attaching it to the router
                            router_id = port['device_id']
                            del body['device_owner']
                            del body['device_id']
                            created_port = self.dest_neutron.create_port(
                                {'port': body})['port']
                            self.dest_neutron.add_interface_router(
                                router_id,
                                {'port_id': created_port['id']})
                            LOG.info("Uplinked router %s to network %s",
                                     router_id, network['id'])
                        except Exception as e:
                            # NOTE(arosen): this occurs here if you run the
                            # script multiple times as we don't track this.
                            LOG.error("Failed to add router interface: %s", e)
                        continue

                    try:
                        created_port = self.dest_neutron.create_port(
                            {'port': body})['port']
                    except Exception as e:
                        # NOTE(arosen): this occurs here if you run the
                        # script multiple times as we don't track this.
                        LOG.error("Failed to create port (%s) : %s",
                                  port, e)
                    else:
                        LOG.info("Created port %s with IPs: %s",
                                 created_port['id'],
                                 created_port.get('fixed_ips'))

    def migrate_floatingips(self):
        """Migrates floatingips from source to dest neutron."""
        try:
            source_fips = self.source_neutron.list_floatingips()['floatingips']
        except Exception:
            # L3 might be disabled in the source
            source_fips = []

        drop_fip_fields = self.basic_ignore_fields + [
            'status', 'router_id', 'id', 'revision']

        for source_fip in source_fips:
            body = self.drop_fields(source_fip, drop_fip_fields)
            try:
                fip = self.dest_neutron.create_floatingip({'floatingip': body})
                LOG.info("Created floatingip %s", fip)
            except Exception as e:
                LOG.error("Failed to create floating ip (%s) : %s",
                          source_fip, e)
