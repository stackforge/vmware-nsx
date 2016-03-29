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


from neutronclient.v2_0 import client


class ApiReplayClient(object):

    def __init__(self, source_os_username, source_os_tenant_name,
                 source_os_password, source_os_auth_url,
                 dest_os_username, dest_os_tenant_name,
                 dest_os_password, dest_os_auth_url):

        self._source_os_username = source_os_username
        self._source_os_tenant_name = source_os_tenant_name
        self._source_os_password = source_os_password
        self._source_os_auth_url = source_os_auth_url

        self._dest_os_username = dest_os_username
        self._dest_os_tenant_name = dest_os_tenant_name
        self._dest_os_password = dest_os_password
        self._dest_os_auth_url = dest_os_auth_url

        self.source_neutron = client.Client(
            username=self._source_os_username,
            tenant_name=self._source_os_tenant_name,
            password=self._source_os_password,
            auth_url=self._source_os_auth_url)

        self.dest_neutron = client.Client(
            username=self._dest_os_username,
            tenant_name=self._dest_os_tenant_name,
            password=self._dest_os_password,
            auth_url=self._dest_os_auth_url)

        source_security_groups = self.source_neutron.list_security_groups()
        dest_security_groups = self.dest_neutron.list_security_groups()
        self.migrate_security_groups(source_security_groups['security_groups'],
                                     dest_security_groups['security_groups'])
        self.source_ports = self.source_neutron.list_ports()
        self.source_subnets = self.source_neutron.list_subnets()

        source_networks = self.source_neutron.list_networks()

        # NOTE: These are fields we drop of when creating a subnet as the
        # network api doesn't allow us to specify them.
        # TODO(arosen): revisit this to make these fields passable.
        drop_subnet_fields = ['updated_at',
                              'created_at',
                              'network_id',
                              'id']

        # NOTE: These are fields we drop of when creating a subnet as the
        # network api doesn't allow us to specify them.
        # TODO(arosen): revisit this to make these fields passable.
        drop_port_fields = ['updated_at',
                            'created_at',
                            'security_groups',  # todo
                            'status',
                            'port_security_enabled',
                            'binding:vif_details',
                            'binding:vif_type',
                            'binding:host_id']

        drop_network_fields = ['status', 'subnets']

        for network in source_networks['networks']:

            body = {}
            for k, v in network.items():
                if k in drop_network_fields:
                    continue
                body[k] = v

            created_net = self.dest_neutron.create_network(
                {'network': body})['network']

            print ("Created network: " + created_net['id'])

            for subnet_id in network['subnets']:
                subnet = self.find_subnet_by_id(subnet_id)

                body = {}
                for k, v in subnet.items():
                    if k in drop_subnet_fields:
                        continue
                    body[k] = v

                # specify the network_id that we just created above
                body['network_id'] = created_net['id']
                self.subnet_drop_ipv6_fields_if_v4(body)
                created_subnet = self.dest_neutron.create_subnet(
                    {'subnet': body})['subnet']
                print ("Created subnet: " + created_subnet['id'])

            # create the ports on the network
            ports = self.get_ports_on_network(network['id'])
            for port in ports:

                # TODO handle these later.
                if port['device_owner'] == 'network:router_interface':
                    continue

                body = {}
                for k, v in port.items():
                    if k in drop_port_fields:
                        continue
                    body[k] = v

                # specify the network_id that we just created above
                port['network_id'] = created_net['id']

                # remove the subnet id field from fixed_ips dict
                for fixed_ips in body['fixed_ips']:
                    del fixed_ips['subnet_id']

                created_port = self.dest_neutron.create_port({'port': body})
                print ("Created port: " + created_port['id'])

    def find_subnet_by_id(self, subnet_id):
        for subnet in self.source_subnets['subnets']:
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

    def get_ports_on_network(self, network_id):
        """Returns all the ports on a given network_id."""
        ports_on_network = []
        for port in self.source_ports['ports']:
            if port['network_id'] == network_id:
                ports_on_network.append(port)
        return ports_on_network

    def have_sg_id(self, seg_id, groups):
        """If the sg_id is in groups return true else false."""
        for group in groups:
            if id == group['id']:
                return True

        return False

    def migrate_security_groups(self, source_sec_groups, dest_sec_groups):
        for sg in source_sec_groups:
            if(self.have_sg_id(sg['id'], dest_sec_groups) is False):
                sg_rules = sg.pop('security_group_rules')
                try:
                    print(self.dest_neutron.create_security_group(
                        {'security_group': sg}))
                except:
                    # TODO(arosen): improve exception handing here.
                    pass

                for sg_rule in sg_rules:
                    try:
                        print (self.dest_neutron.create_security_group_rule(
                            {'security_group_rule': sg_rule}))
                    except:
                        # TODO(arosen): improve exception handing here.
                        # TODO(arosen): right now when you create a default
                        # security group there are rules that it automatically
                        # comes with. Today we try and recreate those rules
                        # and they fail to create because they already exist
                        # it would be better if we ignored these rules as we
                        # don't need to try and recreate them.
                        pass
