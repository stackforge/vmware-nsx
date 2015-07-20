# Copyright 2015 OpenStack Foundation

# All Rights Reserved
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

"""
NSX-V3 Plugin security integration module
"""
from oslo_utils import excutils

from neutron.db import securitygroups_db

from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsx_exc
from vmware_nsx.neutron.plugins.vmware.dbexts import nsx_models
from vmware_nsx.neutron.plugins.vmware.nsxlib.v3 import dfw_api as firewall


class NSSecurityDB(securitygroups_db.SecurityGroupDbMixin):

    def _get_l4_protocol_name(self, proto_num):
        if proto_num == 6:
            return firewall.TCP
        elif proto_num == 17:
            return firewall.UDP
        elif proto_num == 1:
            return firewall.ICMPV4

    def _decide_service(self, sg_rule):
        ip_proto = self._get_ip_proto_number(sg_rule['protocol'])
        l4_protocol = self._get_l4_protocol_name(ip_proto)

        if l4_protocol in [firewall.TCP, firewall.UDP]:
            # If port_range_min is not specified then we assume all ports are
            # matched, relying on neutron to perform validation.
            if sg_rule['port_range_min'] is None:
                pass
            source_ports = ['%(port_range_min)s-%(port_range_max)s' % sg_rule]
            return firewall.get_nsservice(firewall.L4_PORT_SET_NSSERVICE,
                                          l4_protocol=l4_protocol,
                                          source_ports=source_ports)
        elif l4_protocol == firewall.ICMPV4:
            return firewall.get_nsservice(firewall.ICMP_TYPE_NSSERVICE,
                                          protocol=l4_protocol,
                                          icmp_type=sg_rule['port_range_min'],
                                          icmp_code=sg_rule['port_range_max'])

    def _get_fw_rule_from_sg_rule(self, sg_rule, nsgroup_id, rmt_nsgroup_id):
        # IPV4 or IPV6
        ip_protocol = sg_rule['ethertype'].upper()
        direction = (
            firewall.IN if sg_rule['direction'] == 'ingress' else firewall.OUT)

        if sg_rule['remote_ip_prefix']:
            if direction == firewall.IN:
                source = firewall.get_ip_cidr_reference(
                    sg_rule['remote_ip_prefix'], ip_protocol)
                destination = nsgroup_id
            else:
                source, destination = destination, source
        elif sg_rule['remote_group_id']:
            if direction == firewall.IN:
                source = firewall.get_nsgroup_reference(rmt_nsgroup_id)
                destination = nsgroup_id
            else:
                source, destination = destination, source
        else:
            # TBD(roeyc): what is the actual required semantics
            source = destination = nsgroup_id

        service = self._decide_service(sg_rule)
        name = sg_rule['id']

        return firewall.get_firewall_rule_dict(name, source,
                                               destination, direction,
                                               ip_protocol, service,
                                               firewall.ALLOW)

    def _create_firewall_rules(self, context, section_id, nsgroup_id,
                               security_group_rules):
        # 1. translate rules
        # 2. insert in section
        # 3. save mappings

        firewall_rules = []
        for sg_rule in security_group_rules:

            remote_sg_id = sg_rule.get('remote_sg_id')

            remote_nsgroup_id = self._get_remote_nsg_mapping(
                context, remote_sg_id, sg_rule['security_group_id'])

            fw_rule = self._get_fw_rule_from_sg_rule(sg_rule,
                                                     nsgroup_id,
                                                     remote_nsgroup_id)

            firewall_rules.append(fw_rule)
        return firewall.add_rules_in_section(firewall_rules, section_id)

    def _save_rule_mappings(self, session, firewall_rules):
        # REVISIT(roeyc): This method should take care db access only.
        rules = [(rule['display_name'], rule['id']) for rule in firewall_rules]
        with session.begin(subtransactions=True):
            for neutron_id, nsx_id in rules:
                mapping = nsx_models.NeutronNsxRuleMapping(
                    neutron_id=neutron_id, nsx_id=nsx_id)
                session.add(mapping)
        return mapping

    def _save_sg_mappings(self, session, sg_id, nsgroup_id, section_id):
        with session.begin(subtransactions=True):
            session.add(
                nsx_models.NeutronNsxFirewallSectionMapping(neutron_id=sg_id,
                                                            nsx_id=section_id))
            session.add(
                nsx_models.NeutronNsxSecurityGroupMapping(neutron_id=sg_id,
                                                          nsx_id=nsgroup_id))

    def _get_sg_mappings(self, session, sg_id):
        nsgroup_id = session.query(nsx_models.NeutronNsxSecurityGroupMapping
                                   ).filter_by(neutron_id=sg_id).one()
        section_id = session.query(nsx_models.NeutronNsxFirewallSectionMapping
                                   ).filter_by(neutron_id=sg_id).one()
        return nsgroup_id, section_id

    def _get_nsgroup_name(self, security_group):
        # Append the security-group id in NSGroup name, for usability purposes.
        return '%(name)s %(id)s' % security_group

    def create_security_group(self, context, security_group, default_sg=False):
        security_group_db = (
            super(NSSecurityDB, self).create_security_group(
                context, security_group, default_sg))

        tenant_id = security_group_db['tenant_id']
        name = self._get_nsgroup_name(security_group_db)

        try:
            ns_group = None
            firewall_section = None

            ns_group = firewall.create_nsgroup(
                name, security_group_db['description'])
            # security-group rules are located in a dedicated firewall section.
            firewall_section = firewall.create_empty_section(
                name, security_group_db['description'], [ns_group['id']],
                tenant_id=tenant_id)

            sg_rules = security_group_db['security_group_rules']
            # translate and creates firewall rules.
            rules = self._create_firewall_rules(
                context, firewall_section['id'], ns_group['id'], sg_rules)
        except nsx_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                # Delete the security-group records from db.
                # default security group deletion requires admin context
                if default_sg:
                    context = context.elevated()
                super(self, NSSecurityDB).delete_security_group(
                    context, security_group_db['id'])
                # If the ns-group or section were created already, then delete
                # them too.
                if ns_group:
                    firewall.delete_nsgroup(ns_group['id'])
                if firewall_section:
                    firewall.delete_section(firewall_section['id'])

        self._save_sg_mappings(context.session, security_group_db['id'],
                               ns_group['id'], firewall_section['id'])
        self._save_rule_mappings(context.session, rules['rules'])

        return security_group_db

    def update_security_group(self, context, id, security_group):
        nsgroup_id, section_id = self._get_sg_mappings(context.session, id)
        updated_security_group = (
            super(NSSecurityDB, self).update_security_group(context, id,
                                                            security_group))
        name = self._get_nsgroup_name(updated_security_group)
        description = updated_security_group['description']
        firewall.update_nsgroup(nsgroup_id, name, description)
        firewall.update_section(section_id, name, description)
        return updated_security_group

    def delete_security_group(self, context, id):
        nsgroup_id, section_id = self._get_sg_mappings(context.session, id)
        super(NSSecurityDB, self).delete_security_group(context, id)
        firewall.delete_section(section_id)
        firewall.delete_nsgroup(nsgroup_id)

    def _get_remote_nsg_mapping(self, context, remote_sg_id, rule_sg_id):
        remote_nsgroup_id = None
        # skip unnecessary db access when possible
        if remote_sg_id == rule_sg_id:
            remote_nsgroup_id = rule_sg_id
        elif remote_sg_id:
            remote_nsgroup_id, _ = self._get_sg_mappings(context.session,
                                                         rule_sg_id)
        return remote_nsgroup_id

    def create_security_group_rule_bulk(self, context, security_group_rules):
        security_group_rules_db = (
            super(NSSecurityDB, self).create_security_group_rule_bulk_native(
                context, security_group_rules))
        sg_id = security_group_rules_db[0]['security_group_id']
        nsgroup_id, section_id = self._get_sg_mappings(context.session, sg_id)
        try:
            rules = self._create_firewall_rules(
                context, section_id, nsgroup_id, security_group_rules_db)
        except nsx_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                for rule in security_group_rules_db:
                    super(NSSecurityDB, self).delete_security_group_rule(
                        context, rule['id'])
        self._save_rule_mappings(context.session, rules['rules'])
        return security_group_rules_db

    def create_security_group_rule(self, context, security_group_rule):
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def delete_security_group_rule(self, context, id):
        super(NSSecurityDB, self).delete_security_group_rule(context, id)

    def _update_lport_with_security_groups(self, context, lport_id,
                                           original, updated):
        added = set(updated) - set(original)
        removed = set(original) - set(updated)
        for sg_id in added:
            nsgroup_id, _ = self._get_sg_mappings(context.session, sg_id)
            firewall.add_nsgroup_member(
                nsgroup_id, firewall.LogicalPort, lport_id)
        for sg_id in removed:
            nsgroup_id, _ = self._get_sg_mappings(context.session, sg_id)
            firewall.remove_nsgroup_member(
                nsgroup_id, lport_id)
