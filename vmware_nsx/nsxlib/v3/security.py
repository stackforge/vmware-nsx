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
NSX-V3 Plugin security integration & Distributed Firewall module
"""

from neutron_lib import constants
from oslo_log import log
from oslo_utils import excutils

from vmware_nsx._i18n import _LE, _LW
from vmware_nsx.nsxlib.v3 import exceptions
from vmware_nsx.nsxlib.v3 import firewall_constants as firewall
from vmware_nsx.nsxlib.v3 import utils


LOG = log.getLogger(__name__)

DEFAULT_SECTION = 'OS Default Section for Neutron Security-Groups'
PORT_SG_SCOPE = 'os-security-group'
MAX_NSGROUPS_CRITERIA_TAGS = 10


class Security(object):

    def _get_l4_protocol_name(self, protocol_number):
        if protocol_number is None:
            return
        protocol_number = constants.IP_PROTOCOL_MAP.get(protocol_number,
                                                        protocol_number)
        protocol_number = int(protocol_number)
        if protocol_number == 6:
            return firewall.TCP
        elif protocol_number == 17:
            return firewall.UDP
        elif protocol_number == 1:
            return firewall.ICMPV4
        else:
            return protocol_number

    def _get_direction(self, sg_rule):
        return (
            firewall.IN if sg_rule['direction'] == 'ingress' else firewall.OUT
        )

    def _decide_service(self, sg_rule):
        l4_protocol = self._get_l4_protocol_name(sg_rule['protocol'])
        direction = self._get_direction(sg_rule)

        if l4_protocol in [firewall.TCP, firewall.UDP]:
            # If port_range_min is not specified then we assume all ports are
            # matched, relying on neutron to perform validation.
            source_ports = []
            if sg_rule['port_range_min'] is None:
                destination_ports = []
            elif sg_rule['port_range_min'] != sg_rule['port_range_max']:
                # NSX API requires a non-empty range (e.g - '22-23')
                destination_ports = ['%(port_range_min)s-%(port_range_max)s'
                                     % sg_rule]
            else:
                destination_ports = ['%(port_range_min)s' % sg_rule]

            if direction == firewall.OUT:
                source_ports, destination_ports = destination_ports, []

            return self.get_nsservice(firewall.L4_PORT_SET_NSSERVICE,
                                      l4_protocol=l4_protocol,
                                      source_ports=source_ports,
                                      destination_ports=destination_ports)
        elif l4_protocol == firewall.ICMPV4:
            return self.get_nsservice(firewall.ICMP_TYPE_NSSERVICE,
                                      protocol=l4_protocol,
                                      icmp_type=sg_rule['port_range_min'],
                                      icmp_code=sg_rule['port_range_max'])
        elif l4_protocol is not None:
            return self.get_nsservice(firewall.IP_PROTOCOL_NSSERVICE,
                                      protocol_number=l4_protocol)

    def _get_fw_rule_from_sg_rule(self, sg_rule, nsgroup_id, rmt_nsgroup_id,
                                  logged, action):
        # IPV4 or IPV6
        ip_protocol = sg_rule['ethertype'].upper()
        direction = self._get_direction(sg_rule)

        if sg_rule.get(firewall.LOCAL_IP_PREFIX):
            local_ip_prefix = self.get_ip_cidr_reference(
                sg_rule[firewall.LOCAL_IP_PREFIX],
                ip_protocol)
        else:
            local_ip_prefix = None

        source = None
        local_group = self.get_nsgroup_reference(nsgroup_id)
        if sg_rule['remote_ip_prefix'] is not None:
            source = self.get_ip_cidr_reference(
                sg_rule['remote_ip_prefix'], ip_protocol)
            destination = local_ip_prefix or local_group
        else:
            if rmt_nsgroup_id:
                source = self.get_nsgroup_reference(rmt_nsgroup_id)
            destination = local_ip_prefix or local_group
        if direction == firewall.OUT:
            source, destination = destination, source

        service = self._decide_service(sg_rule)
        name = sg_rule['id']

        return self.get_firewall_rule_dict(name, source,
                                           destination, direction,
                                           ip_protocol, service,
                                           action, logged)

    def create_firewall_rules(self, context, section_id, nsgroup_id,
                              logging_enabled, action, security_group_rules,
                              ruleid_2_remote_nsgroup_map):

        # 1. translate rules
        # 2. insert in section
        # 3. return the rules
        firewall_rules = []
        for sg_rule in security_group_rules:
            remote_nsgroup_id = ruleid_2_remote_nsgroup_map[sg_rule['id']]
            fw_rule = self._get_fw_rule_from_sg_rule(
                sg_rule, nsgroup_id, remote_nsgroup_id,
                logging_enabled, action)

            firewall_rules.append(fw_rule)

        return self.add_rules_in_section(firewall_rules, section_id)

    def _process_firewall_section_rules_logging_for_update(self, section_id,
                                                           logging_enabled):
        rules = self.get_section_rules(section_id).get('results', [])
        update_rules = False
        for rule in rules:
            if rule['logged'] != logging_enabled:
                rule['logged'] = logging_enabled
                update_rules = True
        return rules if update_rules else None

    def set_firewall_rule_logging_for_section(self, section_id, logging):
        rules = self._process_firewall_section_rules_logging_for_update(
            section_id, logging)
        self.update_section(section_id, rules=rules)

    def update_security_group_on_backend(self, context, security_group,
                                         nsgroup_id, section_id,
                                         log_sg_allowed_traffic):
        name = self.get_nsgroup_name(security_group)
        description = security_group['description']
        logging = (log_sg_allowed_traffic or
                   security_group[firewall.LOGGING])
        rules = self._process_firewall_section_rules_logging_for_update(
            section_id, logging)
        self.update_nsgroup(nsgroup_id, name, description)
        self.update_section(section_id, name, description, rules=rules)

    def get_nsgroup_name(self, security_group):
        # NOTE(roeyc): We add the security-group id to the NSGroup name,
        # for usability purposes.
        return '%(name)s - %(id)s' % security_group

    def get_lport_tags_for_security_groups(self, secgroups):
        if len(secgroups) > MAX_NSGROUPS_CRITERIA_TAGS:
            raise exceptions.NumberOfNsgroupCriteriaTagsReached(
                max_num=MAX_NSGROUPS_CRITERIA_TAGS)
        tags = []
        for sg in secgroups:
            tags = utils.add_v3_tag(tags, PORT_SG_SCOPE, sg)
        if not tags:
            # This port shouldn't be associated with any security-group
            tags = [{'scope': PORT_SG_SCOPE, 'tag': None}]
        return tags

    def update_lport_with_security_groups(self, context, lport_id,
                                          original, updated):
        added = set(updated) - set(original)
        removed = set(original) - set(updated)
        for nsgroup_id in added:
            try:
                self.add_nsgroup_members(
                    nsgroup_id, firewall.LOGICAL_PORT, [lport_id])
            except exceptions.NSGroupIsFull:
                for nsgroup_id in added:
                    # NOTE(roeyc): If the port was not added to the nsgroup
                    # yet, then this request will silently fail.
                    self.remove_nsgroup_member(
                        nsgroup_id, firewall.LOGICAL_PORT, lport_id)
                raise exceptions.SecurityGroupMaximumCapacityReached(
                    sg_id=nsgroup_id)
            except exceptions.ResourceNotFound:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("NSGroup %s doesn't exists"), nsgroup_id)
        for nsgroup_id in removed:
            self.remove_nsgroup_member(
                nsgroup_id, firewall.LOGICAL_PORT, lport_id)

    def init_default_section(self, name, description, nested_groups,
                             log_sg_blocked_traffic):
        fw_sections = self.list_sections()
        for section in fw_sections:
            if section['display_name'] == name:
                break
        else:
            tags = utils.build_v3_api_version_tag()
            section = self.create_empty_section(
                name, description, nested_groups, tags)

        block_rule = self.get_firewall_rule_dict(
            'Block All', action=firewall.DROP,
            logged=log_sg_blocked_traffic)
        # TODO(roeyc): Add additional rules to allow IPV6 NDP.
        dhcp_client = self.get_nsservice(firewall.L4_PORT_SET_NSSERVICE,
                                         l4_protocol=firewall.UDP,
                                         source_ports=[67],
                                         destination_ports=[68])
        dhcp_client_rule_in = self.get_firewall_rule_dict(
            'DHCP Reply', direction=firewall.IN, service=dhcp_client)

        dhcp_server = (
            self.get_nsservice(firewall.L4_PORT_SET_NSSERVICE,
                               l4_protocol=firewall.UDP,
                               source_ports=[68],
                               destination_ports=[67]))
        dhcp_client_rule_out = self.get_firewall_rule_dict(
            'DHCP Request', direction=firewall.OUT, service=dhcp_server)

        self.update_section(section['id'],
                            name, section['description'],
                            applied_tos=nested_groups,
                            rules=[dhcp_client_rule_out,
                                   dhcp_client_rule_in,
                                   block_rule])
        return section['id']

    def get_nsservice(self, resource_type, **properties):
        service = {'resource_type': resource_type}
        service.update(properties)
        return {'service': service}

    def get_nsgroup_port_tag_expression(self, scope, tag):
        return {'resource_type': firewall.NSGROUP_TAG_EXPRESSION,
                'target_type': firewall.LOGICAL_PORT,
                'scope': scope,
                'tag': tag}

    def create_nsgroup(self, display_name, description, tags,
                       membership_criteria=None):
        body = {'display_name': display_name,
                'description': description,
                'tags': tags,
                'members': []}
        if membership_criteria:
            body.update({'membership_criteria': [membership_criteria]})
        return self.client.create('ns-groups', body)

    def list_nsgroups(self):
        return self.client.get(
            'ns-groups?populate_references=false').get('results', [])

    @utils.retry_upon_exception(exceptions.StaleRevision)
    def update_nsgroup(self, nsgroup_id, display_name=None, description=None,
                       membership_criteria=None, members=None):
        nsgroup = self.read_nsgroup(nsgroup_id)
        if display_name is not None:
            nsgroup['display_name'] = display_name
        if description is not None:
            nsgroup['description'] = description
        if members is not None:
            nsgroup['members'] = members
        if membership_criteria is not None:
            nsgroup['membership_criteria'] = [membership_criteria]
        return self.client.update(
            'ns-groups/%s' % nsgroup_id, nsgroup)

    def get_nsgroup_member_expression(self, target_type, target_id):
        return {'resource_type': firewall.NSGROUP_SIMPLE_EXPRESSION,
                'target_property': 'id',
                'target_type': target_type,
                'op': firewall.EQUALS,
                'value': target_id}

    @utils.retry_upon_exception(exceptions.ManagerError)
    def _update_nsgroup_with_members(self, nsgroup_id, members, action):
        members_update = 'ns-groups/%s?action=%s' % (nsgroup_id, action)
        return self.client.create(members_update, members)

    def add_nsgroup_members(self, nsgroup_id, target_type, target_ids):
        members = []
        for target_id in target_ids:
            member_expr = self.get_nsgroup_member_expression(
                target_type, target_id)
            members.append(member_expr)
        members = {'members': members}
        try:
            return self._update_nsgroup_with_members(
                nsgroup_id, members, firewall.ADD_MEMBERS)
        except (exceptions.StaleRevision, exceptions.ResourceNotFound):
            raise
        except exceptions.ManagerError:
            # REVISIT(roeyc): A ManagerError might have been raised for a
            # different reason, e.g - NSGroup does not exists.
            LOG.warning(_LW("Failed to add %(target_type)s resources "
                            "(%(target_ids))s to NSGroup %(nsgroup_id)s"),
                        {'target_type': target_type,
                         'target_ids': target_ids,
                         'nsgroup_id': nsgroup_id})

            raise exceptions.NSGroupIsFull(nsgroup_id=nsgroup_id)

    def remove_nsgroup_member(self, nsgroup_id, target_type,
                              target_id, verify=False):
        member_expr = self.get_nsgroup_member_expression(
            target_type, target_id)
        members = {'members': [member_expr]}
        try:
            return self._update_nsgroup_with_members(
                nsgroup_id, members, firewall.REMOVE_MEMBERS)
        except exceptions.ManagerError:
            if verify:
                raise exceptions.NSGroupMemberNotFound(member_id=target_id,
                                                       nsgroup_id=nsgroup_id)

    def read_nsgroup(self, nsgroup_id):
        return self.client.get(
            'ns-groups/%s?populate_references=true' % nsgroup_id)

    def delete_nsgroup(self, nsgroup_id):
        try:
            return self.client.delete(
                'ns-groups/%s?force=true' % nsgroup_id)
        # FIXME(roeyc): Should only except NotFound error.
        except Exception:
            LOG.debug("NSGroup %s does not exists for delete request.",
                      nsgroup_id)

    def _build_section(self, display_name, description, applied_tos, tags):
        return {'display_name': display_name,
                'description': description,
                'stateful': True,
                'section_type': firewall.LAYER3,
                'applied_tos': [self.get_nsgroup_reference(t_id)
                                for t_id in applied_tos],
                'tags': tags}

    def create_empty_section(self, display_name, description, applied_tos,
                             tags, operation=firewall.INSERT_BOTTOM,
                             other_section=None):
        resource = 'firewall/sections?operation=%s' % operation
        body = self._build_section(display_name, description,
                                   applied_tos, tags)
        if other_section:
            resource += '&id=%s' % other_section
        return self.client.create(resource, body)

    @utils.retry_upon_exception(exceptions.StaleRevision)
    def update_section(self, section_id, display_name=None, description=None,
                       applied_tos=None, rules=None):
        resource = 'firewall/sections/%s' % section_id
        section = self.read_section(section_id)

        if rules is not None:
            resource += '?action=update_with_rules'
            section.update({'rules': rules})
        if display_name is not None:
            section['display_name'] = display_name
        if description is not None:
            section['description'] = description
        if applied_tos is not None:
            section['applied_tos'] = [self.get_nsgroup_reference(nsg_id)
                                      for nsg_id in applied_tos]
        if rules is not None:
            return self.client.create(resource, section)
        elif any(p is not None for p in (display_name, description,
                                         applied_tos)):
            return self.client.update(resource, section)

    def read_section(self, section_id):
        resource = 'firewall/sections/%s' % section_id
        return self.client.get(resource)

    def list_sections(self):
        resource = 'firewall/sections'
        return self.client.get(resource).get('results', [])

    def delete_section(self, section_id):
        resource = 'firewall/sections/%s?cascade=true' % section_id
        return self.client.delete(resource)

    def get_nsgroup_reference(self, nsgroup_id):
        return {'target_id': nsgroup_id,
                'target_type': firewall.NSGROUP}

    def get_ip_cidr_reference(self, ip_cidr_block, ip_protocol):
        target_type = (firewall.IPV4ADDRESS if ip_protocol == firewall.IPV4
                       else firewall.IPV6ADDRESS)
        return {'target_id': ip_cidr_block,
                'target_type': target_type}

    def get_firewall_rule_dict(self, display_name, source=None,
                               destination=None,
                               direction=firewall.IN_OUT,
                               ip_protocol=firewall.IPV4_IPV6,
                               service=None, action=firewall.ALLOW,
                               logged=False):
        return {'display_name': display_name,
                'sources': [source] if source else [],
                'destinations': [destination] if destination else [],
                'direction': direction,
                'ip_protocol': ip_protocol,
                'services': [service] if service else [],
                'action': action,
                'logged': logged}

    def add_rule_in_section(self, rule, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        params = '?operation=insert_bottom'
        return self.client.create(resource + params, rule)

    def add_rules_in_section(self, rules, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        params = '?action=create_multiple&operation=insert_bottom'
        return self.client.create(resource + params, {'rules': rules})

    def delete_rule(self, section_id, rule_id):
        resource = 'firewall/sections/%s/rules/%s' % (section_id, rule_id)
        return self.client.delete(resource)

    def get_section_rules(self, section_id):
        resource = 'firewall/sections/%s/rules' % section_id
        return self.client.get(resource)
