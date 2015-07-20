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
from oslo_log import log

from neutron.db import securitygroups_db

from vmware_nsx.neutron.plugins.vmware.dbexts import nsx_models
from vmware_nsx.neutron.plugins.vmware.nsxlib.v3 import dfw_api as firewall

LOG = log.getLogger(__name__)


def _get_l4_protocol_name(proto_num):
    if proto_num == 6:
        return firewall.TCP
    elif proto_num == 17:
        return firewall.UDP
    elif proto_num == 1:
        return firewall.ICMPV4


def _decide_service(sg_rule):
    ip_proto = securitygroups_db.IP_PROTOCOL_MAP.get(sg_rule['protocol'],
                                                     sg_rule['protocol'])
    l4_protocol = _get_l4_protocol_name(ip_proto)

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
    else:
        return firewall.get_nsservice(firewall.IP_PROTOCOL_NSSERVICE,
                                      protocol_number=ip_proto)


def _get_fw_rule_from_sg_rule(sg_rule, nsgroup_id, rmt_nsgroup_id):
    # IPV4 or IPV6
    ip_protocol = sg_rule['ethertype'].upper()
    direction = (
        firewall.IN if sg_rule['direction'] == 'ingress' else firewall.OUT)

    source = None
    local_group = firewall.get_nsgroup_reference(nsgroup_id)
    if sg_rule['remote_ip_prefix'] is not None:
        source = firewall.get_ip_cidr_reference(sg_rule['remote_ip_prefix'],
                                                ip_protocol)
        destination = local_group
    else:
        if rmt_nsgroup_id:
            source = firewall.get_nsgroup_reference(rmt_nsgroup_id)
        destination = local_group
    if direction == firewall.OUT:
        source, destination = destination, source

    service = _decide_service(sg_rule)
    name = sg_rule['id']

    return firewall.get_firewall_rule_dict(name, source,
                                           destination, direction,
                                           ip_protocol, service,
                                           firewall.ALLOW)


def create_firewall_rules(context, section_id, nsgroup_id,
                          security_group_rules):

    # 1. translate rules
    # 2. insert in section
    # 3. save mappings

    firewall_rules = []
    for sg_rule in security_group_rules:
        remote_nsgroup_id = _get_remote_nsg_mapping(
            context, sg_rule, nsgroup_id)

        fw_rule = _get_fw_rule_from_sg_rule(
            sg_rule, nsgroup_id, remote_nsgroup_id)

        firewall_rules.append(
            firewall.add_rule_in_section(fw_rule, section_id))
    return {'rules': firewall_rules}


def get_nsgroup_name(security_group):
    # Append the security-group id in NSGroup name, for usability purposes.
    return '%(name)s %(id)s' % security_group


def save_sg_rule_mappings(session, firewall_rules):
    # REVISIT(roeyc): This method should take care db access only.
    rules = [(rule['display_name'], rule['id']) for rule in firewall_rules]
    with session.begin(subtransactions=True):
        for neutron_id, nsx_id in rules:
            mapping = nsx_models.NeutronNsxRuleMapping(
                neutron_id=neutron_id, nsx_id=nsx_id)
            session.add(mapping)
    return mapping


def save_sg_mappings(session, sg_id, nsgroup_id, section_id):
    with session.begin(subtransactions=True):
        session.add(
            nsx_models.NeutronNsxFirewallSectionMapping(neutron_id=sg_id,
                                                        nsx_id=section_id))
        session.add(
            nsx_models.NeutronNsxSecurityGroupMapping(neutron_id=sg_id,
                                                      nsx_id=nsgroup_id))


def get_sg_rule_mapping(session, rule_id):
    rule_mapping = session.query(nsx_models.NeutronNsxRuleMapping).filter_by(
        neutron_id=rule_id).one()
    return rule_mapping.nsx_id


def get_sg_mappings(session, sg_id):
    nsgroup_mapping = session.query(nsx_models.NeutronNsxSecurityGroupMapping
                                    ).filter_by(neutron_id=sg_id).one()
    section_mapping = session.query(nsx_models.NeutronNsxFirewallSectionMapping
                                    ).filter_by(neutron_id=sg_id).one()
    return nsgroup_mapping.nsx_id, section_mapping.nsx_id


def _get_remote_nsg_mapping(context, sg_rule, nsgroup_id):
    remote_nsgroup_id = None
    remote_group_id = sg_rule.get('remote_group_id')
    # skip unnecessary db access when possible
    if remote_group_id == sg_rule['security_group_id']:
        remote_nsgroup_id = nsgroup_id
    elif remote_group_id:
        remote_nsgroup_id, _ = get_sg_mappings(context.session,
                                               remote_group_id)
    return remote_nsgroup_id


def update_lport_with_security_groups(context, lport_id, original, updated):
    added = set(updated) - set(original)
    removed = set(original) - set(updated)
    for sg_id in added:
        nsgroup_id, _ = get_sg_mappings(context.session, sg_id)
        firewall.add_nsgroup_member(
            nsgroup_id, firewall.LogicalPort, lport_id)
    for sg_id in removed:
        nsgroup_id, _ = get_sg_mappings(context.session, sg_id)
        firewall.remove_nsgroup_member(
            nsgroup_id, lport_id)
