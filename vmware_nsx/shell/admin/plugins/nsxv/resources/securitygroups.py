# Copyright 2016 VMware, Inc.  All rights reserved.
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


import logging
import xml.etree.ElementTree as et

from neutron.callbacks import registry
from neutron import context
from neutron.db import securitygroups_db
from neutron import manager

from vmware_nsx.db import nsx_models
from vmware_nsx.db import nsxv_models
from vmware_nsx.nsxlib.v3 import dfw_api as firewall
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils
from vmware_nsx.shell import nsxadmin


LOG = logging.getLogger(__name__)


class NeutronSecurityGroupDB(utils.NeutronDbClient):
    def __init__(self):
        super(NeutronSecurityGroupDB, self)
        # FIXME(roeyc): context is already defined in NeutrondDbClient
        self.context = context.get_admin_context()

    def get_security_groups_mappings(self):
        q = self.context.session.query(
            securitygroups_db.SecurityGroup.name,
            securitygroups_db.SecurityGroup.id,
            nsxv_models.NsxvSecurityGroupSectionMapping.ip_section_id,
            nsx_models.NeutronNsxSecurityGroupMapping.nsx_id).join(
                nsxv_models.NsxvSecurityGroupSectionMapping,
                nsx_models.NeutronNsxSecurityGroupMapping).all()
        sg_mappings = [{'name': mapp.name,
                        'id': mapp.id,
                        'section-uri': mapp.ip_section_id,
                        'nsx-securitygroup-id': mapp.nsx_id}
                       for mapp in q]
        return sg_mappings

    def get_security_group(self, sg_id):
        return super(NeutronSecurityGroupDB, self).get_security_group(
            self.context, sg_id)

    def get_security_groups(self):
        return super(NeutronSecurityGroupDB,
                     self).get_security_groups(self.context)

    def delete_security_group_section_mapping(self, sg_id):
        fw_mapping = self.context.session.query(
            nsxv_models.NsxvSecurityGroupSectionMapping).filter(
                neutron_id=sg_id).one_or_none()
        if fw_mapping:
            with self.context.session.begin(subtransactions=True):
                self.context.session.delete(fw_mapping)

    def delete_security_group_backend_mapping(self, sg_id):
        sg_mapping = self.context.session.query(
            nsx_models.NeutronNsxSecurityGroupMapping).filter(
                neutron_id=sg_id).one_or_none()
        if sg_mapping:
            with self.context.session.begin(subtransactions=True):
                self.context.session.delete(sg_mapping)

    def _get_logical_ports_in_security_group(self, security_group_id):
        query = self.context.session.query(
            securitygroups_db.SecurityGroupPortBinding,
            nsx_models.NeutronNsxPortMapping).filter(
                securitygroups_db.SecurityGroupPortBinding.security_group_id
                == security_group_id,
                securitygroups_db.SecurityGroupPortBinding.port_id
                == nsx_models.NeutronNsxPortMapping.neutron_id).all()
        return [p['nsx_port_id'] for p in query]


class NsxFirewallAPI(object):
    def __init__(self):
        self.vcns = utils.get_nsxv_client()

    def list_security_groups(self):
        h, secgroups = self.vcns.list_security_groups()
        root = et.fromstring(secgroups)
        secgroups = []
        for sg in root.iter('securitygroup'):
            sg_id = sg.find('objectId').text
            # This specific security-group is not relevant to the plugin
            if sg_id == 'securitygroup-1':
                continue
            secgroups.append({'name': sg.find('name').text,
                              'id': sg_id})
        return secgroups

    def list_fw_sections(self):
        h, firewall_config = self.vcns.get_dfw_config()
        root = et.fromstring(firewall_config)
        sections = []
        for sec in root.iter('section'):
            sec_id = sec.attrib['id']
            # Don't show NSX default sections, which are not relevant to OS.
            if sec_id in ['1001', '1002', '1003']:
                continue
            sections.append({'name': sec.attrib['name'],
                             'id': sec_id})
        return sections


neutron_sg = NeutronSecurityGroupDB()
nsxv_firewall = NsxFirewallAPI()


def _log_info(resource, data, attrs=['name', 'id']):
    LOG.info(formatters.output_formatter(resource, data, attrs))


def list_handler(resource):
    def wrap(func):
        registry.subscribe(func, resource,
                           nsxadmin.Operations.LIST.value)
        return func
    return wrap


def list_mismatches_handler(resource):
    def wrap(func):
        registry.subscribe(func, resource,
                           nsxadmin.Operations.LIST_MISMATCHES.value)
        return func
    return wrap

def fix_mismatches_handler(resource):
    def wrap(func):
        registery.subscribe(func, resource,
                            nsxadmin.Operations.FIX_MISMATCH.value)
        return func
    return wrap


@list_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
def neutron_list_security_groups_mappings(resource, event, trigger, **kwargs):
    sg_mappings = neutron_sg.get_security_groups_mappings()
    _log_info(constants.SECURITY_GROUPS,
              sg_mappings,
              attrs=['name', 'id', 'section-uri', 'nsx-securitygroup-id'])
    return bool(sg_mappings)


@list_handler(constants.FIREWALL_SECTIONS)
@admin_utils.output_header
def nsx_list_dfw_sections(resource, event, trigger, **kwargs):
    fw_sections = nsxv_firewall.list_fw_sections()
    _log_info(constants.FIREWALL_SECTIONS, fw_sections)
    return bool(fw_sections)


@list_handler(constants.FIREWALL_NSX_GROUPS)
@admin_utils.output_header
def nsx_list_security_groups(resource, event, trigger, **kwargs):
    nsx_secgroups = nsxv_firewall.list_security_groups()
    _log_info(constants.FIREWALL_NSX_GROUPS, nsx_secgroups)
    return bool(nsx_secgroups)


def _find_missing_security_groups():
    nsx_secgroups = nsxv_firewall.list_security_groups()
    sg_mappings = neutron_sg.get_security_groups_mappings()
    missing_secgroups = []
    for sg_db in sg_mappings:
        for nsx_sg in nsx_secgroups:
            if nsx_sg['id'] == sg_db['nsx-securitygroup-id']:
                break
        else:
            missing_secgroups.append(sg_db)
        return missing_secgroups


@list_mismatches_handler(constants.FIREWALL_NSX_GROUPS)
@admin_utils.output_header
def list_missing_security_groups(resource, event, trigger, **kwargs):
    sgs_with_missing_nsx_group = _find_missing_security_groups()
    missing_securitgroups_info = [{'securitygroup-name': sg['name'],
                                   'securitygroup-id': sg['id'],
                                   'nsx-securitygroup-id':
                                   sg['nsx-securitygroup-id']}
                                  for sg in sgs_with_missing_nsx_group]
    _log_info(constants.FIREWALL_NSX_GROUPS, missing_securitgroups_info,
              attrs=['securitygroup-name', 'securitygroup-id',
                     'nsx-securitygroup-id'])
    return bool(missing_securitgroups_info)


def _find_missing_sections():
    fw_sections = nsxv_firewall.list_fw_sections()
    sg_mappings = neutron_sg.get_security_groups_mappings()
    missing_sections = []
    for sg_db in sg_mappings:
        for fw_section in fw_sections:
            if fw_section['id'] == sg_db.get('section-uri', '').split('/')[-1]:
                break
        else:
            missing_sections.append(sg_db)
    return missing_sections


@list_mismatches_handler(constants.FIREWALL_SECTIONS)
@admin_utils.output_header
def list_missing_firewall_sections(resource, event, trigger, **kwargs):
    sgs_with_missing_section = _find_missing_sections()
    missing_sections_info = [{'securitygroup-name': sg['name'],
                              'securitygroup-id': sg['id'],
                              'section-id': sg['section-uri']}
                             for sg in sgs_with_missing_section]
    _log_info(constants.FIREWALL_SECTIONS, missing_sections_info,
              attrs=['securitygroup-name', 'securitygroup-id', 'section-uri'])
    return bool(missing_sections_info)


@fix_mismatches_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
def fix_security_groups(resource, event, trigger, **kwargs):
    context_ = context.get_admin_context()
    plugin = manager.NeutronManager.get_plugin()
    sgs_with_missing_section = _find_missing_sections()
    sgs_with_missing_nsx_group = _find_missing_security_groups()
    # If only the fw section is missing then create it.
    for sg in (set([sg['id'] for sg in sgs_with_missing_section]) -
               set([sg['id'] for sg in sgs_with_missing_nsx_group])):
        neutron_sg.delete_security_group_section_mapping(sg['id'])
        secgroup = neutron_sg.get_security_group(sg['id'])
        plugin._create_fw_section_for_security_group(
            context_, secgroup, sg['nsx-securitygroup-id'])

    # If nsx security-group is missing then create both nsx security-group and
    # a new fw section (remove old one).
    for sg in sgs_with_missing_nsx_group:
        secgroup = neutron_sg.get_security_group(sg['id'])
        plugin._delete_section(sg['section-uri'])
        neutron_sg.delete_security_group_section_mapping(sg['id'])
        neutron_sg.delete_security_group_backend_mapping(sg['id'])
        plugin._process_security_group_create_backend_resources(context,
                                                                secgroup)
        members = []
        for lp in neutron_sg._get_logical_ports_in_security_group(sg['id']):
            member_expr = firewall.get_nsgroup_member_expression(
                firewall.LOGICAL_PORT, lp)
            members.append(member_expr)
        firewall.update_nsgroup_with_members(sg['nsx-securitygroup-id'],
                                             {'members': members},
                                             firewall.ADD_MEMBERS)
