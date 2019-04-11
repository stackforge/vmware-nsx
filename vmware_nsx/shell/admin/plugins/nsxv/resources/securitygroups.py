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

import operator
import re
import xml.etree.ElementTree as et

from neutron.db.models import securitygroup as sg_models
from neutron.db import models_v2
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.callbacks import registry
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from oslo_log import log as logging

from vmware_nsx.common import utils as com_utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import extended_security_group as extended_secgroup
from vmware_nsx.db import extended_security_group_rule as extend_sg_rule
from vmware_nsx.db import nsx_models
from vmware_nsx.db import nsxv_db
from vmware_nsx.db import nsxv_models
from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.extensions import securitygrouppolicy as sg_policy
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils
from vmware_nsx.shell import resources as shell


LOG = logging.getLogger(__name__)


class NeutronSecurityGroupDB(
    utils.NeutronDbClient,
    securitygroups_db.SecurityGroupDbMixin,
    extended_secgroup.ExtendedSecurityGroupPropertiesMixin,
    extend_sg_rule.ExtendedSecurityGroupRuleMixin):

    def __init__(self):
        super(NeutronSecurityGroupDB, self)
        # FIXME(roeyc): context is already defined in NeutrondDbClient
        self.context = n_context.get_admin_context()

    def get_security_groups_mappings(self):
        q = self.context.session.query(
            sg_models.SecurityGroup.name,
            sg_models.SecurityGroup.id,
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

    def get_security_group_rules_mappings(self):
        q = self.context.session.query(
            sg_models.SecurityGroupRule.id,
            nsxv_models.NsxvRuleMapping.nsx_rule_id).join(
                nsxv_models.NsxvRuleMapping).all()
        sg_mappings = [{'rule_id': mapp[0],
                        'nsx_rule_id': mapp[1]}
                       for mapp in q]
        return sg_mappings

    def get_security_group(self, sg_id):
        return super(NeutronSecurityGroupDB, self).get_security_group(
            self.context, sg_id)

    def get_security_groups(self):
        filters = utils.get_plugin_filters(self.context)
        return super(NeutronSecurityGroupDB,
                     self).get_security_groups(self.context, filters=filters)

    def get_security_group_id_by_section_id(self, section_id):
        section_url = ("/api/4.0/firewall/globalroot-0/config/layer3sections"
                       "/%s" % section_id)
        q = self.context.session.query(
            nsxv_models.NsxvSecurityGroupSectionMapping).filter_by(
            ip_section_id=section_url).all()
        if q:
            return q[0].neutron_id

    def _is_provider_section(self, section_id):
        # look for this section id in the nsx_db, and get the security group
        sg_id = self.get_security_group_id_by_section_id(section_id)
        if sg_id:
            # Check in the DB if this is a provider SG
            return self._is_provider_security_group(self.context, sg_id)
        return False

    def delete_security_group_section_mapping(self, sg_id):
        with db_api.CONTEXT_WRITER.using(self.context):
            fw_mapping = self.context.session.query(
                nsxv_models.NsxvSecurityGroupSectionMapping).filter_by(
                    neutron_id=sg_id).one_or_none()
            if fw_mapping:
                self.context.session.delete(fw_mapping)

    def delete_security_group_backend_mapping(self, sg_id):
        with db_api.CONTEXT_WRITER.using(self.context):
            sg_mapping = self.context.session.query(
                nsx_models.NeutronNsxSecurityGroupMapping).filter_by(
                    neutron_id=sg_id).one_or_none()
            if sg_mapping:
                self.context.session.delete(sg_mapping)

    def get_vnics_in_security_group(self, security_group_id):
        with utils.NsxVPluginWrapper() as plugin:
            vnics = []
            query = self.context.session.query(
                models_v2.Port.id, models_v2.Port.device_id
            ).join(sg_models.SecurityGroupPortBinding).filter_by(
                security_group_id=security_group_id).all()
            for p in query:
                vnic_index = plugin._get_port_vnic_index(self.context, p.id)
                vnic_id = plugin._get_port_vnic_id(vnic_index, p.device_id)
                vnics.append(vnic_id)
            return vnics


class NsxFirewallAPI(object):
    def __init__(self):
        self.vcns = utils.get_nsxv_client()

    def list_security_groups(self):
        h, secgroups = self.vcns.list_security_groups()
        if not secgroups:
            return []
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
        if not firewall_config:
            return []
        root = com_utils.normalize_xml(firewall_config)
        sections = []
        for sec in root.iter('section'):
            sec_id = sec.attrib['id']
            # Don't show NSX default sections, which are not relevant to OS.
            if sec_id in ['1001', '1002', '1003']:
                continue
            sections.append({'name': sec.attrib['name'],
                             'id': sec_id})
        return sections

    def delete_fw_section(self, section_id):
        section_uri = ("/api/4.0/firewall/globalroot-0/"
                       "config/layer3sections/%s" % section_id)
        self.vcns.delete_section(section_uri)

    def list_fw_section_rules(self, section_uri):
        return self.vcns.get_section_rules(section_uri)

    def remove_rule_from_section(self, section_uri, rule_id):
        return self.vcns.remove_rule_from_section(section_uri, rule_id)

    def reorder_fw_sections(self):
        # read all the sections
        h, firewall_config = self.vcns.get_dfw_config()
        if not firewall_config:
            LOG.info("No firewall sections were found.")
            return

        root = com_utils.normalize_xml(firewall_config)

        for child in root:
            if str(child.tag) == 'layer3Sections':
                # go over the L3 sections and reorder them.
                # The correct order should be:
                # 1. OS provider security groups
                # 2. service composer policies
                # 3. regular OS security groups
                sections = list(child.iter('section'))
                provider_sections = []
                regular_sections = []
                policy_sections = []

                for sec in sections:
                    if sec.attrib.get('managedBy') == 'NSX Service Composer':
                        policy_sections.append(sec)
                    else:
                        if neutron_sg._is_provider_section(
                            sec.attrib.get('id')):
                            provider_sections.append(sec)
                        else:
                            regular_sections.append(sec)
                    child.remove(sec)

                if not policy_sections and not provider_sections:
                    LOG.info("No need to reorder the firewall sections.")
                    return

                # reorder the sections
                reordered_sections = (provider_sections +
                                      policy_sections +
                                      regular_sections)
                child.extend(reordered_sections)

                # update the new order of sections in the backend
                self.vcns.update_dfw_config(et.tostring(root), h)
                LOG.info("L3 Firewall sections were reordered.")


neutron_sg = NeutronSecurityGroupDB()
nsxv_firewall = NsxFirewallAPI()


def _log_info(resource, data, attrs=['name', 'id']):
    LOG.info(formatters.output_formatter(resource, data, attrs))


@admin_utils.list_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
def neutron_list_security_groups_mappings(resource, event, trigger, **kwargs):
    sg_mappings = neutron_sg.get_security_groups_mappings()
    _log_info(constants.SECURITY_GROUPS,
              sg_mappings,
              attrs=['name', 'id', 'section-uri', 'nsx-securitygroup-id'])
    return bool(sg_mappings)


@admin_utils.list_handler(constants.FIREWALL_SECTIONS)
@admin_utils.output_header
def nsx_list_dfw_sections(resource, event, trigger, **kwargs):
    fw_sections = nsxv_firewall.list_fw_sections()
    _log_info(constants.FIREWALL_SECTIONS, fw_sections)
    return bool(fw_sections)


@admin_utils.list_handler(constants.FIREWALL_NSX_GROUPS)
@admin_utils.output_header
def nsx_list_security_groups(resource, event, trigger, **kwargs):
    nsx_secgroups = nsxv_firewall.list_security_groups()
    _log_info(constants.FIREWALL_NSX_GROUPS, nsx_secgroups)
    return bool(nsx_secgroups)


def _find_missing_security_groups():
    nsx_secgroups = nsxv_firewall.list_security_groups()
    sg_mappings = neutron_sg.get_security_groups_mappings()
    missing_secgroups = {}
    for sg_db in sg_mappings:
        for nsx_sg in nsx_secgroups:
            if nsx_sg['id'] == sg_db['nsx-securitygroup-id']:
                break
        else:
            missing_secgroups[sg_db['id']] = sg_db
    return missing_secgroups


@admin_utils.list_mismatches_handler(constants.FIREWALL_NSX_GROUPS)
@admin_utils.output_header
def list_missing_security_groups(resource, event, trigger, **kwargs):
    sgs_with_missing_nsx_group = _find_missing_security_groups()
    missing_securitgroups_info = [
        {'securitygroup-name': sg['name'],
         'securitygroup-id': sg['id'],
         'nsx-securitygroup-id':
         sg['nsx-securitygroup-id']}
        for sg in sgs_with_missing_nsx_group.values()]
    _log_info(constants.FIREWALL_NSX_GROUPS, missing_securitgroups_info,
              attrs=['securitygroup-name', 'securitygroup-id',
                     'nsx-securitygroup-id'])
    return bool(missing_securitgroups_info)


def _find_missing_sections():
    fw_sections = nsxv_firewall.list_fw_sections()
    sg_mappings = neutron_sg.get_security_groups_mappings()
    missing_sections = {}
    for sg_db in sg_mappings:
        for fw_section in fw_sections:
            if fw_section['id'] == sg_db.get('section-uri', '').split('/')[-1]:
                break
        else:
            missing_sections[sg_db['id']] = sg_db
    return missing_sections


@admin_utils.list_mismatches_handler(constants.FIREWALL_SECTIONS)
@admin_utils.output_header
def list_missing_firewall_sections(resource, event, trigger, **kwargs):
    sgs_with_missing_section = _find_missing_sections()
    missing_sections_info = [{'securitygroup-name': sg['name'],
                              'securitygroup-id': sg['id'],
                              'section-id': sg['section-uri']}
                             for sg in sgs_with_missing_section.values()]
    _log_info(constants.FIREWALL_SECTIONS, missing_sections_info,
              attrs=['securitygroup-name', 'securitygroup-id', 'section-uri'])
    return bool(missing_sections_info)


def _get_unused_firewall_sections():
    fw_sections = nsxv_firewall.list_fw_sections()
    sg_mappings = neutron_sg.get_security_groups_mappings()
    unused_sections = []
    for fw_section in fw_sections:
        for sg_db in sg_mappings:
            if fw_section['id'] == sg_db.get('section-uri', '').split('/')[-1]:
                break
        else:
            # skip sections with non neutron like names
            if re.search("SG Section: .* (.*)", fw_section['name']):
                unused_sections.append(fw_section)
    return unused_sections


@admin_utils.output_header
def list_unused_firewall_sections(resource, event, trigger, **kwargs):
    unused_sections = _get_unused_firewall_sections()
    _log_info(constants.FIREWALL_SECTIONS, unused_sections,
              attrs=['name', 'id'])
    return bool(unused_sections)


@admin_utils.output_header
def clean_unused_firewall_sections(resource, event, trigger, **kwargs):
    unused_sections = _get_unused_firewall_sections()
    for fw_section in unused_sections:
        LOG.info("Deleting firewall section %s", fw_section['id'])
        nsxv_firewall.delete_fw_section(fw_section['id'])
    return bool(unused_sections)


def _find_orphaned_section_rules():
    fw_sections = nsxv_firewall.list_fw_sections()
    sg_mappings = neutron_sg.get_security_groups_mappings()
    rules_mappings = neutron_sg.get_security_group_rules_mappings()
    mapped_rules_ids = [rule['nsx_rule_id'] for rule in rules_mappings]
    orphaned_rules = []

    for sg_db in sg_mappings:
        for fw_section in fw_sections:
            if fw_section['id'] == sg_db.get('section-uri', '').split('/')[-1]:
                # Neutron section.
                nsx_rules = nsxv_firewall.list_fw_section_rules(
                    sg_db.get('section-uri'))
                for nsx_rule in nsx_rules:
                    if str(nsx_rule['id']) not in mapped_rules_ids:
                        orphaned_rules.append(
                            {'nsx-rule-id': nsx_rule['id'],
                             'section-uri': sg_db['section-uri'],
                             'section-id': fw_section['id'],
                             'security-group-id': sg_db['id'],
                             'security-group-name': sg_db['name']})

    return orphaned_rules


@admin_utils.output_header
def list_orphaned_firewall_section_rules(resource, event, trigger, **kwargs):
    orphaned_rules = _find_orphaned_section_rules()
    _log_info(constants.FIREWALL_SECTIONS, orphaned_rules,
              attrs=['security-group-name', 'security-group-id', 'section-id',
                     'nsx-rule-id'])
    return bool(orphaned_rules)


@admin_utils.output_header
def clean_orphaned_firewall_section_rules(resource, event, trigger, **kwargs):
    orphaned_rules = _find_orphaned_section_rules()
    for rule in orphaned_rules:
        try:
            nsxv_firewall.remove_rule_from_section(
                rule['section-uri'], rule['nsx-rule-id'])
        except Exception as e:
            LOG.error("Failed to delete rule %s from section %s: %s",
                      rule['nsx-rule-id'], rule['section-id'], e)
        else:
            LOG.info("Backend rule %s was deleted from section %s",
                     rule['nsx-rule-id'], rule['section-id'])


@admin_utils.output_header
def reorder_firewall_sections(resource, event, trigger, **kwargs):
    nsxv_firewall.reorder_fw_sections()


@admin_utils.fix_mismatches_handler(constants.SECURITY_GROUPS)
@admin_utils.output_header
def fix_security_groups(resource, event, trigger, **kwargs):
    context_ = n_context.get_admin_context()
    sgs_with_missing_section = _find_missing_sections()
    sgs_with_missing_nsx_group = _find_missing_security_groups()
    if not sgs_with_missing_section and not sgs_with_missing_nsx_group:
        # no mismatches
        return

    with utils.NsxVPluginWrapper() as plugin:
        # If only the fw section is missing then create it.
        for sg_id in (set(sgs_with_missing_section.keys()) -
                      set(sgs_with_missing_nsx_group.keys())):
            neutron_sg.delete_security_group_section_mapping(sg_id)
            secgroup = plugin.get_security_group(context_, sg_id)
            plugin._create_fw_section_for_security_group(
                context_, secgroup,
                sgs_with_missing_section[sg_id]['nsx-securitygroup-id'])
            LOG.info("Created NSX section for security group %s", sg_id)

        # If nsx security-group is missing then create both nsx security-group
        # and a new fw section (remove old one).
        for sg_id, sg in sgs_with_missing_nsx_group.items():
            secgroup = plugin.get_security_group(context_, sg_id)
            if sg_id not in sgs_with_missing_section:
                plugin._delete_section(sg['section-uri'])
            neutron_sg.delete_security_group_section_mapping(sg_id)
            neutron_sg.delete_security_group_backend_mapping(sg_id)
            plugin._process_security_group_create_backend_resources(context_,
                                                                    secgroup)
            LOG.info("Created NSX section & security group for security group"
                     " %s", sg_id)
            nsx_id = nsx_db.get_nsx_security_group_id(context_.session, sg_id,
                                                      moref=False)
            for vnic_id in neutron_sg.get_vnics_in_security_group(sg_id):
                plugin._add_member_to_security_group(nsx_id, vnic_id)


@admin_utils.output_header
def list_policies(resource, event, trigger, **kwargs):
    """List nsx service composer policies"""
    context = n_context.get_admin_context()
    with utils.NsxVPluginWrapper() as plugin:
        policies = plugin.get_nsx_policies(context)

    policies.sort(key=operator.itemgetter('id'))
    _log_info("NSX service composer policies:", policies,
              attrs=['id', 'name', 'description'])


@admin_utils.output_header
def migrate_sg_to_policy(resource, event, trigger, **kwargs):
    """Change the mode of a security group from rules to NSX policy"""
    if not kwargs.get('property'):
        LOG.error("Need to specify security-group-id and policy-id "
                  "parameters")
        return

    # input validation
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    sg_id = properties.get('security-group-id')
    if not sg_id:
        LOG.error("Need to specify security-group-id parameter")
        return
    policy_id = properties.get('policy-id')
    if not policy_id:
        LOG.error("Need to specify policy-id parameter")
        return

    # validate that the security group exist and contains rules and no policy
    context_ = n_context.get_admin_context()
    with utils.NsxVPluginWrapper() as plugin:
        try:
            secgroup = plugin.get_security_group(context_, sg_id)
        except ext_sg.SecurityGroupNotFound:
            LOG.error("Security group %s was not found", sg_id)
            return
        if secgroup.get('policy'):
            LOG.error("Security group %s already uses a policy", sg_id)
            return

        # validate that the policy exists
        if not plugin.nsx_v.vcns.validate_inventory(policy_id):
            LOG.error("NSX policy %s was not found", policy_id)
            return

        # get the nsx id from the backend
        nsx_sg_id = nsx_db.get_nsx_security_group_id(context_.session, sg_id,
                                                     moref=True)
        if not nsx_sg_id:
            LOG.error("Did not find security groups %s neutron ID", sg_id)
            return

        # Delete the rules from the security group
        LOG.info("Deleting the rules of security group: %s", sg_id)
        for rule in secgroup.get('security_group_rules', []):
            try:
                plugin.delete_security_group_rule(context_, rule['id'])
            except Exception as e:
                LOG.warning("Failed to delete rule %(r)s from security "
                            "group %(sg)s: %(e)s",
                            {'r': rule['id'], 'sg': sg_id, 'e': e})
                # continue anyway

        # Delete the security group FW section
        LOG.info("Deleting the section of security group: %s", sg_id)
        try:
            section_uri = plugin._get_section_uri(context_.session, sg_id)
            plugin._delete_section(section_uri)
            nsxv_db.delete_neutron_nsx_section_mapping(
                context_.session, sg_id)
        except Exception as e:
            LOG.warning("Failed to delete firewall section of security "
                        "group %(sg)s: %(e)s",
                        {'sg': sg_id, 'e': e})
            # continue anyway

        # bind this security group to the policy in the backend and DB
        LOG.info("Binding the NSX security group %(nsx)s to policy "
                 "%(pol)s",
                 {'nsx': nsx_sg_id, 'pol': policy_id})
        plugin._update_nsx_security_group_policies(
            policy_id, None, nsx_sg_id)
        with context_.session.begin(subtransactions=True):
            prop = context_.session.query(
                extended_secgroup.NsxExtendedSecurityGroupProperties).\
                filter_by(security_group_id=sg_id).one()
            prop[sg_policy.POLICY] = policy_id
        LOG.info("Done.")


@admin_utils.output_header
def firewall_update_cluster_default_fw_section(resource, event, trigger,
                                               **kwargs):
    with utils.NsxVPluginWrapper() as plugin:
        plugin._create_cluster_default_fw_section(update_section=True)
        LOG.info("Cluster default FW section updated.")


@admin_utils.output_header
def update_security_groups_logging(resource, event, trigger, **kwargs):
    """Update allowed traffic logging for all neutron security group rules"""
    errmsg = ("Need to specify log-allowed-traffic property. Add --property "
              "log-allowed-traffic=true/false")
    if not kwargs.get('property'):
        LOG.error("%s", errmsg)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    log_allowed_str = properties.get('log-allowed-traffic')
    if not log_allowed_str or log_allowed_str.lower() not in ['true', 'false']:
        LOG.error("%s", errmsg)
        return
    log_allowed = log_allowed_str.lower() == 'true'

    context = n_context.get_admin_context()

    with utils.NsxVPluginWrapper() as plugin:
        vcns = plugin.nsx_v.vcns
        sg_utils = plugin.nsx_sg_utils
        # If the section/sg is already logged, then no action is
        # required.
        security_groups = plugin.get_security_groups(context)
        LOG.info("Going to update logging of %s sections",
                 len(security_groups))
        for sg in [sg for sg in plugin.get_security_groups(context)
                   if sg.get(sg_logging.LOGGING) is False]:
            if sg.get(sg_policy.POLICY):
                # Logging is not relevant with a policy
                continue

            section_uri = plugin._get_section_uri(context.session,
                                                  sg['id'])
            if section_uri is None:
                continue

            # Section/sg is not logged, update rules logging according
            # to the 'log_security_groups_allowed_traffic' config
            # option.
            try:
                h, c = vcns.get_section(section_uri)
                section = sg_utils.parse_section(c)
                section_needs_update = sg_utils.set_rules_logged_option(
                    section, log_allowed)
                if section_needs_update:
                    vcns.update_section(section_uri,
                                        sg_utils.to_xml_string(section), h)
            except Exception as exc:
                LOG.error('Unable to update security group %(sg)s '
                          'section for logging. %(e)s',
                          {'e': exc, 'sg': sg['id']})


registry.subscribe(update_security_groups_logging,
                   constants.SECURITY_GROUPS,
                   shell.Operations.UPDATE_LOGGING.value)

registry.subscribe(migrate_sg_to_policy,
                   constants.SECURITY_GROUPS,
                   shell.Operations.MIGRATE_TO_POLICY.value)

registry.subscribe(list_policies,
                   constants.SECURITY_GROUPS,
                   shell.Operations.LIST_POLICIES.value)

registry.subscribe(reorder_firewall_sections,
                   constants.FIREWALL_SECTIONS,
                   shell.Operations.NSX_REORDER.value)

registry.subscribe(fix_security_groups,
                   constants.FIREWALL_SECTIONS,
                   shell.Operations.NSX_UPDATE.value)

registry.subscribe(firewall_update_cluster_default_fw_section,
                   constants.FIREWALL_SECTIONS,
                   shell.Operations.NSX_UPDATE.value)

registry.subscribe(list_unused_firewall_sections,
                   constants.FIREWALL_SECTIONS,
                   shell.Operations.LIST_UNUSED.value)

registry.subscribe(clean_unused_firewall_sections,
                   constants.FIREWALL_SECTIONS,
                   shell.Operations.NSX_CLEAN.value)

registry.subscribe(list_orphaned_firewall_section_rules,
                   constants.ORPHANED_RULES,
                   shell.Operations.LIST.value)

registry.subscribe(clean_orphaned_firewall_section_rules,
                   constants.ORPHANED_RULES,
                   shell.Operations.NSX_CLEAN.value)
