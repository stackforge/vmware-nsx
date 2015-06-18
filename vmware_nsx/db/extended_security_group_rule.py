# Copyright 2015 VMware, Inc.
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
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as nexception
from vmware_nsx.db import nsxv_models


class NotIngressRule(nexception.BadRequest):
    message = _("Specifying local_ip_prefix is supported "
                "with ingress rules only.")


class ExtendedSecurityGroupRuleMixin(object):

    def _check_local_ip_prefix(self, context, rule):
        rule_specify_local_ip_prefix = attr.is_attr_set(
            rule.get('local_ip_prefix'))
        if rule_specify_local_ip_prefix and rule['direction'] != 'ingress':
            raise NotIngressRule()
        return rule_specify_local_ip_prefix

    def _save_extended_rule_properties(self, context, rule):
        if not attr.is_attr_set(rule.get('local_ip_prefix')):
            return
        with context.session.begin(subtransactions=True):
            properties = nsxv_models.NsxvExtendedSecurityGroupRuleProperties(
                rule_id=rule['id'],
                local_ip_prefix=rule['local_ip_prefix'])
            context.session.add(properties)

    def _get_security_group_rule_properties(self, context, sgr):
        try:
            properties = (context.session.query(
                nsxv_models.NsxvExtendedSecurityGroupRuleProperties).filter_by(
                    rule_id=sgr['id']).one())
        except exc.NoResultFound:
            sgr['local_ip_prefix'] = None
        else:
            sgr['local_ip_prefix'] = properties.local_ip_prefix
        return sgr
