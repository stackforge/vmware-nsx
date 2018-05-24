# Copyright 2017 VMware, Inc.
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

from neutron_lib import exceptions as n_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _
from vmware_nsx.db import db as nsx_db
from vmware_nsx.services.lbaas import base_mgr
from vmware_nsx.services.lbaas.nsx_v3.implementation import lb_utils

LOG = logging.getLogger(__name__)


class EdgeL7RuleManagerFromDict(base_mgr.Nsxv3LoadbalancerBaseManager):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeL7RuleManagerFromDict, self).__init__()

    def _update_l7rule_change(self, context, rule, obj, completor,
                              delete=False):
        rule_client = self.core_plugin.nsxlib.load_balancer.rule
        policy_id = rule['policy']['id']
        binding = nsx_db.get_nsx_lbaas_l7policy_binding(context.session,
                                                        policy_id)
        if not binding:
            if completor:
                completor.failed_completion(context, obj)
            msg = _('Cannot find nsx lbaas binding for policy '
                    '%(policy_id)s') % {'policy_id': policy_id}
            raise n_exc.BadRequest(resource='lbaas-l7policy-update', msg=msg)

        lb_rule_id = binding['lb_rule_id']
        if delete:
            lb_utils.remove_rule_from_policy(rule)
        else:
            lb_utils.update_rule_in_policy(rule)
        rule_body = lb_utils.convert_l7policy_to_lb_rule(
            context, rule['policy'])
        try:
            rule_client.update(lb_rule_id, **rule_body)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                if completor:
                    completor.failed_completion(context, obj)
                LOG.error('Failed to update L7policy %(policy)s: '
                          '%(err)s', {'policy': policy_id, 'err': e})

        if completor:
            completor.successful_completion(context, obj, delete=delete)

    def create(self, context, rule, obj=None, completor=None):
        self._update_l7rule_change(context, rule, obj, completor)

    def update(self, context, old_rule, new_rule, obj=None, completor=None):
        self._update_l7rule_change(context, new_rule, obj, completor)

    def delete(self, context, rule, obj=None, completor=None):
        self._update_l7rule_change(context, rule, obj, completor, delete=True)
