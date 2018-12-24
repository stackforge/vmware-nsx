# Copyright 2018 VMware, Inc.
#
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

from oslo_config import cfg
from oslo_log import log as logging

from neutron_lib import constants as n_consts
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts

from vmware_nsx._i18n import _
from vmware_nsx.common import utils
from vmware_nsxlib.v3 import policy_defs

LOG = logging.getLogger(__name__)

MAX_KBPS_MIN_VALUE = 1024
# The max limit is calculated so that the value sent to the backed will
# be smaller than 2**31
MAX_BURST_MAX_VALUE = int((2 ** 31 - 1) / 128)


class PolicyQosNotificationsHandler(object):

    def __init__(self):
        super(PolicyQosNotificationsHandler, self).__init__()
        self._core_plugin = None

    @property
    def core_plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    @property
    def _nsxlib_qos(self):
        return self.core_plugin.nsxpolicy.qos_profile

    @property
    def _nsxpolicy(self):
        return self.core_plugin.nsxpolicy

    def create_or_update_policy(self, context, policy):
        policy_id = policy.id
        tags = self.nsxpolicy.build_v3_api_version_project_tag(
            context.tenant_name)
        pol_name = utils.get_name_and_uuid(policy.name or 'policy',
                                           policy.id)

        shapers = []
        dscp = None
        if (hasattr(policy, "rules")):
            for rule in policy["rules"]:
                if rule.rule_type == qos_consts.RULE_TYPE_BANDWIDTH_LIMIT:
                    if rule.direction == n_consts.EGRESS_DIRECTION:
                        # the NSX direction is opposite to the neutron one
                        shapers.append(self._get_shaper_from_rule(
                            rule, is_ingress=True))
                    else:
                        # the NSX direction is opposite to the neutron one
                        shapers.append(self._get_shaper_from_rule(
                            rule, is_ingress=False))
                elif rule.rule_type == qos_consts.RULE_TYPE_DSCP_MARKING:
                    dscp = self._get_dscp_from_rule(rule)
                else:
                    LOG.warning("The NSX-Policy plugin does not support QoS "
                                "rule of type %s", rule.rule_type)

        self._nsxlib_qos.create(pol_name, profile_id=policy_id,
                                dscp=dscp, shaper_configurations=shapers,
                                tags=tags)

    def create_policy(self, context, policy):
        return self.create_or_update_policy(context, policy)

    def delete_policy(self, context, policy_id):
        self._nsxlib_qos.delete(policy_id)

    def update_policy(self, context, policy_id, policy):
        return self.create_or_update_policy(context, policy)

    def _validate_bw_values(self, bw_rule):
        """Validate that the configured values are allowed by the NSX backend.

        Since failing the action from the notification callback
        is not possible, just log the warning and use the minimal/maximal
        values.
        """
        # Validate the max bandwidth value minimum value
        # (max value is above what neutron allows so no need to check it)
        if (bw_rule.max_kbps < MAX_KBPS_MIN_VALUE):
            msg = (_("Invalid input for max_kbps. "
                     "The minimal legal value is %s") % MAX_KBPS_MIN_VALUE)
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)

        # validate the burst size value max value
        # (max value is 0, and neutron already validates this)
        if (bw_rule.max_burst_kbps > MAX_BURST_MAX_VALUE):
            msg = (_("Invalid input for burst_size. "
                     "The maximal legal value is %s") % MAX_BURST_MAX_VALUE)
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)

    def _get_shaper_from_rule(self, bw_rule, is_ingress):
        """Translate the neutron bandwidth_limit_rule values into the
        NSX-lib Policy QoS shaper
        """
        if is_ingress:
            shaper = policy_defs.QoSIngressRateLimiter
            avg_field_name = 'average_bandwidth_kbps'
            peak_field_name = 'peak_bandwidth_kbps'
        else:
            shaper = policy_defs.QoSEgressRateLimiter
            avg_field_name = 'average_bandwidth_mbps'
            peak_field_name = 'peak_bandwidth_mbps'

        kwargs = {}
        if bw_rule:
            kwargs['enabled'] = True

            # translate kbps -> bytes
            kwargs['burst_size_bytes'] = int(bw_rule.max_burst_kbps) * 128

            if is_ingress:
                kwargs[avg_field_name] = int(bw_rule.max_kbps)
            else:
                # translate kbps -> Mbps
                kwargs[avg_field_name] = int(round(
                    float(bw_rule.max_kbps) / 1024))

            # peakBandwidth: a Multiplying on the average BW
            # because the neutron qos configuration supports
            # only 1 value
            kwargs[peak_field_name] = int(round(kwargs[avg_field_name] *
                                          cfg.CONF.NSX.qos_peak_bw_multiplier))
        else:
            kwargs['enabled'] = False

        return shaper(kwargs)

    def _get_dscp_from_rule(self, dscp_rule):
        """Translate the neutron DSCP marking rule values into NSX-lib
        Policy QoS Dscp object
        """
        if dscp_rule:
            mode = policy_defs.QoSDscp.QOS_DSCP_UNTRUSTED
            priority = dscp_rule.dscp_mark
        else:
            mode = policy_defs.QoSDscp.QOS_DSCP_TRUSTED
            mode = 0

        return policy_defs.QoSDscp(mode=mode, priority=priority)

    def update_policy_rules(self, context, policy_id, rules):
        """This handler will do all the updates through the create_or_update"""
        pass

    def validate_policy_rule(self, context, policy_id, rule):
        """Raise an exception if the rule values are not supported"""
        if rule.rule_type == qos_consts.RULE_TYPE_BANDWIDTH_LIMIT:
            self._validate_bw_values(rule)
        elif rule.rule_type == qos_consts.RULE_TYPE_DSCP_MARKING:
            pass
        else:
            msg = (_("The NSX-Policy plugin does not support QoS rule of type "
                     "%s") % rule.rule_type)
            LOG.error(msg)
            raise n_exc.InvalidInput(error_message=msg)
