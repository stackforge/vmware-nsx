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

from neutron_lib.api import validators
from neutron_lib import constants as n_consts
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts

from vmware_nsx._i18n import _
from vmware_nsx.common import exceptions as nsx_exc

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

    def create_policy(self, context, policy):
        policy_id = policy.id
        tags = self.nsxpolicy.build_v3_api_version_project_tag(
            context.tenant_name,
            #project_id=policy.tenant_id  # TODO(asarfaty) wait for nsxlib fix
            )

        self._nsxlib_qos.create(profile_id=policy_id, tags=tags)

    def delete_policy(self, context, policy_id):
        self._nsxlib_qos.delete(policy_id)

    def update_policy(self, context, policy_id, policy):
        # tags = self._get_tags(context, policy)
        # self._nsxlib_qos.update(
        #     profile_id,
        #     tags=tags,
        #     name=policy.name,
        #     description=policy.description)
        pass

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

    def _get_bw_values_from_rule(self, bw_rule):
        """Translate the neutron bandwidth_limit_rule values, into the
        values expected by the NSX-Policy QoS switch profile,
        and validate that those are legal
        """
        if bw_rule:
            shaping_enabled = True

            # translate kbps -> bytes
            burst_size = int(bw_rule.max_burst_kbps) * 128

            # translate kbps -> Mbps
            average_bandwidth = int(round(float(bw_rule.max_kbps) / 1024))

            # peakBandwidth: a Multiplying on the average BW
            # because the neutron qos configuration supports
            # only 1 value
            peak_bandwidth = int(round(average_bandwidth *
                                       cfg.CONF.NSX.qos_peak_bw_multiplier))
        else:
            shaping_enabled = False
            burst_size = None
            peak_bandwidth = None
            average_bandwidth = None

        return shaping_enabled, burst_size, peak_bandwidth, average_bandwidth

    def _get_dscp_values_from_rule(self, dscp_rule):
        """Translate the neutron DSCP marking rule values, into the
        values expected by the NSX-Policy QoS switch profile
        """
        if dscp_rule:
            qos_marking = 'untrusted'
            dscp = dscp_rule.dscp_mark
        else:
            qos_marking = 'trusted'
            dscp = 0

        return qos_marking, dscp

    def update_policy_rules(self, context, policy_id, rules):
        """Update the QoS switch profile with the BW limitations and
        DSCP marking configuration
        """
        # profile_id = nsx_db.get_switch_profile_by_qos_policy(
        #     context.session, policy_id)

        # ingress_bw_rule = None
        # egress_bw_rule = None
        # dscp_rule = None
        # for rule in rules:
        #     if rule.rule_type == qos_consts.RULE_TYPE_BANDWIDTH_LIMIT:
        #         if rule.direction == n_consts.EGRESS_DIRECTION:
        #             egress_bw_rule = rule
        #         else:
        #             ingress_bw_rule = rule
        #     elif rule.rule_type == qos_consts.RULE_TYPE_DSCP_MARKING:
        #         dscp_rule = rule
        #     else:
        #         LOG.warning("The NSX-Policy plugin does not support QoS rule of "
        #                     "type %s", rule.rule_type)

        # # the NSX direction is opposite to the neutron direction
        # (ingress_bw_enabled, ingress_burst_size, ingress_peak_bw,
        #     ingress_average_bw) = self._get_bw_values_from_rule(egress_bw_rule)

        # (egress_bw_enabled, egress_burst_size, egress_peak_bw,
        #     egress_average_bw) = self._get_bw_values_from_rule(ingress_bw_rule)

        # qos_marking, dscp = self._get_dscp_values_from_rule(dscp_rule)

        # self._nsxlib_qos.set_profile_shaping(
        #     profile_id,
        #     ingress_bw_enabled=ingress_bw_enabled,
        #     ingress_burst_size=ingress_burst_size,
        #     ingress_peak_bandwidth=ingress_peak_bw,
        #     ingress_average_bandwidth=ingress_average_bw,
        #     egress_bw_enabled=egress_bw_enabled,
        #     egress_burst_size=egress_burst_size,
        #     egress_peak_bandwidth=egress_peak_bw,
        #     egress_average_bandwidth=egress_average_bw,
        #     qos_marking=qos_marking, dscp=dscp)

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
