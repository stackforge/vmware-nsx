# Copyright 2016 VMware, Inc.
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

from neutron.api.rpc.callbacks import events as callbacks_events
from neutron.api.v2 import attributes
from neutron import context as n_context
from neutron.objects.qos import policy as qos_policy
from oslo_log import log as logging

from vmware_nsx._i18n import _, _LW
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.nsxlib import v3 as nsxlib

LOG = logging.getLogger(__name__)
MAX_KBPS_MIN_VALUE = 1024


def get_port_policy_id(context, port_id):
    policy = qos_policy.QosPolicy.get_port_policy(
        context, port_id)
    if policy:
        return policy.id


def get_network_policy_id(context, net_id):
    policy = qos_policy.QosPolicy.get_network_policy(
        context, net_id)
    if policy:
        return policy.id


def handle_qos_notification(policy_obj, event_type):
    handler = QosNotificationsHandler()
    context = n_context.get_admin_context()

    # Reload the policy as admin so we will have a context
    if (event_type != callbacks_events.DELETED):
        policy = qos_policy.QosPolicy.get_object(context, id=policy_obj.id)

    # Check if QoS policy rule was created/deleted/updated
    if (event_type == callbacks_events.CREATED):
        handler.create_policy(context, policy)

    elif (event_type == callbacks_events.UPDATED):
        if (hasattr(policy_obj, "rules")):
            # With rules - the policy rule was created / deleted / updated
            rules = policy_obj["rules"]
            if not len(rules):
                # the rule was deleted
                handler.delete_policy_bandwidth_limit_rule(
                    context, policy_obj.id)
            else:
                # New or updated rule
                handler.create_or_update_policy_bandwidth_limit_rule(
                    context, policy_obj.id, rules[0])
        else:
            # Without rules - need to update only name / description
            handler.update_policy(context, policy_obj.id, policy)

    elif (event_type == callbacks_events.DELETED):
        handler.delete_policy(context, policy_obj.id)

    else:
        msg = _("Unknown QoS notification event %s") % event_type
        raise nsx_exc.NsxPluginException(err_msg=msg)


class QosNotificationsHandler(object):

    def __init__(self):
        super(QosNotificationsHandler, self).__init__()

    def _get_tags(self, context, policy):
        policy_dict = {'id': policy.id, 'tenant_id': policy.tenant_id}
        return utils.build_v3_tags_payload(
            policy_dict, resource_type='os-neutron-qos-id',
            project_name=context.tenant_name)

    def create_policy(self, context, policy):
        policy_id = policy.id
        tags = self._get_tags(context, policy)
        result = nsxlib.create_qos_switching_profile(
            tags=tags, name=policy.name,
            description=policy.description)
        if not result or not attributes.is_attr_set(result.get('id')):
            msg = _("Unable to create QoS switching profile on the backend")
            raise nsx_exc.NsxPluginException(err_msg=msg)
        profile_id = result['id']

        # Add the mapping entry of the policy_id <-> profile_id
        nsx_db.add_qos_policy_profile_mapping(context.session,
                                              policy_id,
                                              profile_id)

    def delete_policy(self, context, policy_id):
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)
        nsxlib.delete_qos_switching_profile(profile_id)

    def update_policy(self, context, policy_id, policy):
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)
        tags = self._get_tags(context, policy)
        nsxlib.update_qos_switching_profile(
            profile_id,
            tags=tags,
            name=policy.name,
            description=policy.description)

    def _get_bw_values_from_rule(self, bw_rule):
        """Translate the neutron bandwidth_limit_rule values, into the
        values expected by the NSX-v3 QoS switch profile,
        and validate that those are legal
        """
        # validate the max_kbps - it must be at least 1Mbps for the
        # switch profile configuration to succeed.
        if (bw_rule.max_kbps < MAX_KBPS_MIN_VALUE):
            # Since failing the action from the notification callback is not
            # possible, just log the warning and use the minimal value
            LOG.warning(_LW("Invalid input for max_kbps. "
                            "The minimal legal value is 1024"))
            bw_rule.max_kbps = MAX_KBPS_MIN_VALUE

        # 'None' value means we will keep the old value
        burst_size = peak_bandwidth = average_bandwidth = None

        # translate kbps -> bytes
        burst_size = int(bw_rule.max_burst_kbps) * 128

        # translate kbps -> Mbps
        peak_bandwidth = int(float(bw_rule.max_kbps) / 1024)
        # neutron QoS does not support this parameter
        average_bandwidth = peak_bandwidth

        return burst_size, peak_bandwidth, average_bandwidth

    def create_or_update_policy_bandwidth_limit_rule(self, context, policy_id,
                                                     bw_rule):
        """Update the QoS switch profile with the BW limitations of a
        new or updated bandwidth limit rule
        """
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)

        burst_size, peak_bw, average_bw = self._get_bw_values_from_rule(
            bw_rule)

        nsxlib.update_qos_switching_profile_shaping(
            profile_id,
            shaping_enabled=True,
            burst_size=burst_size,
            peak_bandwidth=peak_bw,
            average_bandwidth=average_bw)

    def delete_policy_bandwidth_limit_rule(self, context, policy_id):
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)
        nsxlib.update_qos_switching_profile_shaping(
            profile_id, shaping_enabled=False)
