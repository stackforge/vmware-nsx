# Copyright 2015 VMware, Inc.
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

from oslo_log import log as logging
from oslo_utils import excutils

from neutron.services.qos import qos_plugin
import uuid
from vmware_nsx._i18n import _LE, _LI
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.nsxlib import v3 as nsxlib

LOG = logging.getLogger(__name__)


class NsxV3QosPlugin(qos_plugin.QoSPlugin):

    """Service plugin for VMware NSX-v3 to implement Neutron's Qos API."""

    supported_extension_aliases = ["qos"]

    def __init__(self):
        super(NsxV3QosPlugin, self).__init__()
        LOG.info(_LI("Loading VMware Qos Service Plugin"))

    def _get_tags(self, context, policy):
        return utils.build_v3_tags_payload(
            policy['policy'], resource_type='os-neutron-qos-id',
            project_name=context.tenant_name)

    def create_policy(self, context, policy):
        # randomize a neutron qos policy Id
        policy['policy']['id'] = str(uuid.uuid4())
        tags = self._get_tags(context, policy)
        result = nsxlib.create_qos_switching_profile(
                     tags=tags, name=policy['policy'].get("name"),
                     description=policy['policy'].get("description"))
        profile_id = result['id']

        try:
            policyDict = super(NsxV3QosPlugin, self).create_policy(
                context, policy)

            # Add the mapping entry of the policy_id <-> profile_id
            nsx_db.add_qos_policy_profile_mapping(context.session,
                                                  policy['policy']['id'],
                                                  profile_id)
            return policyDict

        except Exception:
            with excutils.save_and_reraise_exception():
                # Undo creation on the backend
                LOG.exception(_LE('Failed to create qos-policy'))
                nsxlib.delete_qos_switching_profile(profile_id)

    def delete_policy(self, context, policy_id):
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)
        # Delete policy from neutron first; as neutron checks if there are any
        # active network/ port bindings
        super(NsxV3QosPlugin, self).delete_policy(context, policy_id)
        nsxlib.delete_qos_switching_profile(profile_id)

    def update_policy(self, context, policy_id, policy):
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)
        tags = self._get_tags(context, policy)
        nsxlib.update_qos_switching_profile(
            profile_id,
            tags=tags,
            name=policy['policy'].get("name"),
            description=policy['policy'].get("description"))

        return super(NsxV3QosPlugin, self).update_policy(
            context, policy_id, policy)

    def _get_bw_values_from_rule(self, bandwidth_limit_rule):
        """Translate the neutron bandwidth_limit_rule values, into the
        values expected by the NSX-v3 QoS switch profile,
        and validate that those are legal
        """
        bw_data = bandwidth_limit_rule['bandwidth_limit_rule']

        # validate the max_kbps - it must be at least 1Mbps for the
        # switch profile configuration to succeed.
        if 'max_kbps' in bw_data and int(bw_data['max_kbps']) < 1024:
            raise nsx_exc.NsxQosSmallBw()

        # 'None' value means we will keep the old value
        burst_size = peak_bandwidth = average_bandwidth = None

        if 'max_burst_kbps' in bw_data:
            # translate kbps -> bytes
            burst_size = int(bw_data['max_burst_kbps']) * 128

        if 'max_kbps' in bw_data:
            # translate kbps -> Mbps
            peak_bandwidth = int(float(bw_data['max_kbps']) / 1024)
            # neutron QoS does not support this parameter
            average_bandwidth = peak_bandwidth

        return burst_size, peak_bandwidth, average_bandwidth

    def _update_switch_profile_shaping(self, context, policy_id,
                                       bandwidth_limit_rule):
        """Update the QoS switch profile with the BW limitations of a
        new or updated bandwidth limit rule
        """
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)

        burst_size, peak_bw, average_bw = self._get_bw_values_from_rule(
            bandwidth_limit_rule)

        nsxlib.update_qos_switching_profile_shaping(
            profile_id,
            shaping_enabled=True,
            burst_size=burst_size,
            peak_bandwidth=peak_bw,
            average_bandwidth=average_bw)

    def create_policy_bandwidth_limit_rule(self, context, policy_id,
                                           bandwidth_limit_rule):

        self._update_switch_profile_shaping(context, policy_id,
                                            bandwidth_limit_rule)

        return super(NsxV3QosPlugin, self).create_policy_bandwidth_limit_rule(
            context, policy_id, bandwidth_limit_rule)

    def update_policy_bandwidth_limit_rule(self, context, rule_id, policy_id,
                                           bandwidth_limit_rule):
        self._update_switch_profile_shaping(context, policy_id,
                                            bandwidth_limit_rule)

        return super(NsxV3QosPlugin, self).update_policy_bandwidth_limit_rule(
            context, rule_id, policy_id, bandwidth_limit_rule)

    def delete_policy_bandwidth_limit_rule(self, context, rule_id, policy_id):
        profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)
        nsxlib.update_qos_switching_profile_shaping(
            profile_id, shaping_enabled=False)

        return super(NsxV3QosPlugin, self).delete_policy_bandwidth_limit_rule(
            context, rule_id, policy_id)
