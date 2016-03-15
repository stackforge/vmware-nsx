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

from neutron import manager
from neutron.objects.qos import policy as qos_policy
from neutron.plugins.common import constants
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NsxVQosRule(object):

    def __init__(self, context=None, qos_policy_id=None):
        super(NsxVQosRule, self).__init__()

        # Data structure to hold the NSX-V representation
        # of the neutron qos rule.
        self._qos_plugin = None
        self.enabled = False
        self.averageBandwidth = 0
        self.peakBandwidth = 0
        self.burstSize = 0

        if qos_policy_id is not None:
            self._init_from_policy_id(context, qos_policy_id)

    def _get_qos_plugin(self):
        if not self._qos_plugin:
            loaded_plugins = manager.NeutronManager.get_service_plugins()
            self._qos_plugin = loaded_plugins[constants.QOS]
        return self._qos_plugin

    # init the nsx_v qos data (outShapingPolicy) from a neutron qos policy
    def _init_from_policy_id(self, context, qos_policy_id):
        self.enabled = False
        # read the neutron policy restrictions
        if qos_policy_id is not None:
            # read the QOS rule from DB
            plugin = self._get_qos_plugin()
            rules_obj = plugin.get_policy_bandwidth_limit_rules(
                context, qos_policy_id)
            if rules_obj is not None and len(rules_obj) > 0:
                rule_obj = rules_obj[0]
                self.enabled = True
                # averageBandwidth: kbps (neutron) -> bps (nsxv)
                self.averageBandwidth = rule_obj['max_kbps'] * 1024
                # peakBandwidth: the same as the average value because the
                # neutron qos configuration supports only 1 value
                self.peakBandwidth = self.averageBandwidth
                # burstSize: kbps (neutron) -> Bytes (nsxv)
                self.burstSize = rule_obj['max_burst_kbps'] * 128
        return self


def update_network_policy_binding(context, net_id, new_policy_id):
    # detach the old policy (if exists) from the network
    old_policy = qos_policy.QosPolicy.get_network_policy(
        context, net_id)
    if old_policy:
        old_policy.detach_network(net_id)

    # attach the new policy (if exists) to the network
    if new_policy_id is not None:
        new_policy = qos_policy.QosPolicy.get_object(
            context, id=new_policy_id)
        if new_policy:
            new_policy.attach_network(net_id)
