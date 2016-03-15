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

from neutron.db.qos import api as qos_api
from neutron.services.qos import qos_plugin
from oslo_config import cfg
from oslo_log import log as logging
from vmware_nsx._i18n import _LI
from vmware_nsx.db import db as nsx_db
from vmware_nsx.dvs import dvs
from vmware_nsx.services.qos.nsx_v import utils as qos_utils

LOG = logging.getLogger(__name__)


class NsxVQosPlugin(qos_plugin.QoSPlugin):

    """Service plugin for VMware NSX-v to implement Neutron's Qos API."""

    supported_extension_aliases = ["qos"]

    def __init__(self):
        super(NsxVQosPlugin, self).__init__()
        LOG.info(_LI("Loading VMware Qos Service Plugin"))
        if cfg.CONF.nsxv.use_dvs_features:
            self._dvs = dvs.DvsManager()
        else:
            self._dvs = None

    # Update all attached networks when the content of the qos rule changes
    def _update_networks_qos_policy(self, context, policy_id):
        # Find all the networks using this policy
        networks = qos_api.get_network_ids_by_policy_network_binding(
            context, policy_id)
        qos_rule = qos_utils.NsxVQosRule(context=context,
                                         qos_policy_id=policy_id)

        for net_id in networks:
            # update the new bw limitations for this network
            net_morefs = nsx_db.get_nsx_switch_ids(context.session, net_id)
            for moref in net_morefs:
                # update the qos restrictions of the network
                self._dvs.update_port_groups_config(
                    net_id,
                    moref,
                    self._dvs.update_port_group_spec_qos,
                    qos_rule)

    def create_policy_bandwidth_limit_rule(self, context, policy_id,
                                           bandwidth_limit_rule):
        rule = super(NsxVQosPlugin, self).create_policy_bandwidth_limit_rule(
            context, policy_id, bandwidth_limit_rule)
        self._update_networks_qos_policy(context, policy_id)
        return rule

    def update_policy_bandwidth_limit_rule(self, context, rule_id, policy_id,
                                           bandwidth_limit_rule):
        rule = super(NsxVQosPlugin, self).update_policy_bandwidth_limit_rule(
            context, rule_id, policy_id, bandwidth_limit_rule)
        self._update_networks_qos_policy(context, policy_id)
        return rule

    def delete_policy_bandwidth_limit_rule(self, context, rule_id, policy_id):
        super(NsxVQosPlugin, self).delete_policy_bandwidth_limit_rule(
            context, rule_id, policy_id)
        self._update_networks_qos_policy(context, policy_id)
