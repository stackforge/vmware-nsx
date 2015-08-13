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

from neutron.extensions import qos
from neutron.objects.qos import policy as policy_object

from vmware_nsx.neutron.plugins.vmware.common import utils
from vmware_nsx.neutron.plugins.vmware.nsxlib import v3 as nsxlib

LOG = logging.getLogger(__name__)


class NsxQosPlugin(qos.QoSPluginBase):

    """Service plugin for VMware NSX to implement Neutron's Qos API."""

    supported_extension_aliases = ["qos"]

    def __init__(self):
        super(NsxQosPlugin, self).__init__()
        LOG.info(_("Loading VMware Qos Service Plugin"))

    def create_policy(self, context, policy):
        tags = utils.build_v3_tags_payload(policy['policy'])
        result = nsxlib.create_qos_switching_profile(
                     tags=tags, name=policy['policy'].get("name"),
                     description=policy['policy'].get("description"))
        policy['policy']['id'] = result['id']
        policy = policy_object.QosPolicy(context, policy['policy'])
        policy.create()
        return policy

    def delete_policy(self, context, policy_id):
        # Delete policy from neutron first; as neutron checks if there are any
        # active network/ port bindings
        policy = policy_object.QosPolicy(context)
        policy.id = policy_id
        policy.delete()
        nsxlib.delete_qos_switching_profile(policy_id)
