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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_fwaas.services.firewall.agents.l3reference \
    import firewall_l3_agent

from vmware_nsx._i18n import _LE

LOG = logging.getLogger(__name__)


class NsxvFwaasCallbacks(firewall_l3_agent.L3WithFWaaS):
    """NSX-V RPC callbacks for Firewall As A Service - V1."""
    def __init__(self):
        LOG.debug("Loading FWaaS NsxVCallbacks.")
        super(NsxvFwaasCallbacks, self).__init__()

    @log_helpers.log_method_call
    def create_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to create a firewall."""
        LOG.error(_LE("DEBUG ADIT NsxvFwaasCallbacks create_firewall"))
        return super(NsxvFwaasCallbacks, self).create_firewall(
            context, firewall, host)
