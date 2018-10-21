# Copyright 2018 VMware, Inc.
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

from neutron_lib import constants as nl_constants

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.fwaas.common import fwaas_callbacks_v2 as \
    com_callbacks
from vmware_nsx.services.fwaas.nsx_tv import edge_fwaas_driver_v2 as tv_driver

LOG = logging.getLogger(__name__)


class NsxvFwaasCallbacksV2(com_callbacks.NsxFwaasCallbacksV2):
    """NSX-V RPC callbacks for Firewall As A Service - V2."""

    def __init__(self):
        super(NsxvFwaasCallbacksV2, self).__init__()
        # update the fwaas driver in case of TV plugin
        self.internal_driver = None
        if self.fwaas_enabled:
            if self.fwaas_driver.driver_name == tv_driver.FWAAS_DRIVER_NAME:
                self.internal_driver = self.fwaas_driver.get_V_driver()
            else:
                self.internal_driver = self.fwaas_driver

    @property
    def plugin_type(self):
        return projectpluginmap.NsxPlugins.NSX_V

    def should_apply_firewall_to_router(self, context, router_id):
        """Return True if the FWaaS rules should be added to this router."""
        if not super(NsxvFwaasCallbacksV2,
                     self).should_apply_firewall_to_router(context,
                                                           router_id):
            return False

        # get all the relevant router info
        ctx_elevated = context.elevated()
        router_data = self.core_plugin.get_router(ctx_elevated, router_id)
        if not router_data:
            LOG.error("Couldn't read router %s data", router_id)
            return False

        # Check if the FWaaS driver supports this router
        if not self.internal_driver.should_apply_firewall_to_router(
            router_data):
            return False

        return True

    def get_port_rules(self, nsx_ls_id, fwg, plugin_rules):
        return self.internal_driver.get_port_translated_rules(
            nsx_ls_id, fwg, plugin_rules)

    def update_router_firewall(self, context, nsxlib, router_id,
                               router_interfaces, nsx_router_id, section_id):
        """Rewrite all the FWaaS v2 rules in the router edge firewall

        This method should be called on FWaaS updates, and on router
        interfaces changes.
        """
        # DEBUG ADIT
        pass

    def delete_port(self, context, port_id):
        # DEBUG ADIT - this code should be shared
        # Mark the FW group as inactive if this is the last port
        fwg = self.get_port_fwg(context, port_id)
        if (fwg and fwg.get('status') == nl_constants.ACTIVE and
            len(fwg.get('ports', [])) <= 1):
            self.fwplugin_rpc.set_firewall_group_status(
                context, fwg['id'], nl_constants.INACTIVE)
