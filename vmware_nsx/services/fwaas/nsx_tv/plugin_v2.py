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

from neutron_fwaas.services.firewall import fwaas_plugin_v2

from vmware_nsx.plugins.nsx import utils as tvd_utils


class FwaasTVPluginV2(fwaas_plugin_v2.FirewallPluginV2,
                      tvd_utils.TVDServicePluginBase):
    """NSX-TV plugin for Firewall As A Service - V2.

    This plugin adds separation between T/V instances
    """
    def __init__(self):
        super(FwaasTVPluginV2, self).__init__()

    def get_firewall_groups(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(FwaasTVPluginV2, self).get_firewall_groups,
            context, filters=filters, fields=fields)

    def get_firewall_policies(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(FwaasTVPluginV2, self).get_firewall_policies,
            context, filters=filters, fields=fields)

    def get_firewall_rules(self, context, filters=None, fields=None):
        return self._filter_entries(
            super(FwaasTVPluginV2, self).get_firewall_rules,
            context, filters=filters, fields=fields)
