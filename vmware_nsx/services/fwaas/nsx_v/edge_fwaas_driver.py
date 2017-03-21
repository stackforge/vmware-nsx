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

from neutron import manager
from neutron.plugins.common import constants
from neutron_lib.plugins import directory

from neutron_fwaas.extensions import firewall as fw_ext
from neutron_fwaas.services.firewall.drivers import fwaas_base

from vmware_nsx._i18n import _LE

LOG = logging.getLogger(__name__)
FWAAS_DRIVER_NAME = 'Fwaas NSX-V driver'


class EdgeFwaasDriver(fwaas_base.FwaasDriverBase):
    """NSX-V driver for Firewall As A Service - V1."""
    _fwaas_driver = None
    _core_plugin = None

    # DEBUG ADIT?
    def _get_plugin(self, plugin_type):
        loaded_plugins = manager.NeutronManager.get_service_plugins()
        return loaded_plugins[plugin_type]

    # DEBUG ADIT?
    @property
    def fw_driver(self):
        if not EdgeFwaasDriver._fwaas_driver:
            plugin = self._get_plugin(
                constants.FIREWALL)
            EdgeFwaasDriver._fwaas_driver = plugin.drivers['vmwareedge']

        return EdgeFwaasDriver._fwaas_driver

    @property
    def core_plugin(self):
        return directory.get_plugin()

    def __init__(self):
        LOG.debug("Loading FWaaS NsxVDriver.")
        super(EdgeFwaasDriver, self).__init__()

    @log_helpers.log_method_call
    def create_firewall(self, agent_mode, apply_list, firewall):
        """Create the Firewall with a given policy. """
        LOG.debug('Creating firewall %(fw_id)s for tenant %(tid)s',
                  {'fw_id': firewall['id'], 'tid': firewall['tenant_id']})
        LOG.error(_LE("DEBUG ADIT create firewall %s"), firewall)
        try:
            if firewall['admin_state_up']:  # DEBUG ADIT ???
                rule_list = firewall['firewall_rule_list']
                for rule in rule_list:
                    if not rule['enabled']:
                        continue

                    LOG.error(_LE("DEBUG ADIT adding rule %s"), rule)
                # Call plugin._update_subnets_and_dnat_firewall by router type

                #self._setup_firewall(agent_mode, apply_list, firewall)
                #self._remove_conntrack_new_firewall(agent_mode,
                #                                    apply_list, firewall)
                #self.pre_firewall = dict(firewall)
            else:
                self.apply_default_policy(agent_mode, apply_list, firewall)
        except Exception as e:
            # catch known library exceptions and raise Fwaas generic exception
            LOG.exception(_LE("Failed to create firewall: %s"), e)
            raise fw_ext.FirewallInternalDriverError(driver=FWAAS_DRIVER_NAME)

    @log_helpers.log_method_call
    def delete_firewall(self, agent_mode, apply_list, firewall):
        """Delete firewall.

        Removes all policies created by this instance and frees up
        all the resources.
        """
        pass

    @log_helpers.log_method_call
    def update_firewall(self, agent_mode, apply_list, firewall):
        """Apply the policy on all trusted interfaces.

        Remove previous policy and apply the new policy on all trusted
        interfaces.
        """
        pass

    @log_helpers.log_method_call
    def apply_default_policy(self, agent_mode, apply_list, firewall):
        """Apply the default policy on all trusted interfaces.

        Remove current policy and apply the default policy on all trusted
        interfaces.
        """
        pass
