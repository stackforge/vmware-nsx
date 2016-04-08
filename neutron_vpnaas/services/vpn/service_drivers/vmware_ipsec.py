# Copyright 2016 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
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
from oslo_utils import importutils

from neutron_vpnaas.services.vpn import service_drivers


IPSEC = 'ipsec'


class VMwareIPsecVPNDriver(service_drivers.VpnDriver):

    def __init__(self, service_plugin):
        """Initialize service plugin and load backend driver."""
        self._nsx_vpn_driver = cfg.CONF.nsx_vpn_driver
        self._nsx_vpn_validator = cfg.CONF.nsx_vpn_validator
        validator = importutils.import_object(self._nsx_vpn_validator,
                                              service_plugin)

        super(VMwareIPsecVPNDriver, self).__init__(service_plugin, validator)
        self._driver = importutils.import_object(self._nsx_vpn_driver,
                                                 service_plugin)

    @property
    def service_type(self):
        return IPSEC

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        self._driver.create_ipsec_site_connection(context,
                                                  ipsec_site_connection)

    def update_ipsec_site_connection(
        self, context, old_ipsec_site_connection, ipsec_site_connection):
        self._driver.update_ipsec_site_connection(context,
                                                  old_ipsec_site_connection,
                                                  ipsec_site_connection)

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        self._driver.delete_ipsec_site_connection(context,
                                                  ipsec_site_connection)

    def ipsec_site_conn_status_update(self, context, status):
        self.service_plugin.update_status_by_agent(context, status)

    def create_vpnservice(self, context, vpnservice):
        self._driver.create_vpnservice(context, vpnservice)

    def delete_vpnservice(self, context, vpnservice):
        pass

    def update_vpnservice(self, context, old_vpn_service, new_vpn_service):
        pass
