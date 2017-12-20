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

from networking_l2gw.db.l2gateway import l2gateway_db
from networking_l2gw.services.l2gateway.common import constants as l2gw_const
from neutron_lib.plugins import directory

from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.services.l2gateway.nsx_v import driver as v_driver
from vmware_nsx.services.l2gateway.nsx_v3 import driver as t_driver


class NsxTvdL2GatewayDriver(l2gateway_db.L2GatewayMixin):

    """Class to handle API calls for L2 gateway and NSX-TVD plugin wrapper."""

    def __init__(self, plugin):
        super(NsxTvdL2GatewayDriver, self).__init__()
        self._plugin = plugin

        # supported drivers:
        self.drivers = {}
        self.drivers[projectpluginmap.NsxPlugins.NSX_T] = (
            t_driver.NsxV3Driver())
        self.drivers[projectpluginmap.NsxPlugins.NSX_V] = (
            v_driver.NsxvL2GatewayDriver())

    @property
    def core_plugin(self):
        return directory.get_plugin()

    def create_l2_gateway_precommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def create_l2_gateway_postcommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def create_l2_gateway(self, context, l2_gateway):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      l2_gateway.tenant_id)
        return p.create_l2_gateway(context, l2_gateway)

    def update_l2_gateway_precommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def update_l2_gateway_postcommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def create_l2_gateway_connection_precommit(self, contex, gw_connection):
        # Not implemented by any of the plugins
        pass

    def _get_gw_connection_plugin(self, context, gw_connection):
        l2gw_id = gw_connection.get(l2gw_const.L2GATEWAY_ID)
        l2gw = self._plugin._get_l2_gateway(context, l2gw_id)
        return self.core_plugin._get_plugin_from_project(context,
                                                         l2gw.tenant_id)

    def create_l2_gateway_connection_postcommit(self, context, gw_connection):
        p = self._get_gw_connection_plugin(context, gw_connection)
        return p.create_l2_gateway_connection_postcommit(
            context, gw_connection)

    def create_l2_gateway_connection(self, context, l2_gateway_connection):
        p = self._get_gw_connection_plugin(context, l2_gateway_connection)
        return p.create_l2_gateway_connection(context, l2_gateway_connection)

    def delete_l2_gateway_connection_precommit(self, context,
                                               l2_gateway_connection):
        # Not implemented by any of the plugins
        pass

    def delete_l2_gateway_connection_postcommit(self, context,
                                                l2_gateway_connection):
        p = self._get_gw_connection_plugin(context, l2_gateway_connection)
        return p.delete_l2_gateway_connection_postcommit(
            context, l2_gateway_connection)

    def delete_l2_gateway_connection(self, context, l2_gateway_connection):
        p = self._get_gw_connection_plugin(context, l2_gateway_connection)
        return p.delete_l2_gateway_connection(context, l2_gateway_connection)

    def delete_l2_gateway(self, context, l2_gateway):
        l2gw = self._plugin._get_l2_gateway(context, l2_gateway)
        p = self.core_plugin._get_plugin_from_project(context,
                                                      l2gw.tenant_id)
        return p.delete_l2_gateway(context, l2_gateway)

    def delete_l2_gateway_precommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass

    def delete_l2_gateway_postcommit(self, context, l2_gateway):
        # Not implemented by any of the plugins
        pass
