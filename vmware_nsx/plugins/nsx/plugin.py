# Copyright 2014 VMware, Inc.
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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.db import _resource_extend as resource_extend
from neutron.db import _utils as db_utils
from neutron.db import agents_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db_api
from neutron.db.availability_zone import router as router_az_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.db.models import l3 as l3_db_models
from neutron.db.models import securitygroup as securitygroup_model  # noqa
from neutron.db import models_v2
from neutron.db import portsecurity_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db
from neutron.quota import resource_registry
from neutron_lib.api.definitions import availability_zone as az_def

from vmware_nsx.common import availability_zones as nsx_com_az
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import managers as nsx_managers
from vmware_nsx.plugins.common import plugin as nsx_plugin_common
from vmware_nsx.plugins.nsx_v import plugin as v
from vmware_nsx.plugins.nsx_v3 import plugin as t

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class NsxKunePlugin(addr_pair_db.AllowedAddressPairsMixin,
                    agents_db.AgentDbMixin,
                    nsx_plugin_common.NsxPluginBase,
                    external_net_db.External_net_db_mixin,
                    extraroute_db.ExtraRoute_db_mixin,
                    extradhcpopt_db.ExtraDhcpOptMixin,
                    router_az_db.RouterAvailabilityZoneMixin,
                    l3_gwmode_db.L3_NAT_db_mixin,
                    portsecurity_db.PortSecurityDbMixin,
                    securitygroups_db.SecurityGroupDbMixin,
                    nsx_com_az.NSXAvailabilityZonesPluginCommon):

    supported_extension_aliases = []

    __native_bulk_support = False
    __native_pagination_support = True
    __native_sorting_support = True

    @resource_registry.tracked_resources(
        network=models_v2.Network,
        port=models_v2.Port,
        subnet=models_v2.Subnet,
        subnetpool=models_v2.SubnetPool,
        security_group=securitygroup_model.SecurityGroup,
        security_group_rule=securitygroup_model.SecurityGroupRule,
        router=l3_db_models.Router,
        floatingip=l3_db_models.FloatingIP)
    def __init__(self):
        self._extension_manager = nsx_managers.ExtensionManager()
        LOG.info("Start NSX Plugin")
        # update supported extensions
        super(NsxKunePlugin, self).__init__()

        # init V init T and AZ's
        self._v = v.NsxVPluginV2()
        self._t = t.NsxV3Plugin()
        self._init_availability_zones()

        self.supported_extension_aliases = list(
            set(self._v.supported_extension_aliases).intersection(
                self._t.supported_extension_aliases))

    def _init_availability_zones(self):
        # must have default az
        if not cfg.CONF.default_availability_zones:
            error = _("Default_availability_zones must be defined")
            raise nsx_exc.NsxPluginException(err_msg=error)
        # cannot have the same zones for different plugins
        self._v_azs = self._v.get_azs_names()
        self._t_azs = self._t.get_azs_names()
        same_azs = set(self._v_azs) - set(self._t_azs)
        if same_azs:
            error = _("Cannot define the same AZ in both plugins %s") % same_azs
            raise nsx_exc.NsxPluginException(err_msg=error)
        default_az = cfg.CONF.default_availability_zones[0]

    def _get_plugin_from_az(self, obj):
        # Get the AZ from the hints of the object or use default
        if az_def.AZ_HINTS in obj:
            az_name = obj[az_def.AZ_HINTS]
        else:
            az_name = cfg.CONF.default_availability_zones[0]
        if az_name in self._v_azs:
            return self._v
        else:
            # return t also for illegal az and let the plugin take care of it
            return self._t

    def create_network(self, context, network):
        p = self._get_plugin_from_az(network)
        return p.create_network(context, network)

    def delete_network(self, context, id):
        p = self._get_plugin_from_net_id(id)
        p.delete_network(context, id)

    def get_network(self, context, id, fields=None):
        p = self._get_plugin_from_net_id(id)
        return p.get_network(context, id, fields=fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        filters = filters or {}
        with db_api.context_manager.reader.using(context):
            networks = (
                super(NsxKunePlugin, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            for net in networks:
                p = self._get_plugin_from_az(net)
                p._extend_get_network_dict_provider(context, net)
        return (networks if not fields else
                [db_utils.resource_fields(network,
                                          fields) for network in networks])

    def update_network(self, context, id, network):
        p = self._get_plugin_from_net_id(id)
        return p.update_network(context, id, network)

    def create_port(self, context, port):
        id = port['port']['network_id']
        p = self._get_plugin_from_net_id(id)
        return p.create_port(context, port)

    def update_port(self, context, id, port):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(db_port['network_id'])
        return p.update_port(context, id, port)

    def delete_port(self, context, id, l3_port_check=True,
                    nw_gw_port_check=True, force_delete_dhcp=False):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(db_port['network_id'])
        p.delete_port(context, id, l3_port_check=l3_port_check,
                      nw_gw_port_check=nw_gw_port_check,
                      force_delete_dhcp=force_delete_dhcp)

    def get_subnet(self, context, id, fields=None):
        db_subnet = self._get_subnet(context, id)
        p = self._get_plugin_from_net_id(db_subnet['network_id'])
        return p.get_subnet(context, id, fields=fields)

    def get_subnets(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        subnets = (self._v.get_subnets(context, filters=filters,
                                       fields=fields, sorts=sorts,
                                       limit=limit, marker=marker,
                                       page_reverse=page_reverse) +
                   self._t.get_subnets(context, filters=filters,
                                       fields=fields, sorts=sorts,
                                       limit=limit, marker=marker,
                                       page_reverse=page_reverse))
        return subnets

    def delete_subnet(self, context, id):
        db_subnet = self._get_subnet(context, id)
        p = self._get_plugin_from_net_id(db_subnet['network_id'])
        p.delete_subnet(context, id)

    def create_subnet(self, context, subnet):
        id = subnet['subnet']['network_id']
        p = self._get_plugin_from_net_id(id)
        return p.create_subnet(context, subnet)

    def update_subnet(self, context, id, subnet):
        db_subnet = self._get_subnet(context, id)
        p = self._get_plugin_from_net_id(db_subnet['network_id'])
        return p.update_subnet(context, id, subnet)

    def get_network_availability_zones(self, net_db):
        # TBD
        return []

#    def create_router(self, context, router, allow_metadata=True):
#
#    def update_router(self, context, router_id, router):
#
#    def delete_router(self, context, id):
#
#3    def get_router(self, context, id, fields=None):
#
#    def add_router_interface(self, context, router_id, interface_info):
##
#    def remove_router_interface(self, context, router_id, interface_info):
#
#    def create_floatingip(self, context, floatingip):
##
#    def update_floatingip(self, context, id, floatingip):
#
#    def delete_floatingip(self, context, id):
#
#    def disassociate_floatingips(self, context, port_id):
#
#    def create_security_group(self, context, security_group,
#                               default_sg=False):
#
#    def update_security_group(self, context, id, security_group):
#3
#    def delete_security_group(self, context, id):
#
#    def create_security_group_rule(self, context, security_group_rule):
#3
#    def create_security_group_rule_bulk(self, context, security_group_rules):
#
#    def delete_security_group_rule(self, context, id):
