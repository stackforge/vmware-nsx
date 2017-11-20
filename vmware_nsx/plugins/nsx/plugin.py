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

import sys

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

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
from neutron_lib.exceptions import availability_zone as az_exc

from vmware_nsx.common import availability_zones as nsx_com_az
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import managers as nsx_managers
from vmware_nsx.db import nsx_portbindings_db as pbin_db
from vmware_nsx.plugins.common import plugin as nsx_plugin_common
from vmware_nsx.plugins.nsx_v import plugin as v
from vmware_nsx.plugins.nsx_v3 import plugin as t

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class NsxTVPlugin(addr_pair_db.AllowedAddressPairsMixin,
                  agents_db.AgentDbMixin,
                  nsx_plugin_common.NsxPluginBase,
                  external_net_db.External_net_db_mixin,
                  extraroute_db.ExtraRoute_db_mixin,
                  extradhcpopt_db.ExtraDhcpOptMixin,
                  router_az_db.RouterAvailabilityZoneMixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  pbin_db.NsxPortBindingMixin,
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
        super(NsxTVPlugin, self).__init__()

        # init V init T and AZ's
        self._v = v.NsxVPluginV2()
        self._t = t.NsxV3Plugin()
        self.init_availability_zones()

        # init the extensions supported by both plugins
        self.supported_extension_aliases = list(
            set(self._v.supported_extension_aliases).intersection(
                self._t.supported_extension_aliases))

    def init_availability_zones(self):
        # This plugin must have a default az
        if not cfg.CONF.default_availability_zones:
            error = _("Default_availability_zones must be defined")
            raise nsx_exc.NsxPluginException(err_msg=error)
        # cannot have the same zone name in both V&T plugins
        self._v_azs = self._v.get_azs_names()
        self._t_azs = self._t.get_azs_names()
        same_azs = set(self._v_azs) & set(self._t_azs)
        if same_azs:
            error = (_("Cannot define the same AZ in both plugins %s") %
                     same_azs)
            raise nsx_exc.NsxPluginException(err_msg=error)
        # check that the default az exists
        default_az = cfg.CONF.default_availability_zones[0]
        self.all_azs = set(self._v_azs) | set(self._t_azs)
        if default_az not in self.all_azs:
            error = _("The default AZ is not defined in the NSX "
                      "plugin")
            raise nsx_exc.NsxPluginException(err_msg=error)

    def _list_availability_zones(self, context, filters=None):
        result = {}
        for az in set(self._v_azs) | set(self._t_azs):
            # Add this availability zone as a router & network resource
            for resource in ('router', 'network'):
                result[(az, resource)] = True
        return result

    def validate_availability_zones(self, context, resource_type,
                                    availability_zones):
        """Verify that the availability zones exist when creating an object"""
        diff = (set(availability_zones) - set(self.all_azs))
        if diff:
            raise az_exc.AvailabilityZoneNotFound(
                availability_zone=diff.pop())

    def _get_plugin_from_az(self, data, action=None):
        if not action:
            # caller method name
            action = sys._getframe(1).f_code.co_name
        # Get the AZ from the hints of the object or use default
        if data.get(az_def.AZ_HINTS, []):
            az_name = data[az_def.AZ_HINTS][0]
        else:
            az_name = cfg.CONF.default_availability_zones[0]
        # Find if this is a T or V AZ
        if az_name in self._v_azs:
            LOG.info("Using NSX-V plugin to %(action)s with az %(az)s",
                     {'action': action, 'az': az_name})
            return self._v
        else:
            # return T also for illegal az and let the plugin take care of it
            LOG.info("Using NSX-V3 plugin to %(action)s with az %(az)s",
                     {'action': action, 'az': az_name})
            return self._t

    def _get_plugin_from_net_id(self, context, net_id):
        # get the network using the super plugin
        network = super(NsxTVPlugin, self).get_network(context, net_id)
        # caller method name
        action = sys._getframe(1).f_code.co_name
        return self._get_plugin_from_az(network, action=action)

    def create_network(self, context, network):
        p = self._get_plugin_from_az(network['network'])
        return p.create_network(context, network)

    def delete_network(self, context, id):
        p = self._get_plugin_from_net_id(context, id)
        p.delete_network(context, id)

    def get_network(self, context, id, fields=None):
        p = self._get_plugin_from_net_id(context, id)
        return p.get_network(context, id, fields=fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        filters = filters or {}
        with db_api.context_manager.reader.using(context):
            networks = (
                super(NsxTVPlugin, self).get_networks(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            for net in networks:
                p = self._get_plugin_from_az(net)
                p._extend_get_network_dict_provider(context, net)
        return (networks if not fields else
                [db_utils.resource_fields(network,
                                          fields) for network in networks])

    def update_network(self, context, id, network):
        p = self._get_plugin_from_net_id(context, id)
        return p.update_network(context, id, network)

    def create_port(self, context, port):
        id = port['port']['network_id']
        p = self._get_plugin_from_net_id(context, id)
        return p.create_port(context, port)

    def update_port(self, context, id, port):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        return p.update_port(context, id, port)

    def delete_port(self, context, id, l3_port_check=True,
                    nw_gw_port_check=True, force_delete_dhcp=False):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        p.delete_port(context, id, l3_port_check=l3_port_check,
                      nw_gw_port_check=nw_gw_port_check,
                      force_delete_dhcp=force_delete_dhcp)

    def get_subnet(self, context, id, fields=None):
        db_subnet = self._get_subnet(context, id)
        p = self._get_plugin_from_net_id(context, db_subnet['network_id'])
        return p.get_subnet(context, id, fields=fields)

    def get_subnets(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        # The subnets is tricky as the metadata requests make use of the
        # get subnet. So there are two use cases here:
        # 1. that the metadata request returns a value
        # 2. that this is a gemeral subnet query.
        # First we check T if subnets are returned here then we can return,
        # if [] tjem it could be a V metadata request
        subnets = self._t.get_subnets(context, filters=filters,
                                      fields=fields, sorts=sorts,
                                      limit=limit, marker=marker,
                                      page_reverse=page_reverse)
        if subnets:
            return subnets
        return self._v.get_subnets(context, filters=filters,
                                   fields=fields, sorts=sorts,
                                   limit=limit, marker=marker,
                                   page_reverse=page_reverse)

    def delete_subnet(self, context, id):
        db_subnet = self._get_subnet(context, id)
        p = self._get_plugin_from_net_id(context, db_subnet['network_id'])
        p.delete_subnet(context, id)

    def create_subnet(self, context, subnet):
        id = subnet['subnet']['network_id']
        p = self._get_plugin_from_net_id(context, id)
        return p.create_subnet(context, subnet)

    def update_subnet(self, context, id, subnet):
        db_subnet = self._get_subnet(context, id)
        p = self._get_plugin_from_net_id(context, db_subnet['network_id'])
        return p.update_subnet(context, id, subnet)

    def get_network_availability_zones(self, net_db):
        # TBD - FIX
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

    def create_security_group(self, context, security_group,
                              default_sg=False):
        # First create with T
        sg = self._t.create_security_group(context, security_group,
                                           default_sg=default_sg)
        # Create on backend for V
        try:
            self._v._process_security_group_create_backend_resources(
                context, sg)
        except Exception:
            with excutils.save_and_reraise_exception():
                if default_sg:
                    context = context.elevated()
                super(NsxTVPlugin, self).delete_security_group(context,
                                                               sg['id'])
        return sg

    def delete_security_group(self, context, id):
        self._v.delete_security_group(context, id, delete_base=False)
        self._t.delete_security_group(context, id)

    def update_security_group(self, context, id, security_group):
        self._t.update_security_group(context, id, security_group)
        return self._v.update_security_group(context, id, security_group)

#    def delete_security_group(self, context, id):
#
#    def create_security_group_rule(self, context, security_group_rule):
#3
#    def create_security_group_rule_bulk(self, context, security_group_rules):
#
#    def delete_security_group_rule(self, context, id):
