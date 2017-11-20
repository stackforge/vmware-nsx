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
from oslo_utils import uuidutils

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
from neutron_lib.api import validators
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import availability_zone as az_exc

from vmware_nsx.common import availability_zones as nsx_com_az
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import managers as nsx_managers
from vmware_nsx.db import (
    routertype as rt_rtr)
from vmware_nsx.db import nsx_portbindings_db as pbin_db
from vmware_nsx.plugins.common import plugin as nsx_plugin_common
from vmware_nsx.plugins.nsx_v import plugin as v
from vmware_nsx.plugins.nsx_v3 import plugin as t

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class NsxTVPlugin(addr_pair_db.AllowedAddressPairsMixin,
                  agents_db.AgentDbMixin,
                  nsx_plugin_common.NsxPluginBase,
                  rt_rtr.RouterType_mixin,
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
        # TODO(asarfaty) we may want to add some extensions that are supported
        # by only one of the plugins such as router-type
        self.supported_extension_aliases = list(
            set(self._v.supported_extension_aliases).intersection(
                self._t.supported_extension_aliases))

        # Add some plugin specific extensions
        self.supported_extension_aliases.append('nsxv-router-type')
        self.supported_extension_aliases.append('nsxv-router-size')

        # mark extensions which are supported by only one of the plugins
        self._unsupported_fields = {self._t.plugin_type: {},
                                    self._v.plugin_type: {}}
        self._unsupported_fields[self._t.plugin_type]['router'] = [
            'router_size', 'router_type']
        self._unsupported_fields[self._v.plugin_type]['router'] = []

    @property
    def plugin_type(self):
        return "Nsx-TV"

    def _validate_obj_extensions(self, data, plugin_type, obj_type):
        for field in self._unsupported_fields[plugin_type][obj_type]:
            if validators.is_attr_set(data.get(field)):
                err_msg = (_('Can not support %(field)s extension for '
                             '%(obj_type)s %(p)s plugin') % {
                           'field': field,
                           'obj_type': obj_type,
                           'p': plugin_type})
                raise n_exc.InvalidInput(error_message=err_msg)

    def _cleanup_obj_fields(self, data, plugin_type, obj_type):
        for field in self._unsupported_fields[plugin_type][obj_type]:
            if field in data:
                del data[field]

    def init_availability_zones(self):
        # This plugin must have a default az
        if not cfg.CONF.default_availability_zones:
            error = _("NSX-TV plugin error: default_availability_zones must "
                      "be defined in the neutron config file")
            raise nsx_exc.NsxPluginException(err_msg=error)
        # cannot have the same zone name in both V&T plugins
        self._v_azs = self._v.get_azs_names()
        self._t_azs = self._t.get_azs_names()
        same_azs = set(self._v_azs) & set(self._t_azs)
        if same_azs:
            error = (_("NSX-TV plugin error: Cannot define the same AZ in "
                       "both plugins: %s") %
                     same_azs)
            raise nsx_exc.NsxPluginException(err_msg=error)
        # check that the default az exists
        default_az = cfg.CONF.default_availability_zones[0]
        self.all_azs = set(self._v_azs) | set(self._t_azs)
        if default_az not in self.all_azs:
            error = (_("NSX-TV plugin error: The default AZ %s should be "
                       "defined in one of the NSX plugins configuration") %
                     default_az)
            raise nsx_exc.NsxPluginException(err_msg=error)

    def _list_availability_zones(self, context, filters=None):
        result = {}
        for az in self.all_azs:
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

    def _get_availability_zones_from_obj_data(self, data, use_default=True):
        # Get the AZ from the hints of the object or use default
        az_name = None
        if data.get(az_def.AZ_HINTS, []):
            az_name = data[az_def.AZ_HINTS][0]
        elif use_default:
            az_name = cfg.CONF.default_availability_zones[0]
        return az_name

    def _get_plugin_from_az(self, data, action=None):
        if not action:
            # caller method name
            action = sys._getframe(1).f_code.co_name
        # Get the AZ from the hints of the object or use default
        az_name = self._get_availability_zones_from_obj_data(data)
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

    def get_network_availability_zones(self, net_db):
        az_name = self._get_availability_zones_from_obj_data(
            net_db, use_default=False)
        if az_name:
            return [az_name]
        else:
            return []

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

    def delete_port(self, context, id, **kwargs):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        p.delete_port(context, id, **kwargs)

    def get_port(self, context, id, fields=None):
        db_port = self._get_port(context, id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        return p.get_port(context, id, fields=fields)

    def get_subnet(self, context, id, fields=None):
        db_subnet = self._get_subnet(context, id)
        p = self._get_plugin_from_net_id(context, db_subnet['network_id'])
        return p.get_subnet(context, id, fields=fields)

    def get_subnets(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        # The subnets is tricky as the metadata requests make use of the
        # get subnet. So there are two use cases here:
        # 1. that the metadata request returns a value
        # 2. that this is a general subnet query.
        # First we check T if subnets are returned here then we can return,
        # if [] returned it could be a V metadata request
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

    def get_router_availability_zones(self, router):
        az_name = self._get_availability_zones_from_obj_data(
            router, use_default=False)
        if az_name:
            return [az_name]
        else:
            return []

    def _validate_router_gw_plugin(self, context, router_plugin,
                                   gw_info):
        if gw_info and gw_info.get('network_id'):
            net_plugin = self._get_plugin_from_net_id(
                context, gw_info['network_id'])
            if net_plugin.plugin_type != router_plugin.plugin_type:
                err_msg = (_('Router gateway should belong to the %s plugin '
                             'as the router') % router_plugin.plugin_type)
                raise n_exc.InvalidInput(error_message=err_msg)

    def _validate_router_interface_plugin(self, context, router_plugin,
                                          interface_info):
        is_port, is_sub = self._validate_interface_info(interface_info)
        if is_port:
            net_id = self.get_port(
                context, interface_info['port_id'])['network_id']
        elif is_sub:
            net_id = self.get_subnet(
                context, interface_info['subnet_id'])['network_id']
        net_plugin = self._get_plugin_from_net_id(context, net_id)
        if net_plugin.plugin_type != router_plugin.plugin_type:
            err_msg = (_('Router interface should belong to the %s plugin '
                         'as the router') % router_plugin.plugin_type)
            raise n_exc.InvalidInput(error_message=err_msg)

    def _get_plugin_from_router_id(self, context, router_id):
        # get the network using the super plugin
        router = super(NsxTVPlugin, self).get_router(context, router_id)
        # caller method name
        action = sys._getframe(1).f_code.co_name
        return self._get_plugin_from_az(router, action=action)

    def create_router(self, context, router):
        p = self._get_plugin_from_az(router['router'])
        self._validate_router_gw_plugin(context, p, router['router'].get(
            'external_gateway_info'))
        self._validate_obj_extensions(
            router['router'], p.plugin_type, 'router')
        new_router = p.create_router(context, router)
        self._cleanup_obj_fields(
            router['router'], p.plugin_type, 'router')
        return new_router

    def update_router(self, context, router_id, router):
        p = self._get_plugin_from_router_id(context, router_id)
        self._validate_router_gw_plugin(context, p, router['router'].get(
            'external_gateway_info'))
        self._validate_obj_extensions(
            router['router'], p.plugin_type, 'router')
        return p.update_router(context, router_id, router)

    def get_router(self, context, id, fields=None):
        p = self._get_plugin_from_router_id(context, id)
        router = p.get_router(context, id, fields=fields)
        self._cleanup_obj_fields(router, p.plugin_type, 'router')
        return router

    def add_router_interface(self, context, router_id, interface_info):
        p = self._get_plugin_from_router_id(context, router_id)
        self._validate_router_interface_plugin(context, p, interface_info)
        return p.add_router_interface(context, router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        p = self._get_plugin_from_router_id(context, router_id)
        return p.remove_router_interface(context, router_id, interface_info)

    def _validate_fip_router_plugin(self, context, fip_plugin, fip_data):
        if 'router_id' in fip_data:
            router_plugin = self._get_plugin_from_router_id(
                context, fip_data['router_id'])
            if router_plugin.plugin_type != fip_plugin.plugin_type:
                err_msg = (_('Floatingip router should belong to the %s '
                             'plugin as the floatingip') %
                           fip_plugin.plugin_type)
                raise n_exc.InvalidInput(error_message=err_msg)

    def create_floatingip(self, context, floatingip):
        net_id = floatingip['floatingip']['floating_network_id']
        p = self._get_plugin_from_net_id(context, net_id)
        self._validate_fip_router_plugin(context, p, floatingip['floatingip'])
        return p.create_floatingip(context, floatingip)

    def update_floatingip(self, context, id, floatingip):
        fip = self._get_floatingip(context, id)
        net_id = fip['floating_network_id']
        p = self._get_plugin_from_net_id(context, net_id)
        self._validate_fip_router_plugin(context, p, floatingip['floatingip'])
        return p.update_floatingip(context, id, floatingip)

    def delete_floatingip(self, context, id):
        fip = self._get_floatingip(context, id)
        net_id = fip['floating_network_id']
        p = self._get_plugin_from_net_id(context, net_id)
        return p.delete_floatingip(context, id)

    def disassociate_floatingips(self, context, port_id):
        db_port = self._get_port(context, port_id)
        p = self._get_plugin_from_net_id(context, db_port['network_id'])
        return p.disassociate_floatingips(context, port_id)

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

    def create_security_group_rule_bulk(self, context, security_group_rules):
        sg_rules = security_group_rules['security_group_rules']
        for r in sg_rules:
            r['security_group_rule']['id'] = (
                r['security_group_rule'].get('id') or
                uuidutils.generate_uuid())
        sgs = self._t.create_security_group_rule_bulk(context,
                                                      security_group_rules)
        self._v.create_security_group_rule_bulk(context,
                                                security_group_rules,
                                                base_create=False)
        return sgs

    def create_security_group_rule(self, context, security_group_rule):
        security_group_rule['security_group_rule']['id'] = (
            security_group_rule['security_group_rule'].get('id') or
            uuidutils.generate_uuid())
        sg = self._t.create_security_group_rule(context, security_group_rule)
        self._v.create_security_group_rule(context, security_group_rule,
                                           create_base=False)
        return sg

    def delete_security_group_rule(self, context, id):
        self._v.delete_security_group_rule(context, id, delete_base=False)
        self._t.delete_security_group_rule(context, id)
