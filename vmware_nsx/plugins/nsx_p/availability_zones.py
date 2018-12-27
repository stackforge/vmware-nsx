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

from oslo_config import cfg
from oslo_log import log

from vmware_nsx.common import availability_zones as common_az
from vmware_nsx.common import config
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.plugins.common_v3 import availability_zones as v3_az
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc

LOG = log.getLogger(__name__)

DEFAULT_NAME = common_az.DEFAULT_NAME + 'p'


class NsxPAvailabilityZone(v3_az.NsxV3AvailabilityZone):

    def get_az_opts(self):
        return config.get_nsxp_az_opts(self.name)

    def init_defaults(self):
        # use the default configuration
        self.metadata_proxy = cfg.CONF.nsx_p.metadata_proxy
        self.dhcp_profile = cfg.CONF.nsx_p.dhcp_profile
        self.native_metadata_route = cfg.CONF.nsx_p.native_metadata_route
        self.default_overlay_tz = cfg.CONF.nsx_p.default_overlay_tz
        self.default_vlan_tz = cfg.CONF.nsx_p.default_vlan_tz
        self.default_tier0_router = cfg.CONF.nsx_p.default_tier0_router
        self.dns_domain = cfg.CONF.nsx_p.dns_domain
        self.nameservers = cfg.CONF.nsx_p.nameservers

    def _init_default_resource(self, resource_api, config_name,
                               filter_list_results=None,
                               auto_config=False,
                               is_mandatory=True):
        # NOTE(annak): we may need to generalize this for API calls
        # requiring path ids
        name_or_id = getattr(self, config_name)
        if not name_or_id:
            if auto_config:
                # If the field not specified, the system will auto-configure
                # in case only single resource is present
                resources = resource_api.list()
                if filter_list_results:
                    resources = filter_list_results(resources)
                if len(resources) == 1:
                    return resources[0]['id']

            if is_mandatory:
                if self.is_default():
                    raise cfg.RequiredOptError(config_name,
                                               group=cfg.OptGroup('nsx_p'))
                else:
                    msg = (_("No %(res)s provided for availability "
                             "zone %(az)s") % {
                        'res': config_name,
                        'az': self.name})
                    raise nsx_exc.NsxPluginException(err_msg=msg)
            return None

        try:
            # Check if the configured value is the ID
            resource_api.get(name_or_id, silent=True)
            return name_or_id
        except nsx_lib_exc.ResourceNotFound:
            # Check if the configured value is the name
            resource = resource_api.get_by_name(name_or_id)
            if resource:
                return resource['id']
            else:
                if self.is_default():
                    raise cfg.RequiredOptError(config_name,
                                               group=cfg.OptGroup('nsx_p'))
                else:
                    msg = (_("Could not find %(res)s %(id)s for availability "
                             "zone %(az)s") % {
                        'res': config_name,
                        'id': name_or_id,
                        'az': self.name})
                    raise nsx_exc.NsxPluginException(err_msg=msg)

    def translate_configured_names_to_uuids(self, nsxpolicy):
        super(NsxPAvailabilityZone, self).translate_configured_names_to_uuids(
            nsxpolicy)

        # TODO(asarfaty): add DHCP/metadata parameters
        # TODO(asarfaty): add support for init_objects_by_tags
        self._default_overlay_tz_uuid = self._init_default_resource(
            nsxpolicy.transport_zone, 'default_overlay_tz',
            auto_config=True, is_mandatory=True,
            filter_list_results=lambda tzs: [
                tz for tz in tzs if tz['tz_type'].startswith('OVERLAY')])

        self._default_vlan_tz_uuid = self._init_default_resource(
            nsxpolicy.transport_zone, 'default_vlan_tz',
            auto_config=True, is_mandatory=False,
            filter_list_results=lambda tzs: [
                tz for tz in tzs if tz['tz_type'].startswith('VLAN')])

        self._default_tier0_router = self._init_default_resource(
            nsxpolicy.tier0, 'default_tier0_router',
            auto_config=True, is_mandatory=True)

        self.dhcp_relay_service = cfg.CONF.nsx_p.dhcp_relay_service


class NsxPAvailabilityZones(common_az.ConfiguredAvailabilityZones):

    default_name = DEFAULT_NAME

    def __init__(self):
        default_azs = cfg.CONF.default_availability_zones
        super(NsxPAvailabilityZones, self).__init__(
            cfg.CONF.nsx_p.availability_zones,
            NsxPAvailabilityZone,
            default_availability_zones=default_azs)
