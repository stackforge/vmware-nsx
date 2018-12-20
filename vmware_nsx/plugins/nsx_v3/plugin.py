# Copyright 2015 VMware, Inc.
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
import copy
import time

import mock
import netaddr
from neutron_lib.agent import topics
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api import extensions
from neutron_lib.api import faults
from neutron_lib.api.validators import availability_zone as az_validator
from neutron_lib.db import api as db_api
from neutron_lib.db import utils as db_utils
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from neutron_lib.services.qos import constants as qos_consts

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.db import _resource_extend as resource_extend
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db.availability_zone import router as router_az_db
from neutron.db import db_base_plugin_v2
from neutron.db import dns_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import extraroute_db
from neutron.db import l3_attrs_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db.models import l3 as l3_db_models
from neutron.db.models import securitygroup as securitygroup_model  # noqa
from neutron.db import models_v2
from neutron.db import portbindings_db
from neutron.db import portsecurity_db
from neutron.db import securitygroups_db
from neutron.db import vlantransparent_db
from neutron.extensions import providernet
from neutron.extensions import securitygroup as ext_sg
from neutron.quota import resource_registry
from neutron_lib.api.definitions import extra_dhcp_opt as ext_edo
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions as callback_exc
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib import context as q_context
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import uuidutils
from sqlalchemy import exc as sql_exc
import webob.exc

from vmware_nsx._i18n import _
from vmware_nsx.api_replay import utils as api_replay_utils
from vmware_nsx.common import availability_zones as nsx_com_az
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import l3_rpc_agent_api
from vmware_nsx.common import locking
from vmware_nsx.common import managers
from vmware_nsx.common import nsx_constants
from vmware_nsx.common import utils
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import extended_security_group_rule as extend_sg_rule
from vmware_nsx.db import maclearning as mac_db
from vmware_nsx.dhcp_meta import rpc as nsx_rpc
from vmware_nsx.extensions import advancedserviceproviders as as_providers
from vmware_nsx.extensions import housekeeper as hk_ext
from vmware_nsx.extensions import maclearning as mac_ext
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.plugins.common.housekeeper import housekeeper
from vmware_nsx.plugins.common_v3 import plugin as nsx_plugin_common
from vmware_nsx.plugins.nsx import utils as tvd_utils
from vmware_nsx.plugins.nsx_v3 import availability_zones as nsx_az
from vmware_nsx.plugins.nsx_v3 import utils as v3_utils
from vmware_nsx.services.fwaas.common import utils as fwaas_utils
from vmware_nsx.services.fwaas.nsx_v3 import fwaas_callbacks_v1
from vmware_nsx.services.fwaas.nsx_v3 import fwaas_callbacks_v2
from vmware_nsx.services.lbaas.nsx_v3.implementation import healthmonitor_mgr
from vmware_nsx.services.lbaas.nsx_v3.implementation import l7policy_mgr
from vmware_nsx.services.lbaas.nsx_v3.implementation import l7rule_mgr
from vmware_nsx.services.lbaas.nsx_v3.implementation import listener_mgr
from vmware_nsx.services.lbaas.nsx_v3.implementation import loadbalancer_mgr
from vmware_nsx.services.lbaas.nsx_v3.implementation import member_mgr
from vmware_nsx.services.lbaas.nsx_v3.implementation import pool_mgr
from vmware_nsx.services.lbaas.nsx_v3.v2 import lb_driver_v2
from vmware_nsx.services.lbaas.octavia import constants as oct_const
from vmware_nsx.services.lbaas.octavia import octavia_listener
from vmware_nsx.services.qos.common import utils as qos_com_utils
from vmware_nsx.services.qos.nsx_v3 import driver as qos_driver
from vmware_nsx.services.trunk.nsx_v3 import driver as trunk_driver
from vmware_nsxlib.v3 import core_resources as nsx_resources
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as nsxlib_consts
from vmware_nsxlib.v3 import router as nsxlib_router
from vmware_nsxlib.v3 import security
from vmware_nsxlib.v3 import utils as nsxlib_utils


LOG = log.getLogger(__name__)
NSX_V3_NO_PSEC_PROFILE_NAME = 'nsx-default-spoof-guard-vif-profile'
NSX_V3_MAC_LEARNING_PROFILE_NAME = 'neutron_port_mac_learning_profile'
NSX_V3_FW_DEFAULT_SECTION = 'OS Default Section for Neutron Security-Groups'
NSX_V3_FW_DEFAULT_NS_GROUP = 'os_default_section_ns_group'
NSX_V3_DEFAULT_SECTION = 'OS-Default-Section'
NSX_V3_EXCLUDED_PORT_NSGROUP_NAME = 'neutron_excluded_port_nsgroup'
NSX_V3_NON_VIF_PROFILE = 'nsx-default-switch-security-non-vif-profile'
NSX_V3_NON_VIF_ENS_PROFILE = \
    'nsx-default-switch-security-non-vif-profile-for-ens'
NSX_V3_SERVER_SSL_PROFILE = 'nsx-default-server-ssl-profile'
NSX_V3_CLIENT_SSL_PROFILE = 'nsx-default-client-ssl-profile'
# Default UUID for the global OS rule
NSX_V3_OS_DFW_UUID = '00000000-def0-0000-0fed-000000000000'


# NOTE(asarfaty): the order of inheritance here is important. in order for the
# QoS notification to work, the AgentScheduler init must be called first
# NOTE(arosen): same is true with the ExtendedSecurityGroupPropertiesMixin
# this needs to be above securitygroups_db.SecurityGroupDbMixin.
# FIXME(arosen): we can solve this inheritance order issue by just mixining in
# the classes into a new class to handle the order correctly.
@resource_extend.has_resource_extenders
class NsxV3Plugin(agentschedulers_db.AZDhcpAgentSchedulerDbMixin,
                  addr_pair_db.AllowedAddressPairsMixin,
                  nsx_plugin_common.NsxPluginV3Base,
                  extend_sg_rule.ExtendedSecurityGroupRuleMixin,
                  securitygroups_db.SecurityGroupDbMixin,
                  external_net_db.External_net_db_mixin,
                  extraroute_db.ExtraRoute_db_mixin,
                  router_az_db.RouterAvailabilityZoneMixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  portbindings_db.PortBindingMixin,
                  portsecurity_db.PortSecurityDbMixin,
                  extradhcpopt_db.ExtraDhcpOptMixin,
                  dns_db.DNSDbMixin,
                  vlantransparent_db.Vlantransparent_db_mixin,
                  mac_db.MacLearningDbMixin,
                  nsx_com_az.NSXAvailabilityZonesPluginCommon,
                  l3_attrs_db.ExtraAttributesMixin,
                  hk_ext.Housekeeper):

    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["allowed-address-pairs",
                                   "address-scope",
                                   "quotas",
                                   "binding",
                                   "extra_dhcp_opt",
                                   "agent",
                                   "dhcp_agent_scheduler",
                                   "ext-gw-mode",
                                   "security-group",
                                   "secgroup-rule-local-ip-prefix",
                                   "port-security",
                                   "provider",
                                   "external-net",
                                   "extraroute",
                                   "router",
                                   "availability_zone",
                                   "network_availability_zone",
                                   "router_availability_zone",
                                   "subnet_allocation",
                                   "security-group-logging",
                                   "provider-security-group",
                                   "housekeeper",
                                   "port-security-groups-filtering"]

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
        self.fwaas_callbacks = None
        self._is_sub_plugin = tvd_utils.is_tvd_core_plugin()
        self.init_is_complete = False
        self.octavia_listener = None
        self.octavia_stats_collector = None
        nsxlib_utils.set_is_attr_callback(validators.is_attr_set)
        self._extend_fault_map()
        if self._is_sub_plugin:
            extension_drivers = cfg.CONF.nsx_tvd.nsx_v3_extension_drivers
            self._update_project_mapping()
        else:
            extension_drivers = cfg.CONF.nsx_extension_drivers
        self._extension_manager = managers.ExtensionManager(
            extension_drivers=extension_drivers)
        self.cfg_group = 'nsx_v3'  # group name for nsx_v3 section in nsx.ini
        super(NsxV3Plugin, self).__init__()
        # Bind the dummy L3 notifications
        self.l3_rpc_notifier = l3_rpc_agent_api.L3NotifyAPI()
        LOG.info("Starting NsxV3Plugin")
        self._extension_manager.initialize()
        self.supported_extension_aliases.extend(
            self._extension_manager.extension_aliases())

        self.nsxlib = v3_utils.get_nsxlib_wrapper()
        if self.nsxlib.feature_supported(nsxlib_consts.FEATURE_ON_BEHALF_OF):
            nsxlib_utils.set_inject_headers_callback(
                v3_utils.inject_headers)
        else:
            nsxlib_utils.set_inject_headers_callback(
                v3_utils.inject_requestid_header)
        self.lbv2_driver = self._init_lbv2_driver()

        registry.subscribe(
            self.on_subnetpool_address_scope_updated,
            resources.SUBNETPOOL_ADDRESS_SCOPE, events.AFTER_UPDATE)

        self._nsx_version = self.nsxlib.get_version()
        LOG.info("NSX Version: %s", self._nsx_version)

        self.tier0_groups_dict = {}

        # Initialize the network availability zones, which will be used only
        # when native_dhcp_metadata is True
        self.init_availability_zones()

        # Translate configured transport zones, routers, dhcp profile and
        # metadata proxy names to uuid.
        self._translate_configured_names_to_uuids()
        self._init_dhcp_metadata()

        self._prepare_default_rules()

        # init profiles on nsx backend
        self._init_nsx_profiles()

        # Include exclude NSGroup
        LOG.debug("Initializing NSX v3 Excluded Port NSGroup")
        self._excluded_port_nsgroup = None
        self._excluded_port_nsgroup = self._init_excluded_port_nsgroup()
        if not self._excluded_port_nsgroup:
            msg = _("Unable to initialize NSX v3 Excluded Port NSGroup %s"
                    ) % NSX_V3_EXCLUDED_PORT_NSGROUP_NAME
            raise nsx_exc.NsxPluginException(err_msg=msg)

        qos_driver.register()

        self.start_rpc_listeners_called = False

        self._unsubscribe_callback_events()
        if cfg.CONF.api_replay_mode:
            self.supported_extension_aliases.append('api-replay')

        # Support transparent VLANS from 2.2.0 onwards. The feature is only
        # supported if the global configuration flag vlan_transparent is
        # True
        if cfg.CONF.vlan_transparent:
            if self.nsxlib.feature_supported(nsxlib_consts.FEATURE_TRUNK_VLAN):
                self.supported_extension_aliases.append("vlan-transparent")
            else:
                LOG.warning("Current NSX version %s doesn't support "
                            "transparent vlans", self.nsxlib.get_version())

        # Register NSXv3 trunk driver to support trunk extensions
        self.trunk_driver = trunk_driver.NsxV3TrunkDriver.create(self)

        registry.subscribe(self.spawn_complete,
                           resources.PROCESS,
                           events.AFTER_SPAWN)

        # subscribe the init complete method last, so it will be called only
        # if init was successful
        registry.subscribe(self.init_complete,
                           resources.PROCESS,
                           events.AFTER_INIT)

    def _update_project_mapping(self):
        ctx = q_context.get_admin_context()
        try:
            nsx_db.add_project_plugin_mapping(
                ctx.session,
                nsx_constants.INTERNAL_V3_TENANT_ID,
                projectpluginmap.NsxPlugins.NSX_T)
        except db_exc.DBDuplicateEntry:
            pass

    def _ensure_default_rules(self):
        # Include default section NSGroup
        LOG.debug("Initializing NSX v3 default section NSGroup")
        self._default_section_nsgroup = None
        self._default_section_nsgroup = self._init_default_section_nsgroup()
        if not self._default_section_nsgroup:
            msg = _("Unable to initialize NSX v3 default section NSGroup %s"
                    ) % NSX_V3_FW_DEFAULT_NS_GROUP
            raise nsx_exc.NsxPluginException(err_msg=msg)
        self.default_section = self._init_default_section_rules()
        LOG.info("Initializing NSX v3 default section %(section)s "
                 "and NSGroup %(nsgroup)s",
                 {'section': self.default_section,
                  'nsgroup': self._default_section_nsgroup.get('id')})

    def _ensure_global_sg_placeholder(self, context):
        found_sg = False
        try:
            super(NsxV3Plugin, self).get_security_group(
                context, NSX_V3_OS_DFW_UUID, fields=['id'])
        except ext_sg.SecurityGroupNotFound:
            LOG.warning('Creating a global security group')
            sec_group = {'security_group':
                         {'id': NSX_V3_OS_DFW_UUID,
                          'tenant_id': nsx_constants.INTERNAL_V3_TENANT_ID,
                          'name': 'NSX Internal',
                          'description': ''}}
            try:
                # ensure that the global default is created, and only once
                # without retrying on DB errors
                with mock.patch("oslo_db.api.wrap_db_retry."
                                "_is_exception_expected",
                                return_value=False):
                    super(NsxV3Plugin, self).create_security_group(
                        context, sec_group, True)
            except Exception:
                # Treat a race of multiple processing creating the sec group
                LOG.warning('Unable to create global security group. Probably '
                            'already created by another server')
                found_sg = True
        else:
            LOG.info('Found a global security group')
            found_sg = True

        if found_sg:
            # check if the section and nsgroup are already in the DB. If not
            # it means another server is creating them right now.
            nsgroup_id, section_id = nsx_db.get_sg_mappings(
                context.session, NSX_V3_OS_DFW_UUID)
            if nsgroup_id is None or section_id is None:
                LOG.info("Global security exists without NSX objects")
                # Wait a bit to let the other server finish
                # TODO(asarfaty): consider sleeping until it is in the DB
                time.sleep(3)

    def _cleanup_duplicates(self, ns_group_id, section_id):
        LOG.warning("Duplicate rules created! Deleting NS group %(nsgroup)s "
                    "and section %(section)s",
                    {'nsgroup': ns_group_id,
                     'section': section_id})
        # Delete duplicates created
        if section_id:
            self.nsxlib.firewall_section.delete(section_id)
        if ns_group_id:
            self.nsxlib.ns_group.delete(ns_group_id)
        # Ensure global variables are updated
        self._ensure_default_rules()

    def _prepare_default_rules(self):
        ctx = q_context.get_admin_context()
        # Need a global placeholder as the DB below has a foreign key to
        # this security group
        self._ensure_global_sg_placeholder(ctx)
        self._ensure_default_rules()
        # Validate if there is a race between processes
        nsgroup_id, section_id = nsx_db.get_sg_mappings(
            ctx.session, NSX_V3_OS_DFW_UUID)
        LOG.debug("Default NSGroup - %s, Section %s", nsgroup_id, section_id)
        default_ns_group_id = self._default_section_nsgroup.get('id')
        duplicates = False
        if nsgroup_id is None or section_id is None:
            # This means that the DB was not updated with the NSX IDs
            try:
                LOG.debug("Updating NSGroup - %s, Section %s",
                          default_ns_group_id, self.default_section)
                nsx_db.save_sg_mappings(ctx,
                                        NSX_V3_OS_DFW_UUID,
                                        default_ns_group_id,
                                        self.default_section)
            except Exception:
                # Another process must have update the DB at the same time
                # so delete the once that were just created
                LOG.debug("Concurrent update! Duplicates exist")
                duplicates = True
        else:
            if (section_id != self.default_section):
                LOG.debug("Section %(nsx)s doesn't match the one in the DB "
                          "%(db)s. Duplicates exist",
                          {'nsx': self.default_section,
                           'db': section_id})
                duplicates = True
            if (nsgroup_id != default_ns_group_id):
                LOG.debug("NSGroup %(nsx)s doesn't match the one in the DB "
                          "%(db)s. Duplicates exist",
                          {'nsx': default_ns_group_id,
                           'db': nsgroup_id})
                duplicates = True
        if duplicates:
            # deleting the NSX NS group & section found on the NSX backend
            # which are duplications, and use the ones from the DB
            self._cleanup_duplicates(default_ns_group_id,
                                     self.default_section)

    @staticmethod
    def plugin_type():
        return projectpluginmap.NsxPlugins.NSX_T

    @staticmethod
    def is_tvd_plugin():
        return False

    def spawn_complete(self, resource, event, trigger, payload=None):
        # This method should run only once, but after init_complete
        if not self.init_is_complete:
            self.init_complete(None, None, None)

        if not self._is_sub_plugin:
            self.octavia_stats_collector = (
                octavia_listener.NSXOctaviaStatisticsCollector(
                    self,
                    self._get_octavia_stats_getter()))

    def init_complete(self, resource, event, trigger, payload=None):
        with locking.LockManager.get_lock('plugin-init-complete'):
            if self.init_is_complete:
                # Should be called only once per worker
                return

            # reinitialize the cluster upon fork for api workers to ensure
            # each process has its own keepalive loops + state
            self.nsxlib.reinitialize_cluster(resource, event, trigger,
                                             payload=payload)

            # Init the FWaaS support
            self._init_fwaas()

            # Init the house keeper
            self.housekeeper = housekeeper.NsxHousekeeper(
                hk_ns='vmware_nsx.neutron.nsxv3.housekeeper.jobs',
                hk_jobs=cfg.CONF.nsx_v3.housekeeping_jobs,
                hk_readonly=cfg.CONF.nsx_v3.housekeeping_readonly,
                hk_readonly_jobs=cfg.CONF.nsx_v3.housekeeping_readonly_jobs)

            # Init octavia listener and endpoints
            self._init_octavia()

            self.init_is_complete = True

    def _init_octavia(self):
        if self._is_sub_plugin:
            # The TVD plugin will take care of this
            return

        if not self.nsxlib.feature_supported(
            nsxlib_consts.FEATURE_LOAD_BALANCER):
            return

        octavia_objects = self._get_octavia_objects()
        self.octavia_listener = octavia_listener.NSXOctaviaListener(
            **octavia_objects)

    def _get_octavia_objects(self):
        return {
            'loadbalancer': loadbalancer_mgr.EdgeLoadBalancerManagerFromDict(),
            'listener': listener_mgr.EdgeListenerManagerFromDict(),
            'pool': pool_mgr.EdgePoolManagerFromDict(),
            'member': member_mgr.EdgeMemberManagerFromDict(),
            'healthmonitor':
                healthmonitor_mgr.EdgeHealthMonitorManagerFromDict(),
            'l7policy': l7policy_mgr.EdgeL7PolicyManagerFromDict(),
            'l7rule': l7rule_mgr.EdgeL7RuleManagerFromDict()}

    def _get_octavia_stats_getter(self):
        return listener_mgr.stats_getter

    def _extend_fault_map(self):
        """Extends the Neutron Fault Map.

        Exceptions specific to the NSX Plugin are mapped to standard
        HTTP Exceptions.
        """
        faults.FAULT_MAP.update({nsx_lib_exc.ManagerError:
                                 webob.exc.HTTPBadRequest,
                                 nsx_lib_exc.ServiceClusterUnavailable:
                                 webob.exc.HTTPServiceUnavailable,
                                 nsx_lib_exc.ClientCertificateNotTrusted:
                                 webob.exc.HTTPBadRequest,
                                 nsx_exc.SecurityGroupMaximumCapacityReached:
                                 webob.exc.HTTPBadRequest,
                                 nsx_lib_exc.NsxLibInvalidInput:
                                 webob.exc.HTTPBadRequest,
                                 nsx_exc.NsxENSPortSecurity:
                                 webob.exc.HTTPBadRequest,
                                 })

    def _init_fwaas(self):
        if fwaas_utils.is_fwaas_v1_plugin_enabled():
            LOG.info("NSXv3 FWaaS v1 plugin enabled")
            self.fwaas_callbacks = fwaas_callbacks_v1.Nsxv3FwaasCallbacksV1()
        if fwaas_utils.is_fwaas_v2_plugin_enabled():
            LOG.info("NSXv3 FWaaS v2 plugin enabled")
            self.fwaas_callbacks = fwaas_callbacks_v2.Nsxv3FwaasCallbacksV2()

    def _init_lbv2_driver(self):
        # Get LBaaSv2 driver during plugin initialization. If the platform
        # has a version that doesn't support native loadbalancing, the driver
        # will return a NotImplementedManager class.
        LOG.debug("Initializing LBaaSv2.0 nsxv3 driver")
        if self.nsxlib.feature_supported(nsxlib_consts.FEATURE_LOAD_BALANCER):
            return lb_driver_v2.EdgeLoadbalancerDriverV2()
        else:
            LOG.warning("Current NSX version %(ver)s doesn't support LBaaS",
                        {'ver': self.nsxlib.get_version()})
            return lb_driver_v2.DummyLoadbalancerDriverV2()

    def init_availability_zones(self):
        self._availability_zones_data = nsx_az.NsxV3AvailabilityZones(
            use_tvd_config=self._is_sub_plugin)

    def _init_nsx_profiles(self):
        LOG.debug("Initializing NSX v3 port spoofguard switching profile")
        if not self._init_port_security_profile():
            msg = _("Unable to initialize NSX v3 port spoofguard switching "
                    "profile: %s") % v3_utils.NSX_V3_PSEC_PROFILE_NAME
            raise nsx_exc.NsxPluginException(err_msg=msg)
        profile_client = self.nsxlib.switching_profile
        no_psec_prof = profile_client.find_by_display_name(
            NSX_V3_NO_PSEC_PROFILE_NAME)[0]
        self._no_psec_profile_id = profile_client.build_switch_profile_ids(
            profile_client, no_psec_prof)[0]

        LOG.debug("Initializing NSX v3 DHCP switching profile")
        try:
            self._init_dhcp_switching_profile()
        except Exception as e:
            msg = (_("Unable to initialize NSX v3 DHCP switching profile: "
                     "%(id)s. Reason: %(reason)s") % {
                   'id': v3_utils.NSX_V3_DHCP_PROFILE_NAME,
                   'reason': str(e)})
            raise nsx_exc.NsxPluginException(err_msg=msg)

        self._mac_learning_profile = None
        # Only create MAC Learning profile when nsxv3 version >= 1.1.0
        if self.nsxlib.feature_supported(nsxlib_consts.FEATURE_MAC_LEARNING):
            LOG.debug("Initializing NSX v3 Mac Learning switching profile")
            try:
                self._init_mac_learning_profile()
                # Only expose the extension if it is supported
                self.supported_extension_aliases.append('mac-learning')
            except Exception as e:
                LOG.warning("Unable to initialize NSX v3 MAC Learning "
                            "profile: %(name)s. Reason: %(reason)s",
                            {'name': NSX_V3_MAC_LEARNING_PROFILE_NAME,
                             'reason': e})

        no_switch_security_prof = profile_client.find_by_display_name(
                NSX_V3_NON_VIF_PROFILE)[0]
        self._no_switch_security = profile_client.build_switch_profile_ids(
            profile_client, no_switch_security_prof)[0]
        no_switch_security_prof = profile_client.find_by_display_name(
                NSX_V3_NON_VIF_ENS_PROFILE)[0]
        self._no_switch_security_ens = profile_client.build_switch_profile_ids(
            profile_client, no_switch_security_prof)[0]

        self.server_ssl_profile = None
        self.client_ssl_profile = None
        # Only create LB profiles when nsxv3 version >= 2.1.0
        if self.nsxlib.feature_supported(nsxlib_consts.FEATURE_LOAD_BALANCER):
            LOG.debug("Initializing NSX v3 Load Balancer default profiles")
            try:
                self._init_lb_profiles()
            except Exception as e:
                msg = (_("Unable to initialize NSX v3 lb profiles: "
                         "Reason: %(reason)s") % {'reason': str(e)})
                raise nsx_exc.NsxPluginException(err_msg=msg)

    def _translate_configured_names_to_uuids(self):
        # If using tags to find the objects, make sure tag scope is configured
        if (cfg.CONF.nsx_v3.init_objects_by_tags and
            not cfg.CONF.nsx_v3.search_objects_scope):
            raise cfg.RequiredOptError("search_objects_scope",
                                       group=cfg.OptGroup('nsx_v3'))

        # Validate and translate native dhcp profiles per az
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            if not cfg.CONF.nsx_v3.dhcp_profile:
                raise cfg.RequiredOptError("dhcp_profile",
                                           group=cfg.OptGroup('nsx_v3'))

            if not cfg.CONF.nsx_v3.metadata_proxy:
                raise cfg.RequiredOptError("metadata_proxy",
                                           group=cfg.OptGroup('nsx_v3'))

        # Translate all the uuids in each of the availability
        for az in self.get_azs_list():
            az.translate_configured_names_to_uuids(self.nsxlib)

    @nsxlib_utils.retry_upon_exception(
        Exception, max_attempts=cfg.CONF.nsx_v3.retries)
    def _init_default_section_nsgroup(self):
        with locking.LockManager.get_lock('nsxv3_init_default_nsgroup'):
            nsgroup = self._get_default_section_nsgroup()
            if not nsgroup:
                # Create a new NSGroup for default section
                membership_criteria = (
                    self.nsxlib.ns_group.get_port_tag_expression(
                        security.PORT_SG_SCOPE, NSX_V3_DEFAULT_SECTION))
                nsgroup = self.nsxlib.ns_group.create(
                    NSX_V3_FW_DEFAULT_NS_GROUP,
                    'OS Default Section Port NSGroup',
                    tags=self.nsxlib.build_v3_api_version_tag(),
                    membership_criteria=membership_criteria)
            return self._get_default_section_nsgroup()

    def _get_default_section_nsgroup(self):
        if self._default_section_nsgroup:
            return self._default_section_nsgroup
        nsgroups = self.nsxlib.ns_group.find_by_display_name(
            NSX_V3_FW_DEFAULT_NS_GROUP)
        return nsgroups[0] if nsgroups else None

    @nsxlib_utils.retry_upon_exception(
        Exception, max_attempts=cfg.CONF.nsx_v3.retries)
    def _init_excluded_port_nsgroup(self):
        with locking.LockManager.get_lock('nsxv3_excluded_port_nsgroup_init'):
            nsgroup = self._get_excluded_port_nsgroup()
            if not nsgroup:
                # Create a new NSGroup for excluded ports.
                membership_criteria = (
                    self.nsxlib.ns_group.get_port_tag_expression(
                        security.PORT_SG_SCOPE, nsxlib_consts.EXCLUDE_PORT))
                nsgroup = self.nsxlib.ns_group.create(
                    NSX_V3_EXCLUDED_PORT_NSGROUP_NAME,
                    'Neutron Excluded Port NSGroup',
                    tags=self.nsxlib.build_v3_api_version_tag(),
                    membership_criteria=membership_criteria)
                # Add this NSGroup to NSX Exclusion List.
                self.nsxlib.firewall_section.add_member_to_fw_exclude_list(
                    nsgroup['id'], nsxlib_consts.NSGROUP)
            return self._get_excluded_port_nsgroup()

    def _get_excluded_port_nsgroup(self):
        if self._excluded_port_nsgroup:
            return self._excluded_port_nsgroup
        nsgroups = self.nsxlib.ns_group.find_by_display_name(
            NSX_V3_EXCLUDED_PORT_NSGROUP_NAME)
        return nsgroups[0] if nsgroups else None

    def _unsubscribe_callback_events(self):
        # l3_db explicitly subscribes to the port delete callback. This
        # callback is unsubscribed here since l3 APIs are handled by
        # core_plugin instead of an advanced service, in case of NSXv3 plugin,
        # and the prevention logic is handled by NSXv3 plugin itself.
        registry.unsubscribe(
            l3_db.L3_NAT_dbonly_mixin._prevent_l3_port_delete_callback,
            resources.PORT,
            events.BEFORE_DELETE)

    def _validate_dhcp_profile(self, dhcp_profile_uuid):
        dhcp_profile = self.nsxlib.switching_profile.get(dhcp_profile_uuid)
        if (dhcp_profile.get('resource_type') !=
            nsx_resources.SwitchingProfileTypes.SWITCH_SECURITY):
            msg = _("Invalid configuration on the backend for DHCP "
                    "switching profile %s. Switching Profile must be of type "
                    "'Switch Security'") % dhcp_profile_uuid
            raise n_exc.InvalidInput(error_message=msg)
        dhcp_filter = dhcp_profile.get('dhcp_filter')
        if (not dhcp_filter or dhcp_filter.get('client_block_enabled') or
            dhcp_filter.get('server_block_enabled')):
            msg = _("Invalid configuration on the backend for DHCP "
                    "switching profile %s. DHCP Server Block and Client Block "
                    "must be disabled") % dhcp_profile_uuid
            raise n_exc.InvalidInput(error_message=msg)

    @nsxlib_utils.retry_upon_exception(
        Exception, max_attempts=cfg.CONF.nsx_v3.retries)
    def _init_dhcp_switching_profile(self):
        with locking.LockManager.get_lock('nsxv3_dhcp_profile_init'):
            if not self._get_dhcp_security_profile():
                self.nsxlib.switching_profile.create_dhcp_profile(
                    v3_utils.NSX_V3_DHCP_PROFILE_NAME,
                    'Neutron DHCP Security Profile',
                    tags=self.nsxlib.build_v3_api_version_tag())
            return self._get_dhcp_security_profile()

    def _get_dhcp_security_profile(self):
        if hasattr(self, '_dhcp_profile') and self._dhcp_profile:
            return self._dhcp_profile
        profile = self.nsxlib.switching_profile.find_by_display_name(
            v3_utils.NSX_V3_DHCP_PROFILE_NAME)
        self._dhcp_profile = nsx_resources.SwitchingProfileTypeId(
            profile_type=(nsx_resources.SwitchingProfileTypes.
                          SWITCH_SECURITY),
            profile_id=profile[0]['id']) if profile else None
        return self._dhcp_profile

    def _init_mac_learning_profile(self):
        with locking.LockManager.get_lock('nsxv3_mac_learning_profile_init'):
            if not self._get_mac_learning_profile():
                self.nsxlib.switching_profile.create_mac_learning_profile(
                    NSX_V3_MAC_LEARNING_PROFILE_NAME,
                    'Neutron MAC Learning Profile',
                    tags=self.nsxlib.build_v3_api_version_tag())
            return self._get_mac_learning_profile()

    def _get_mac_learning_profile(self):
        if (hasattr(self, '_mac_learning_profile') and
            self._mac_learning_profile):
            return self._mac_learning_profile
        profile = self.nsxlib.switching_profile.find_by_display_name(
            NSX_V3_MAC_LEARNING_PROFILE_NAME)
        self._mac_learning_profile = nsx_resources.SwitchingProfileTypeId(
            profile_type=(nsx_resources.SwitchingProfileTypes.
                          MAC_LEARNING),
            profile_id=profile[0]['id']) if profile else None
        return self._mac_learning_profile

    def _init_lb_profiles(self):
        with locking.LockManager.get_lock('nsxv3_lb_profiles_init'):
            lb_profiles = self._get_lb_profiles()
            if not lb_profiles.get('client_ssl_profile'):
                self.nsxlib.load_balancer.client_ssl_profile.create(
                    NSX_V3_CLIENT_SSL_PROFILE,
                    'Neutron LB Client SSL Profile',
                    tags=self.nsxlib.build_v3_api_version_tag())
            if not lb_profiles.get('server_ssl_profile'):
                self.nsxlib.load_balancer.server_ssl_profile.create(
                    NSX_V3_SERVER_SSL_PROFILE,
                    'Neutron LB Server SSL Profile',
                    tags=self.nsxlib.build_v3_api_version_tag())

    def _get_lb_profiles(self):
        if not self.client_ssl_profile:
            ssl_profile_client = self.nsxlib.load_balancer.client_ssl_profile
            profile = ssl_profile_client.find_by_display_name(
                NSX_V3_CLIENT_SSL_PROFILE)
            self.client_ssl_profile = profile[0]['id'] if profile else None
        if not self.server_ssl_profile:
            ssl_profile_client = self.nsxlib.load_balancer.server_ssl_profile
            profile = ssl_profile_client.find_by_display_name(
                NSX_V3_SERVER_SSL_PROFILE)
            self.server_ssl_profile = profile[0]['id'] if profile else None

        return {'client_ssl_profile': self.client_ssl_profile,
                'server_ssl_profile': self.server_ssl_profile}

    def _get_port_security_profile_id(self):
        return self.nsxlib.switching_profile.build_switch_profile_ids(
            self.nsxlib.switching_profile, self._psec_profile)[0]

    def _get_port_security_profile(self):
        if hasattr(self, '_psec_profile') and self._psec_profile:
            return self._psec_profile
        profile = self.nsxlib.switching_profile.find_by_display_name(
            v3_utils.NSX_V3_PSEC_PROFILE_NAME)
        self._psec_profile = profile[0] if profile else None
        return self._psec_profile

    @nsxlib_utils.retry_upon_exception(
        Exception, max_attempts=cfg.CONF.nsx_v3.retries)
    def _init_port_security_profile(self):
        profile = self._get_port_security_profile()
        if profile:
            return profile

        with locking.LockManager.get_lock('nsxv3_psec_profile_init'):
            # NOTE(boden): double-checked locking pattern
            profile = self._get_port_security_profile()
            if profile:
                return profile

            self.nsxlib.switching_profile.create_spoofguard_profile(
                v3_utils.NSX_V3_PSEC_PROFILE_NAME,
                'Neutron Port Security Profile',
                whitelist_ports=True, whitelist_switches=False,
                tags=self.nsxlib.build_v3_api_version_tag())
        return self._get_port_security_profile()

    def _init_default_section_rules(self):
        with locking.LockManager.get_lock('nsxv3_default_section'):
            section_description = ("This section is handled by OpenStack to "
                                   "contain default rules on security-groups.")
            section_id = self.nsxlib.firewall_section.init_default(
                NSX_V3_FW_DEFAULT_SECTION, section_description,
                [self._default_section_nsgroup.get('id')],
                cfg.CONF.nsx_v3.log_security_groups_blocked_traffic)
            return section_id

    def _init_dhcp_metadata(self):
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            if cfg.CONF.dhcp_agent_notification:
                msg = _("Need to disable dhcp_agent_notification when "
                        "native_dhcp_metadata is enabled")
                raise nsx_exc.NsxPluginException(err_msg=msg)
            self._init_native_dhcp()
            self._init_native_metadata()
        else:
            self._setup_dhcp()
            self._start_rpc_notifiers()

    def _init_native_dhcp(self):
        try:
            for az in self.get_azs_list():
                self.nsxlib.native_dhcp_profile.get(
                    az._native_dhcp_profile_uuid)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to retrieve DHCP Profile %s, "
                          "native DHCP service is not supported",
                          az._native_dhcp_profile_uuid)

    def _init_native_metadata(self):
        try:
            for az in self.get_azs_list():
                self.nsxlib.native_md_proxy.get(az._native_md_proxy_uuid)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to retrieve Metadata Proxy %s, "
                          "native metadata service is not supported",
                          az._native_md_proxy_uuid)

    def _setup_rpc(self):
        self.endpoints = [dhcp_rpc.DhcpRpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]

    def _setup_dhcp(self):
        """Initialize components to support DHCP."""
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.add_periodic_dhcp_agent_status_check()

    def _start_rpc_notifiers(self):
        """Initialize RPC notifiers for agents."""
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )

    def start_rpc_listeners(self):
        if self.start_rpc_listeners_called:
            # If called more than once - we should not create it again
            return self.conn.consume_in_threads()

        self._setup_rpc()
        self.topic = topics.PLUGIN
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.create_consumer(topics.REPORTS,
                                  [agents_db.AgentExtRpcCallback()],
                                  fanout=False)
        self.start_rpc_listeners_called = True

        return self.conn.consume_in_threads()

    def _get_edge_cluster(self, tier0_uuid):
        if (not self.tier0_groups_dict.get(tier0_uuid) or not self.
                tier0_groups_dict[tier0_uuid].get('edge_cluster_uuid')):
            self.nsxlib.router.validate_tier0(self.tier0_groups_dict,
                                              tier0_uuid)
        tier0_info = self.tier0_groups_dict[tier0_uuid]
        return tier0_info['edge_cluster_uuid']

    def _allow_ens_networks(self):
        return cfg.CONF.nsx_v3.ens_support

    def _create_network_at_the_backend(self, context, net_data, az,
                                       transparent_vlan):
        provider_data = self._validate_provider_create(
            context, net_data,
            az._default_vlan_tz_uuid,
            az._default_overlay_tz_uuid,
            self.nsxlib.transport_zone,
            self.nsxlib.logical_switch,
            transparent_vlan=transparent_vlan)
        neutron_net_id = net_data.get('id') or uuidutils.generate_uuid()
        net_data['id'] = neutron_net_id

        if (provider_data['is_provider_net'] and
            provider_data['net_type'] == utils.NsxV3NetworkTypes.NSX_NETWORK):
            # Network already exists on the NSX backend
            nsx_id = provider_data['physical_net']
        else:
            # Create network on the backend
            # update the network name to indicate the neutron id too.
            net_name = utils.get_name_and_uuid(net_data['name'] or 'network',
                                               neutron_net_id)
            tags = self.nsxlib.build_v3_tags_payload(
                net_data, resource_type='os-neutron-net-id',
                project_name=context.tenant_name)

            admin_state = net_data.get('admin_state_up', True)
            LOG.debug('create_network: %(net_name)s, %(physical_net)s, '
                      '%(tags)s, %(admin_state)s, %(vlan_id)s',
                      {'net_name': net_name,
                       'physical_net': provider_data['physical_net'],
                       'tags': tags,
                       'admin_state': admin_state,
                       'vlan_id': provider_data['vlan_id']})
            trunk_vlan_range = None
            if transparent_vlan:
                # all vlan tags are allowed for guest vlan
                trunk_vlan_range = [0, const.MAX_VLAN_TAG]
            nsx_result = self.nsxlib.logical_switch.create(
                net_name, provider_data['physical_net'], tags,
                admin_state=admin_state,
                vlan_id=provider_data['vlan_id'],
                description=net_data.get('description'),
                trunk_vlan_range=trunk_vlan_range)
            nsx_id = nsx_result['id']

        return (provider_data['is_provider_net'],
                provider_data['net_type'],
                provider_data['physical_net'],
                provider_data['vlan_id'],
                nsx_id)

    def _is_ddi_supported_on_net_with_type(self, context, network_id):
        net = self.get_network(context, network_id)
        # NSX current does not support transparent VLAN ports for
        # DHCP and metadata
        if cfg.CONF.vlan_transparent:
            if net.get('vlan_transparent') is True:
                return False, "VLAN transparent"
        # NSX current does not support flat network ports for
        # DHCP and metadata
        if net.get(pnet.NETWORK_TYPE) == utils.NsxV3NetworkTypes.FLAT:
            return False, "flat"
        # supported for overlay networks, and for vlan networks depending on
        # NSX version
        is_overlay = self._is_overlay_network(context, network_id)
        net_type = "overlay" if is_overlay else "non-overlay"
        return (is_overlay or self.nsxlib.feature_supported(
                    nsxlib_consts.FEATURE_VLAN_ROUTER_INTERFACE)), net_type

    def _is_ddi_supported_on_network(self, context, network_id):
        result, _ = self._is_ddi_supported_on_net_with_type(
            context, network_id)
        return result

    def _is_overlay_network(self, context, network_id):
        """Return True if this is an overlay network

        1. No binding ("normal" overlay networks will have no binding)
        2. Geneve network
        3. nsx network where the backend network is connected to an overlay TZ
        """
        bindings = nsx_db.get_network_bindings(context.session, network_id)
        # With NSX plugin, "normal" overlay networks will have no binding
        if not bindings:
            # check the backend transport zone
            az = self.get_network_az_by_net_id(context, network_id)
            tz = az._default_overlay_tz_uuid
            if tz:
                backend_type = self.nsxlib.transport_zone.get_transport_type(
                    tz)
                if (backend_type !=
                    self.nsxlib.transport_zone.TRANSPORT_TYPE_OVERLAY):
                    # This is a misconfiguration
                    LOG.warning("Availability zone %(az)s default overlay TZ "
                                "%(tz)s is of type %(type)s",
                                {'az': az.name, 'tz': tz,
                                 'type': backend_type})
                    return False
            return True
        binding = bindings[0]
        if binding.binding_type == utils.NsxV3NetworkTypes.GENEVE:
            return True
        if binding.binding_type == utils.NsxV3NetworkTypes.NSX_NETWORK:
            # check the backend network
            # TODO(asarfaty): Keep TZ type in DB to avoid going to the backend
            ls = self.nsxlib.logical_switch.get(binding.phy_uuid)
            tz = ls.get('transport_zone_id')
            if tz:
                backend_type = self.nsxlib.transport_zone.get_transport_type(
                    tz)
                return (backend_type ==
                        self.nsxlib.transport_zone.TRANSPORT_TYPE_OVERLAY)
        return False

    def get_subnets(self, context, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
        filters = filters or {}
        lswitch_ids = filters.pop(as_providers.ADV_SERVICE_PROVIDERS, [])
        if lswitch_ids:
            # This is a request from Nova for metadata processing.
            # Find the corresponding neutron network for each logical switch.
            network_ids = filters.pop('network_id', [])
            context = context.elevated()
            for lswitch_id in lswitch_ids:
                network_ids += nsx_db.get_net_ids(context.session, lswitch_id)
            filters['network_id'] = network_ids
        return super(NsxV3Plugin, self).get_subnets(
            context, filters, fields, sorts, limit, marker, page_reverse)

    def _get_mdproxy_port_name(self, net_name, net_id):
        return utils.get_name_and_uuid('%s-%s' % ('mdproxy',
                                                  net_name or 'network'),
                                       net_id)

    def _tier0_validator(self, tier0_uuid):
        self.nsxlib.router.validate_tier0(self.tier0_groups_dict, tier0_uuid)

    def _get_nsx_net_tz_id(self, nsx_net):
        return nsx_net['transport_zone_id']

    def create_network(self, context, network):
        net_data = network['network']
        external = net_data.get(extnet_apidef.EXTERNAL)
        is_external_net = validators.is_attr_set(external) and external
        is_ddi_network = False
        tenant_id = net_data['tenant_id']

        # validate the availability zone, and get the AZ object
        if az_def.AZ_HINTS in net_data:
            self._validate_availability_zones_forced(
                context, 'network', net_data[az_def.AZ_HINTS])
        az = self.get_obj_az_by_hints(net_data)

        self._ensure_default_security_group(context, tenant_id)

        # Update the transparent vlan if configured
        vlt = False
        if extensions.is_extension_supported(self, 'vlan-transparent'):
            vlt = vlan_apidef.get_vlan_transparent(net_data)

        self._validate_create_network(context, net_data)

        if is_external_net:
            is_provider_net, net_type, physical_net, vlan_id = (
                self._validate_external_net_create(
                    net_data, az._default_tier0_router,
                    self._tier0_validator))
            nsx_net_id = None
            is_backend_network = False
        else:
            is_provider_net, net_type, physical_net, vlan_id, nsx_net_id = (
                self._create_network_at_the_backend(context, net_data, az,
                                                    vlt))
            is_backend_network = True

        try:
            rollback_network = False
            with db_api.CONTEXT_WRITER.using(context):
                # Create network in Neutron
                created_net = super(NsxV3Plugin, self).create_network(context,
                                                                      network)
                self._extension_manager.process_create_network(
                    context, net_data, created_net)
                if psec.PORTSECURITY not in net_data:
                    net_data[psec.PORTSECURITY] = True
                self._process_network_port_security_create(
                    context, net_data, created_net)
                self._process_l3_create(context, created_net, net_data)

                if az_def.AZ_HINTS in net_data:
                    # Update the AZ hints in the neutron object
                    az_hints = az_validator.convert_az_list_to_string(
                        net_data[az_def.AZ_HINTS])
                    super(NsxV3Plugin, self).update_network(
                        context,
                        created_net['id'],
                        {'network': {az_def.AZ_HINTS: az_hints}})

                if is_provider_net:
                    # Save provider network fields, needed by get_network()
                    net_bindings = [nsx_db.add_network_binding(
                        context.session, created_net['id'],
                        net_type, physical_net, vlan_id)]
                    self._extend_network_dict_provider(context, created_net,
                                                       bindings=net_bindings)
                if is_backend_network:
                    # Add neutron-id <-> nsx-id mapping to the DB
                    # after the network creation is done
                    neutron_net_id = created_net['id']
                    nsx_db.add_neutron_nsx_network_mapping(
                        context.session,
                        neutron_net_id,
                        nsx_net_id)

                if extensions.is_extension_supported(self, 'vlan-transparent'):
                    super(NsxV3Plugin, self).update_network(context,
                        created_net['id'],
                        {'network': {'vlan_transparent': vlt}})

            rollback_network = True

            is_ddi_network = self._is_ddi_supported_on_network(
                context, created_net['id'])
            if (is_backend_network and
                cfg.CONF.nsx_v3.native_dhcp_metadata and
                is_ddi_network):
                # Enable native metadata proxy for this network.
                tags = self.nsxlib.build_v3_tags_payload(
                    created_net, resource_type='os-neutron-net-id',
                    project_name=context.tenant_name)
                name = self._get_mdproxy_port_name(created_net['name'],
                                                   created_net['id'])
                md_port = self.nsxlib.logical_port.create(
                    nsx_net_id, az._native_md_proxy_uuid,
                    tags=tags, name=name,
                    attachment_type=nsxlib_consts.ATTACHMENT_MDPROXY)
                LOG.debug("Created MD-Proxy logical port %(port)s "
                          "for network %(network)s",
                          {'port': md_port['id'],
                           'network': created_net['id']})
        except Exception:
            with excutils.save_and_reraise_exception():
                # Undo creation on the backend
                LOG.exception('Failed to create network')
                if (nsx_net_id and
                    net_type != utils.NsxV3NetworkTypes.NSX_NETWORK):
                    self.nsxlib.logical_switch.delete(nsx_net_id)
                if (cfg.CONF.nsx_v3.native_dhcp_metadata and
                    is_backend_network and is_ddi_network):
                    # Delete the mdproxy port manually
                    self._delete_network_nsx_dhcp_port(created_net['id'])

                if rollback_network:
                    super(NsxV3Plugin, self).delete_network(
                        context, created_net['id'])

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        net_model = self._get_network(context, created_net['id'])
        resource_extend.apply_funcs('networks', created_net, net_model)

        # Update the QoS policy (will affect only future compute ports)
        qos_com_utils.set_qos_policy_on_new_net(
            context, net_data, created_net)
        if net_data.get(qos_consts.QOS_POLICY_ID):
            LOG.info("QoS Policy %(qos)s will be applied to future compute "
                     "ports of network %(net)s",
                     {'qos': net_data[qos_consts.QOS_POLICY_ID],
                      'net': created_net['id']})

        return created_net

    def _ens_psec_supported(self):
        return self.nsxlib.feature_supported(
            nsxlib_consts.FEATURE_ENS_WITH_SEC)

    def _validate_ens_net_portsecurity(self, net_data):
        """Validate/Update the port security of the new network for ENS TZ"""
        if not self._ens_psec_supported():
            if cfg.CONF.nsx_v3.disable_port_security_for_ens:
                # Override the port-security to False
                if net_data[psec.PORTSECURITY]:
                    LOG.warning("Disabling port security for bew network")
                    # Set the port security to False
                    net_data[psec.PORTSECURITY] = False

            elif net_data.get(psec.PORTSECURITY):
                # Port security enabled is not allowed
                raise nsx_exc.NsxENSPortSecurity()
            else:
                # Update the default port security to False if not set
                net_data[psec.PORTSECURITY] = False

    def _has_active_port(self, context, network_id):
        ports_in_use = context.session.query(models_v2.Port).filter_by(
            network_id=network_id).all()
        return not all([p.device_owner in
                        db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS
                        for p in ports_in_use]) if ports_in_use else False

    def _retry_delete_network(self, context, network_id):
        """This method attempts to retry the delete on a network if there are
           AUTO_DELETE_PORT_OWNERS left. This is to avoid a race condition
           between delete_network and the dhcp creating a port on the network.
        """
        first_try = True
        while True:
            try:
                with db_api.CONTEXT_WRITER.using(context):
                    self._process_l3_delete(context, network_id)
                    return super(NsxV3Plugin, self).delete_network(
                        context, network_id)
            except n_exc.NetworkInUse:
                # There is a race condition in delete_network() that we need
                # to work around here.  delete_network() issues a query to
                # automatically delete DHCP ports and then checks to see if any
                # ports exist on the network.  If a network is created and
                # deleted quickly, such as when running tempest, the DHCP agent
                # may be creating its port for the network around the same time
                # that the network is deleted.  This can result in the DHCP
                # port getting created in between these two queries in
                # delete_network().  To work around that, we'll call
                # delete_network() a second time if we get a NetworkInUse
                # exception but the only port(s) that exist are ones that
                # delete_network() is supposed to automatically delete.
                if not first_try:
                    # We tried once to work around the known race condition,
                    # but we still got the exception, so something else is
                    # wrong that we can't recover from.
                    raise
                first_try = False
                if self._has_active_port(context, network_id):
                    # There is a port on the network that is not going to be
                    # automatically deleted (such as a tenant created port), so
                    # we have nothing else to do but raise the exception.
                    raise

    def _delete_network_nsx_dhcp_port(self, network_id):
        port_id = self.nsxlib.get_id_by_resource_and_tag(
            self.nsxlib.logical_port.resource_type,
            'os-neutron-net-id', network_id)
        if port_id:
            self.nsxlib.logical_port.delete(port_id)

    def delete_network(self, context, network_id):
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            lock = 'nsxv3_network_' + network_id
            with locking.LockManager.get_lock(lock):
                # Disable native DHCP if there is no other existing port
                # besides DHCP port.
                if not self._has_active_port(context, network_id):
                    self._disable_native_dhcp(context, network_id)

        nsx_net_id = self._get_network_nsx_id(context, network_id)
        is_nsx_net = self._network_is_nsx_net(context, network_id)
        is_ddi_network = self._is_ddi_supported_on_network(context, network_id)
        # First call DB operation for delete network as it will perform
        # checks on active ports
        self._retry_delete_network(context, network_id)
        if (not self._network_is_external(context, network_id) and
            not is_nsx_net):
            # TODO(salv-orlando): Handle backend failure, possibly without
            # requiring us to un-delete the DB object. For instance, ignore
            # failures occurring if logical switch is not found
            self.nsxlib.logical_switch.delete(nsx_net_id)
        else:
            if (cfg.CONF.nsx_v3.native_dhcp_metadata and is_nsx_net and
                is_ddi_network):
                # Delete the mdproxy port manually
                self._delete_network_nsx_dhcp_port(network_id)
            # TODO(berlin): delete subnets public announce on the network

    def _get_network_nsx_id(self, context, neutron_id):
        # get the nsx switch id from the DB mapping
        mappings = nsx_db.get_nsx_switch_ids(context.session, neutron_id)
        if not mappings or len(mappings) == 0:
            LOG.debug("Unable to find NSX mappings for neutron "
                      "network %s.", neutron_id)
            # fallback in case we didn't find the id in the db mapping
            # This should not happen, but added here in case the network was
            # created before this code was added.
            return neutron_id
        else:
            return mappings[0]

    def update_network(self, context, id, network):
        original_net = super(NsxV3Plugin, self).get_network(context, id)
        net_data = network['network']
        # Neutron does not support changing provider network values
        providernet._raise_if_updates_provider_attributes(net_data)
        self._validate_qos_policy_id(
            context, net_data.get(qos_consts.QOS_POLICY_ID))
        extern_net = self._network_is_external(context, id)
        is_nsx_net = self._network_is_nsx_net(context, id)
        is_ens_net = self._is_ens_tz_net(context, id)

        # Validate the updated parameters
        self._validate_update_network(context, id, original_net, net_data)
        # add some plugin specific validations
        if is_ens_net:
            self._assert_on_ens_with_qos(net_data)

        updated_net = super(NsxV3Plugin, self).update_network(context, id,
                                                              network)
        self._extension_manager.process_update_network(context, net_data,
                                                       updated_net)
        if psec.PORTSECURITY in net_data:
            # do not allow to enable port security on ENS networks
            if (net_data[psec.PORTSECURITY] and
                not original_net[psec.PORTSECURITY] and is_ens_net and
                not self._ens_psec_supported()):
                raise nsx_exc.NsxENSPortSecurity()
            self._process_network_port_security_update(
                context, net_data, updated_net)
        self._process_l3_update(context, updated_net, network['network'])
        self._extend_network_dict_provider(context, updated_net)

        if (not extern_net and not is_nsx_net and
            ('name' in net_data or 'admin_state_up' in net_data or
             'description' in net_data)):
            try:
                # get the nsx switch id from the DB mapping
                nsx_id = self._get_network_nsx_id(context, id)
                net_name = net_data.get('name',
                                        original_net.get('name')) or 'network'
                self.nsxlib.logical_switch.update(
                    nsx_id,
                    name=utils.get_name_and_uuid(net_name, id),
                    admin_state=net_data.get('admin_state_up'),
                    description=net_data.get('description'))
                # Backend does not update the admin state of the ports on
                # the switch when the switch's admin state changes. Do not
                # update the admin state of the ports in neutron either.
            except nsx_lib_exc.ManagerError:
                LOG.exception("Unable to update NSX backend, rolling "
                              "back changes on neutron")
                with excutils.save_and_reraise_exception():
                    # remove the AZ from the network before rollback because
                    # it is read only, and breaks the rollback
                    if 'availability_zone_hints' in original_net:
                        del original_net['availability_zone_hints']
                    super(NsxV3Plugin, self).update_network(
                        context, id, {'network': original_net})

        if qos_consts.QOS_POLICY_ID in net_data:
            # attach the policy to the network in neutron DB
            #(will affect only future compute ports)
            qos_com_utils.update_network_policy_binding(
                context, id, net_data[qos_consts.QOS_POLICY_ID])
            if net_data[qos_consts.QOS_POLICY_ID]:
                LOG.info("QoS Policy %(qos)s will be applied to future "
                         "compute ports of network %(net)s",
                         {'qos': net_data[qos_consts.QOS_POLICY_ID],
                          'net': id})

        if not extern_net and not is_nsx_net:
            # update the network name & attributes in related NSX objects:
            if 'name' in net_data or 'dns_domain' in net_data:
                # update the dhcp server after finding it by tags
                self._update_dhcp_server_on_net_update(context, updated_net)

            if 'name' in net_data:
                # update the mdproxy port after finding it by tags
                self._update_mdproxy_port_on_net_update(context, updated_net)

                # update the DHCP port after finding it by tags
                self._update_dhcp_port_on_net_update(context, updated_net)

        return updated_net

    def _update_dhcp_port_on_net_update(self, context, network):
        """Update the NSX DHCP port when the neutron network changes"""
        dhcp_service = nsx_db.get_nsx_service_binding(
            context.session, network['id'], nsxlib_consts.SERVICE_DHCP)
        if dhcp_service and dhcp_service['port_id']:
            # get the neutron port id and search by it
            port_tag = [{'scope': 'os-neutron-dport-id',
                         'tag': dhcp_service['port_id']}]
            dhcpports = self.nsxlib.search_by_tags(
                tags=port_tag,
                resource_type=self.nsxlib.logical_port.resource_type)
            if dhcpports['results']:
                # There should be only 1 dhcp port
                # update the port name by the new network name
                name = self._get_dhcp_port_name(network['name'], network['id'])
                try:
                    self.nsxlib.logical_port.update(
                        dhcpports['results'][0]['id'],
                        False, name=name, attachment_type=False)
                except Exception as e:
                    LOG.warning("Failed to update network %(id)s DHCP port "
                                "on the NSX: %(e)s", {'id': network['id'],
                                                      'e': e})

    def _update_mdproxy_port_on_net_update(self, context, network):
        """Update the NSX MDPROXY port when the neutron network changes"""
        net_tag = [{'scope': 'os-neutron-net-id', 'tag': network['id']}]
        # find the logical port by the neutron network id & attachment
        mdproxy_list = self.nsxlib.search_by_tags(
            tags=net_tag,
            resource_type=self.nsxlib.logical_port.resource_type)
        if not mdproxy_list['results']:
            return
        for port in mdproxy_list['results']:
            if (port.get('attachment') and
                port['attachment'].get('attachment_type') == 'METADATA_PROXY'):
                # update the port name by the new network name
                name = self._get_mdproxy_port_name(network['name'],
                                                   network['id'])
                try:
                    self.nsxlib.logical_port.update(
                        port['id'], False, name=name, attachment_type=False)
                except Exception as e:
                    LOG.warning("Failed to update network %(id)s mdproxy port "
                                "on the NSX: %(e)s", {'id': network['id'],
                                                      'e': e})
                # There should be only 1 mdproxy port so it is safe to return
                return

    def _update_dhcp_server_on_net_update(self, context, network):
        """Update the NSX DHCP server when the neutron network changes"""
        net_tag = [{'scope': 'os-neutron-net-id', 'tag': network['id']}]
        # Find the DHCP server by the neutron network tag
        dhcp_srv_list = self.nsxlib.search_by_tags(
            tags=net_tag,
            resource_type=self.nsxlib.dhcp_server.resource_type)
        if dhcp_srv_list['results']:
            # Calculate the new name and domain by the network data
            dhcp_name = self.nsxlib.native_dhcp.build_server_name(
                network['name'], network['id'])
            az = self.get_network_az_by_net_id(context, network['id'])
            domain_name = self.nsxlib.native_dhcp.build_server_domain_name(
                network.get('dns_domain'), az.dns_domain)
            try:
                # There should be only 1 dhcp server
                # Update its name and domain
                self.nsxlib.dhcp_server.update(
                    dhcp_srv_list['results'][0]['id'],
                    name=dhcp_name,
                    domain_name=domain_name)
            except Exception as e:
                LOG.warning("Failed to update network %(id)s dhcp server on "
                            "the NSX: %(e)s", {'id': network['id'], 'e': e})

    def _has_no_dhcp_enabled_subnet(self, context, network):
        # Check if there is no DHCP-enabled subnet in the network.
        for subnet in network.subnets:
            if subnet.enable_dhcp:
                return False
        return True

    def _has_single_dhcp_enabled_subnet(self, context, network):
        # Check if there is only one DHCP-enabled subnet in the network.
        count = 0
        for subnet in network.subnets:
            if subnet.enable_dhcp:
                count += 1
                if count > 1:
                    return False
        return True if count == 1 else False

    def _validate_address_space(self, context, subnet):
        # Only working for IPv4 at the moment
        if (subnet['ip_version'] != 4):
            return

        # get the subnet IPs
        if ('allocation_pools' in subnet and
            validators.is_attr_set(subnet['allocation_pools'])):
            # use the pools instead of the cidr
            subnet_networks = [
                netaddr.IPRange(pool.get('start'), pool.get('end'))
                for pool in subnet.get('allocation_pools')]
        else:
            cidr = subnet.get('cidr')
            if not validators.is_attr_set(cidr):
                return
            subnet_networks = [netaddr.IPNetwork(subnet['cidr'])]

        # Check if subnet overlaps with shared address space.
        # This is checked on the backend when attaching subnet to a router.
        shared_ips = '100.64.0.0/10'
        for subnet_net in subnet_networks:
            if netaddr.IPSet(subnet_net) & netaddr.IPSet([shared_ips]):
                msg = _("Subnet overlaps with shared address space "
                        "%s") % shared_ips
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)

        # Ensure that the NSX uplink does not lie on the same subnet as
        # the external subnet
        filters = {'id': [subnet['network_id']],
                   'router:external': [True]}
        external_nets = self.get_networks(context, filters=filters)
        tier0_routers = [ext_net[pnet.PHYSICAL_NETWORK]
                         for ext_net in external_nets
                         if ext_net.get(pnet.PHYSICAL_NETWORK)]
        for tier0_rtr in set(tier0_routers):
            tier0_ips = self.nsxlib.logical_router_port.get_tier0_uplink_ips(
                tier0_rtr)
            for ip_address in tier0_ips:
                for subnet_network in subnet_networks:
                    if (netaddr.IPAddress(ip_address) in subnet_network):
                        msg = _("External subnet cannot overlap with T0 "
                                "router address %s") % ip_address
                        LOG.error(msg)
                        raise n_exc.InvalidInput(error_message=msg)

    def _create_bulk_with_callback(self, resource, context, request_items,
                                   post_create_func=None, rollback_func=None):
        # This is a copy of the _create_bulk() in db_base_plugin_v2.py,
        # but extended with user-provided callback functions.
        objects = []
        collection = "%ss" % resource
        items = request_items[collection]
        try:
            with db_api.CONTEXT_WRITER.using(context):
                for item in items:
                    obj_creator = getattr(self, 'create_%s' % resource)
                    obj = obj_creator(context, item)
                    objects.append(obj)
                    if post_create_func:
                        # The user-provided post_create function is called
                        # after a new object is created.
                        post_create_func(obj)
        except Exception:
            if rollback_func:
                # The user-provided rollback function is called when an
                # exception occurred.
                for obj in objects:
                    rollback_func(obj)

            # Note that the session.rollback() function is called here.
            # session.rollback() will invoke transaction.rollback() on
            # the transaction this session maintains. The latter will
            # deactive the transaction and clear the session's cache.
            #
            # But depending on where the exception occurred,
            # transaction.rollback() may have already been called
            # internally before reaching here.
            #
            # For example, if the exception happened under a
            # "with session.begin(subtransactions=True):" statement
            # anywhere in the middle of processing obj_creator(),
            # transaction.__exit__() will invoke transaction.rollback().
            # Thus when the exception reaches here, the session's cache
            # is already empty.
            context.session.rollback()
            with excutils.save_and_reraise_exception():
                LOG.error("An exception occurred while creating "
                          "the %(resource)s:%(item)s",
                          {'resource': resource, 'item': item})
        return objects

    def _post_create_subnet(self, context, subnet):
        LOG.debug("Collect native DHCP entries for network %s",
                  subnet['network_id'])
        dhcp_service = nsx_db.get_nsx_service_binding(
            context.session, subnet['network_id'], nsxlib_consts.SERVICE_DHCP)
        if dhcp_service:
            _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, dhcp_service['port_id'])
            return {'nsx_port_id': nsx_port_id,
                    'nsx_service_id': dhcp_service['nsx_service_id']}

    def _rollback_subnet(self, subnet, dhcp_info):
        LOG.debug("Rollback native DHCP entries for network %s",
                  subnet['network_id'])
        if dhcp_info:
            try:
                self.nsxlib.logical_port.delete(dhcp_info['nsx_port_id'])
            except Exception as e:
                LOG.error("Failed to delete logical port %(id)s "
                          "during rollback. Exception: %(e)s",
                          {'id': dhcp_info['nsx_port_id'], 'e': e})
            try:
                self.nsxlib.dhcp_server.delete(dhcp_info['nsx_service_id'])
            except Exception as e:
                LOG.error("Failed to delete logical DHCP server %(id)s "
                          "during rollback. Exception: %(e)s",
                          {'id': dhcp_info['nsx_service_id'], 'e': e})

    def create_subnet_bulk(self, context, subnets):
        # Maintain a local cache here because when the rollback function
        # is called, the cache in the session may have already been cleared.
        _subnet_dhcp_info = {}

        def _post_create(subnet):
            if subnet['enable_dhcp']:
                _subnet_dhcp_info[subnet['id']] = self._post_create_subnet(
                    context, subnet)

        def _rollback(subnet):
            if subnet['enable_dhcp'] and subnet['id'] in _subnet_dhcp_info:
                self._rollback_subnet(subnet, _subnet_dhcp_info[subnet['id']])
                del _subnet_dhcp_info[subnet['id']]

        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            return self._create_bulk_with_callback('subnet', context, subnets,
                                                   _post_create, _rollback)
        else:
            return self._create_bulk('subnet', context, subnets)

    def create_subnet(self, context, subnet):
        self._validate_host_routes_input(subnet)
        # TODO(berlin): public external subnet announcement
        if (cfg.CONF.nsx_v3.native_dhcp_metadata and
            subnet['subnet'].get('enable_dhcp', False)):
            self._validate_external_subnet(context,
                                           subnet['subnet']['network_id'])
            lock = 'nsxv3_network_' + subnet['subnet']['network_id']
            ddi_support, ddi_type = self._is_ddi_supported_on_net_with_type(
                context, subnet['subnet']['network_id'])
            with locking.LockManager.get_lock(lock):
                # Check if it is on an overlay network and is the first
                # DHCP-enabled subnet to create.
                if ddi_support:
                    network = self._get_network(
                        context, subnet['subnet']['network_id'])
                    if self._has_no_dhcp_enabled_subnet(context, network):
                        created_subnet = super(
                            NsxV3Plugin, self).create_subnet(context, subnet)
                        try:
                            # This can be called only after the super create
                            # since we need the subnet pool to be translated
                            # to allocation pools
                            self._validate_address_space(
                                context, created_subnet)
                        except n_exc.InvalidInput:
                            # revert the subnet creation
                            with excutils.save_and_reraise_exception():
                                super(NsxV3Plugin, self).delete_subnet(
                                    context, created_subnet['id'])
                        self._extension_manager.process_create_subnet(context,
                            subnet['subnet'], created_subnet)
                        dhcp_relay = self.get_network_az_by_net_id(
                            context,
                            subnet['subnet']['network_id']).dhcp_relay_service
                        if not dhcp_relay:
                            self._enable_native_dhcp(context, network,
                                                     created_subnet)
                        msg = None
                    else:
                        msg = (_("Can not create more than one DHCP-enabled "
                                "subnet in network %s") %
                               subnet['subnet']['network_id'])
                else:
                    msg = _("Native DHCP is not supported for %(type)s "
                            "network %(id)s") % {
                          'id': subnet['subnet']['network_id'],
                          'type': ddi_type}
                if msg:
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
        else:
            created_subnet = super(NsxV3Plugin, self).create_subnet(
                context, subnet)
            try:
                # This can be called only after the super create
                # since we need the subnet pool to be translated
                # to allocation pools
                self._validate_address_space(context, created_subnet)
            except n_exc.InvalidInput:
                # revert the subnet creation
                with excutils.save_and_reraise_exception():
                    super(NsxV3Plugin, self).delete_subnet(
                        context, created_subnet['id'])
        return created_subnet

    def delete_subnet(self, context, subnet_id):
        # TODO(berlin): cancel public external subnet announcement
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            # Ensure that subnet is not deleted if attached to router.
            self._subnet_check_ip_allocations_internal_router_ports(
                context, subnet_id)
            subnet = self.get_subnet(context, subnet_id)
            if subnet['enable_dhcp']:
                lock = 'nsxv3_network_' + subnet['network_id']
                with locking.LockManager.get_lock(lock):
                    # Check if it is the last DHCP-enabled subnet to delete.
                    network = self._get_network(context, subnet['network_id'])
                    if self._has_single_dhcp_enabled_subnet(context, network):
                        try:
                            self._disable_native_dhcp(context, network['id'])
                        except Exception as e:
                            LOG.error("Failed to disable native DHCP for"
                                      "network %(id)s. Exception: %(e)s",
                                      {'id': network['id'], 'e': e})
                        super(NsxV3Plugin, self).delete_subnet(
                            context, subnet_id)
                        return
        super(NsxV3Plugin, self).delete_subnet(context, subnet_id)

    def update_subnet(self, context, subnet_id, subnet):
        updated_subnet = None
        orig_subnet = self.get_subnet(context, subnet_id)
        self._validate_host_routes_input(
            subnet,
            orig_enable_dhcp=orig_subnet['enable_dhcp'],
            orig_host_routes=orig_subnet['host_routes'])
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            enable_dhcp = subnet['subnet'].get('enable_dhcp')
            if (enable_dhcp is not None and
                enable_dhcp != orig_subnet['enable_dhcp']):
                lock = 'nsxv3_network_' + orig_subnet['network_id']
                with locking.LockManager.get_lock(lock):
                    network = self._get_network(
                        context, orig_subnet['network_id'])
                    if enable_dhcp:
                        (ddi_support,
                         ddi_type) = self._is_ddi_supported_on_net_with_type(
                            context, orig_subnet['network_id'])
                        if ddi_support:
                            if self._has_no_dhcp_enabled_subnet(
                                context, network):
                                updated_subnet = super(
                                    NsxV3Plugin, self).update_subnet(
                                    context, subnet_id, subnet)
                                self._extension_manager.process_update_subnet(
                                    context, subnet['subnet'], updated_subnet)
                                self._enable_native_dhcp(context, network,
                                                         updated_subnet)
                                msg = None
                            else:
                                msg = (_("Multiple DHCP-enabled subnets is "
                                         "not allowed in network %s") %
                                       orig_subnet['network_id'])
                        else:
                            msg = (_("Native DHCP is not supported for "
                                     "%(type)s network %(id)s") %
                                   {'id': orig_subnet['network_id'],
                                    'type': ddi_type})
                        if msg:
                            LOG.error(msg)
                            raise n_exc.InvalidInput(error_message=msg)
                    elif self._has_single_dhcp_enabled_subnet(context,
                                                              network):
                        self._disable_native_dhcp(context, network['id'])
                        updated_subnet = super(
                            NsxV3Plugin, self).update_subnet(
                            context, subnet_id, subnet)
                        self._extension_manager.process_update_subnet(
                            context, subnet['subnet'], updated_subnet)

        if not updated_subnet:
            updated_subnet = super(NsxV3Plugin, self).update_subnet(
                context, subnet_id, subnet)
            self._extension_manager.process_update_subnet(
                context, subnet['subnet'], updated_subnet)

        # Check if needs to update logical DHCP server for native DHCP.
        if (cfg.CONF.nsx_v3.native_dhcp_metadata and
            updated_subnet['enable_dhcp']):
            kwargs = {}
            for key in ('dns_nameservers', 'gateway_ip', 'host_routes'):
                if key in subnet['subnet']:
                    value = subnet['subnet'][key]
                    if value != orig_subnet[key]:
                        kwargs[key] = value
                        if key != 'dns_nameservers':
                            kwargs['options'] = None
            if 'options' in kwargs:
                sr, gw_ip = self.nsxlib.native_dhcp.build_static_routes(
                    updated_subnet.get('gateway_ip'),
                    updated_subnet.get('cidr'),
                    updated_subnet.get('host_routes', []))
                kwargs['options'] = {'option121': {'static_routes': sr}}
                kwargs.pop('host_routes', None)
                if (gw_ip is not None and 'gateway_ip' not in kwargs and
                    gw_ip != updated_subnet['gateway_ip']):
                    kwargs['gateway_ip'] = gw_ip
            if kwargs:
                dhcp_service = nsx_db.get_nsx_service_binding(
                    context.session, orig_subnet['network_id'],
                    nsxlib_consts.SERVICE_DHCP)
                if dhcp_service:
                    try:
                        self.nsxlib.dhcp_server.update(
                            dhcp_service['nsx_service_id'], **kwargs)
                    except nsx_lib_exc.ManagerError:
                        with excutils.save_and_reraise_exception():
                            LOG.error(
                                "Unable to update logical DHCP server "
                                "%(server)s for network %(network)s",
                                {'server': dhcp_service['nsx_service_id'],
                                 'network': orig_subnet['network_id']})
                    if 'options' in kwargs:
                        # Need to update the static binding of every VM in
                        # this logical DHCP server.
                        bindings = nsx_db.get_nsx_dhcp_bindings_by_service(
                            context.session, dhcp_service['nsx_service_id'])
                        for binding in bindings:
                            port = self._get_port(context, binding['port_id'])
                            dhcp_opts = port.get(ext_edo.EXTRADHCPOPTS)
                            self._update_dhcp_binding_on_server(
                                context, binding, port['mac_address'],
                                binding['ip_address'],
                                port['network_id'],
                                gateway_ip=kwargs.get('gateway_ip', False),
                                dhcp_opts=dhcp_opts,
                                options=kwargs.get('options'),
                                subnet=updated_subnet)

        if (cfg.CONF.nsx_v3.metadata_on_demand and
            not cfg.CONF.nsx_v3.native_dhcp_metadata):
            # If enable_dhcp is changed on a subnet attached to a router,
            # update internal metadata network accordingly.
            if 'enable_dhcp' in subnet['subnet']:
                port_filters = {'device_owner': const.ROUTER_INTERFACE_OWNERS,
                                'fixed_ips': {'subnet_id': [subnet_id]}}
                ports = self.get_ports(context, filters=port_filters)
                for port in ports:
                    nsx_rpc.handle_router_metadata_access(
                        self, context, port['device_id'],
                        interface=not updated_subnet['enable_dhcp'])
        return updated_subnet

    def _build_address_bindings(self, port):
        address_bindings = []
        for fixed_ip in port['fixed_ips']:
            # NOTE(arosen): nsx-v3 doesn't seem to handle ipv6 addresses
            # currently so for now we remove them here and do not pass
            # them to the backend which would raise an error.
            if netaddr.IPNetwork(fixed_ip['ip_address']).version == 6:
                continue
            address_bindings.append(nsx_resources.PacketAddressClassifier(
                fixed_ip['ip_address'], port['mac_address'], None))

        for pair in port.get(addr_apidef.ADDRESS_PAIRS):
            address_bindings.append(nsx_resources.PacketAddressClassifier(
                pair['ip_address'], pair['mac_address'], None))

        return address_bindings

    def _get_qos_profile_id(self, context, policy_id):
        switch_profile_id = nsx_db.get_switch_profile_by_qos_policy(
            context.session, policy_id)
        nsxlib_qos = self.nsxlib.qos_switching_profile
        qos_profile = nsxlib_qos.get(switch_profile_id)
        if qos_profile:
            profile_ids = nsxlib_qos.build_switch_profile_ids(
                self.nsxlib.switching_profile, qos_profile)
            if profile_ids and len(profile_ids) > 0:
                # We have only 1 QoS profile, so this array is of size 1
                return profile_ids[0]
        # Didn't find it
        err_msg = _("Could not find QoS switching profile for policy "
                    "%s") % policy_id
        LOG.error(err_msg)
        raise n_exc.InvalidInput(error_message=err_msg)

    def _is_excluded_port(self, device_owner, port_security):
        if device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF:
            return False
        if device_owner == const.DEVICE_OWNER_DHCP:
            if not cfg.CONF.nsx_v3.native_dhcp_metadata:
                return True
        elif not port_security:
            return True
        return False

    def _create_port_at_the_backend(self, context, port_data,
                                    l2gw_port_check, psec_is_on,
                                    is_ens_tz_port):
        device_owner = port_data.get('device_owner')
        device_id = port_data.get('device_id')
        if device_owner == const.DEVICE_OWNER_DHCP:
            resource_type = 'os-neutron-dport-id'
        elif device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF:
            resource_type = 'os-neutron-rport-id'
        else:
            resource_type = 'os-neutron-port-id'
        tags = self.nsxlib.build_v3_tags_payload(
            port_data, resource_type=resource_type,
            project_name=context.tenant_name)
        resource_type = self._get_resource_type_for_device_id(
            device_owner, device_id)
        if resource_type:
            tags = nsxlib_utils.add_v3_tag(tags, resource_type, device_id)

        add_to_exclude_list = False
        if self._is_excluded_port(device_owner, psec_is_on):
            if self.nsxlib.feature_supported(
                nsxlib_consts.FEATURE_EXCLUDE_PORT_BY_TAG):
                tags.append({'scope': security.PORT_SG_SCOPE,
                             'tag': nsxlib_consts.EXCLUDE_PORT})
            else:
                add_to_exclude_list = True

        elif self.nsxlib.feature_supported(
            nsxlib_consts.FEATURE_DYNAMIC_CRITERIA):
            # If port has no security-groups then we don't need to add any
            # security criteria tag.
            if port_data[ext_sg.SECURITYGROUPS]:
                tags += self.nsxlib.ns_group.get_lport_tags(
                    port_data[ext_sg.SECURITYGROUPS] +
                    port_data[provider_sg.PROVIDER_SECURITYGROUPS])
            # Add port to the default list
            if (device_owner != l3_db.DEVICE_OWNER_ROUTER_INTF and
                device_owner != const.DEVICE_OWNER_DHCP):
                tags.append({'scope': security.PORT_SG_SCOPE,
                             'tag': NSX_V3_DEFAULT_SECTION})

        address_bindings = (self._build_address_bindings(port_data)
                            if psec_is_on else [])

        if not device_owner:
            # no attachment
            attachment_type = None
            vif_uuid = None
        elif l2gw_port_check:
            # Change the attachment type for L2 gateway owned ports.
            # NSX backend requires the vif id be set to bridge endpoint id
            # for ports plugged into a Bridge Endpoint.
            # Also set port security to False, since L2GW port does not have
            # an IP address.
            vif_uuid = device_id
            attachment_type = device_owner
            psec_is_on = False
        elif device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF:
            # no attachment change
            attachment_type = False
            vif_uuid = False
        else:
            # default attachment
            attachment_type = nsxlib_consts.ATTACHMENT_VIF
            vif_uuid = port_data['id']

        profiles = []

        # Add availability zone profiles first (so that specific profiles will
        # override them)
        port_az = self.get_network_az_by_net_id(context,
                                                port_data['network_id'])
        if port_az.switching_profiles_objs:
            profiles.extend(port_az.switching_profiles_objs)

        mac_learning_profile_set = False
        if psec_is_on:
            address_pairs = port_data.get(addr_apidef.ADDRESS_PAIRS)
            if validators.is_attr_set(address_pairs) and address_pairs:
                mac_learning_profile_set = True
            profiles.append(self._get_port_security_profile_id())
        else:
            if is_ens_tz_port:
                profiles.append(self._no_switch_security_ens)
            else:
                profiles.append(self._no_switch_security)
        if device_owner == const.DEVICE_OWNER_DHCP:
            if ((not is_ens_tz_port or self._ens_psec_supported()) and
                not cfg.CONF.nsx_v3.native_dhcp_metadata):
                profiles.append(self._dhcp_profile)

        # Add QoS switching profile, if exists
        qos_policy_id = None
        if validators.is_attr_set(port_data.get(qos_consts.QOS_POLICY_ID)):
            qos_policy_id = port_data[qos_consts.QOS_POLICY_ID]
        elif device_owner.startswith(const.DEVICE_OWNER_COMPUTE_PREFIX):
            # check if the network of this port has a policy
            qos_policy_id = qos_com_utils.get_network_policy_id(
                context, port_data['network_id'])
        if qos_policy_id:
            qos_profile_id = self._get_qos_profile_id(context, qos_policy_id)
            profiles.append(qos_profile_id)

        # Add mac_learning profile if it exists and is configured
        if ((not is_ens_tz_port or self._ens_psec_supported()) and
            self._mac_learning_profile and
            (mac_learning_profile_set or
             (validators.is_attr_set(port_data.get(mac_ext.MAC_LEARNING)) and
              port_data.get(mac_ext.MAC_LEARNING) is True))):
            profiles.append(self._mac_learning_profile)
            if is_ens_tz_port:
                if self._no_switch_security_ens not in profiles:
                    profiles.append(self._no_switch_security_ens)
            else:
                if self._no_switch_security not in profiles:
                    profiles.append(self._no_switch_security)

        name = self._build_port_name(context, port_data)
        nsx_net_id = self._get_network_nsx_id(context, port_data['network_id'])
        try:
            result = self.nsxlib.logical_port.create(
                nsx_net_id, vif_uuid,
                tags=tags,
                name=name,
                admin_state=port_data['admin_state_up'],
                address_bindings=address_bindings,
                attachment_type=attachment_type,
                switch_profile_ids=profiles,
                description=port_data.get('description'))
        except nsx_lib_exc.ManagerError as inst:
            # we may fail if the QoS is not supported for this port
            # (for example - transport zone with KVM)
            LOG.exception("Unable to create port on the backend: %s",
                          inst)
            msg = _("Unable to create port on the backend")
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # Attach the policy to the port in the neutron DB
        if qos_policy_id:
            qos_com_utils.update_port_policy_binding(context,
                                                     port_data['id'],
                                                     qos_policy_id)

        # Add the port to the exclude list if necessary - this is if
        # the version is below 2.0.0
        if add_to_exclude_list:
            self.nsxlib.firewall_section.add_member_to_fw_exclude_list(
                result['id'], nsxlib_consts.TARGET_TYPE_LOGICAL_PORT)

        return result

    def _get_net_tz(self, context, net_id):
        mappings = nsx_db.get_nsx_switch_ids(context.session, net_id)
        if mappings:
            nsx_net_id = nsx_net_id = mappings[0]
            if nsx_net_id:
                nsx_net = self.nsxlib.logical_switch.get(nsx_net_id)
                return nsx_net.get('transport_zone_id')

    def _is_ens_tz_net(self, context, net_id):
        #Check the host-switch-mode of the TZ connected to network
        tz_id = self._get_net_tz(context, net_id)
        if tz_id:
            # Check the mode of this TZ
            return self._is_ens_tz(tz_id)
        return False

    def _is_ens_tz(self, tz_id):
        mode = self.nsxlib.transport_zone.get_host_switch_mode(tz_id)
        return mode == self.nsxlib.transport_zone.HOST_SWITCH_MODE_ENS

    def _is_ens_tz_port(self, context, port_data):
        # Check the host-switch-mode of the TZ connected to the ports network
        return self._is_ens_tz_net(context, port_data['network_id'])

    def _has_native_dhcp_metadata(self):
        return cfg.CONF.nsx_v3.native_dhcp_metadata

    def _assert_on_dhcp_relay_without_router(self, context, port_data,
                                             original_port=None):
        # Prevent creating/updating port with device owner prefix 'compute'
        # on a subnet with dhcp relay but no router.
        if not original_port:
            original_port = port_data
        device_owner = port_data.get('device_owner')
        if (device_owner is None or
            not device_owner.startswith(const.DEVICE_OWNER_COMPUTE_PREFIX)):
            # not a compute port
            return

        if not self.get_network_az_by_net_id(
            context,
            original_port['network_id']).dhcp_relay_service:
            # No dhcp relay for the net of this port
            return

        # get the subnet id from the fixed ips of the port
        if 'fixed_ips' in port_data and port_data['fixed_ips']:
            subnet_id = port_data['fixed_ips'][0]['subnet_id']
        elif 'fixed_ips' in original_port and original_port['fixed_ips']:
            subnet_id = original_port['fixed_ips'][0]['subnet_id']
        else:
            return

        # check only dhcp enabled subnets
        subnet = self.get_subnet(context.elevated(), subnet_id)
        if not subnet['enable_dhcp']:
            return

        # check if the subnet is attached to a router
        port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [original_port['network_id']]}
        interfaces = self.get_ports(context.elevated(), filters=port_filters)
        router_found = False
        for interface in interfaces:
            if interface['fixed_ips'][0]['subnet_id'] == subnet_id:
                router_found = True
                break
        if not router_found:
            err_msg = _("Neutron is configured with DHCP_Relay but no router "
                        "connected to the subnet")
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def _assert_on_port_admin_state(self, port_data, device_owner):
        """Do not allow changing the admin state of some ports"""
        if (device_owner == l3_db.DEVICE_OWNER_ROUTER_INTF or
            device_owner == l3_db.DEVICE_OWNER_ROUTER_GW):
            if port_data.get("admin_state_up") is False:
                err_msg = _("admin_state_up=False router ports are not "
                            "supported")
                LOG.warning(err_msg)
                raise n_exc.InvalidInput(error_message=err_msg)

    def _filter_ipv4_dhcp_fixed_ips(self, context, fixed_ips):
        ips = []
        for fixed_ip in fixed_ips:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version != 4:
                continue
            with db_api.CONTEXT_READER.using(context):
                subnet = self.get_subnet(context, fixed_ip['subnet_id'])
            if subnet['enable_dhcp']:
                ips.append(fixed_ip)
        return ips

    def _add_dhcp_binding(self, context, port):
        if not utils.is_port_dhcp_configurable(port):
            return
        dhcp_service = nsx_db.get_nsx_service_binding(
            context.session, port['network_id'], nsxlib_consts.SERVICE_DHCP)
        if not dhcp_service:
            return
        for fixed_ip in self._filter_ipv4_dhcp_fixed_ips(
            context, port['fixed_ips']):
            binding = self._add_dhcp_binding_on_server(
                context, dhcp_service['nsx_service_id'], fixed_ip['subnet_id'],
                fixed_ip['ip_address'], port)
            try:
                nsx_db.add_neutron_nsx_dhcp_binding(
                    context.session, port['id'], fixed_ip['subnet_id'],
                    fixed_ip['ip_address'], dhcp_service['nsx_service_id'],
                    binding['id'])
            except (db_exc.DBError, sql_exc.TimeoutError):
                LOG.error("Failed to add mapping of DHCP binding "
                          "%(binding)s for port %(port)s, deleting "
                          "DHCP binding on server",
                          {'binding': binding['id'], 'port': port['id']})
                fake_db_binding = {
                    'port_id': port['id'],
                    'nsx_service_id': dhcp_service['nsx_service_id'],
                    'nsx_binding_id': binding['id']}
                self._delete_dhcp_binding_on_server(context, fake_db_binding)

    def _validate_extra_dhcp_options(self, opts):
        if not opts or not cfg.CONF.nsx_v3.native_dhcp_metadata:
            return
        for opt in opts:
            opt_name = opt['opt_name']
            opt_val = opt['opt_value']
            if opt_name == 'classless-static-route':
                # separate validation for option121
                if opt_val is not None:
                    try:
                        net, ip = opt_val.split(',')
                    except Exception:
                        msg = (_("Bad value %(val)s for DHCP option "
                                 "%(name)s") % {'name': opt_name,
                                                'val': opt_val})
                        raise n_exc.InvalidInput(error_message=msg)
            elif not self.nsxlib.dhcp_server.get_dhcp_opt_code(opt_name):
                msg = (_("DHCP option %s is not supported") % opt_name)
                raise n_exc.InvalidInput(error_message=msg)

    def _get_dhcp_options(self, context, ip, extra_dhcp_opts, net_id,
                          subnet):
        # Always add option121.
        net_az = self.get_network_az_by_net_id(context, net_id)
        options = {'option121': {'static_routes': [
            {'network': '%s' % net_az.native_metadata_route,
             'next_hop': '0.0.0.0'},
            {'network': '%s' % net_az.native_metadata_route,
             'next_hop': ip}]}}
        if subnet:
            sr, gateway_ip = self.nsxlib.native_dhcp.build_static_routes(
                subnet.get('gateway_ip'), subnet.get('cidr'),
                subnet.get('host_routes', []))
            options['option121']['static_routes'].extend(sr)
        # Adding extra options only if configured on port
        if extra_dhcp_opts:
            other_opts = []
            for opt in extra_dhcp_opts:
                opt_name = opt['opt_name']
                if opt['opt_value'] is not None:
                    # None value means - delete this option. Since we rebuild
                    # the options from scratch, it can be ignored.
                    opt_val = opt['opt_value']
                    if opt_name == 'classless-static-route':
                        # Add to the option121 static routes
                        net, ip = opt_val.split(',')
                        options['option121']['static_routes'].append({
                            'network': net, 'next_hop': ip})
                    else:
                        other_opts.append({
                            'code': self.nsxlib.dhcp_server.get_dhcp_opt_code(
                                opt_name),
                            'values': [opt_val]})
            if other_opts:
                options['others'] = other_opts
        return options

    def _add_dhcp_binding_on_server(self, context, dhcp_service_id, subnet_id,
                                    ip, port):
        try:
            hostname = 'host-%s' % ip.replace('.', '-')
            subnet = self.get_subnet(context, subnet_id)
            gateway_ip = subnet.get('gateway_ip')
            options = self._get_dhcp_options(
                context, ip, port.get(ext_edo.EXTRADHCPOPTS),
                port['network_id'], subnet)
            binding = self.nsxlib.dhcp_server.create_binding(
                dhcp_service_id, port['mac_address'], ip, hostname,
                cfg.CONF.nsx_v3.dhcp_lease_time, options, gateway_ip)
            LOG.debug("Created static binding (mac: %(mac)s, ip: %(ip)s, "
                      "gateway: %(gateway)s, options: %(options)s) for port "
                      "%(port)s on logical DHCP server %(server)s",
                      {'mac': port['mac_address'], 'ip': ip,
                       'gateway': gateway_ip, 'options': options,
                       'port': port['id'],
                       'server': dhcp_service_id})
            return binding
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to create static binding (mac: %(mac)s, "
                          "ip: %(ip)s, gateway: %(gateway)s, options: "
                          "%(options)s) for port %(port)s on logical DHCP "
                          "server %(server)s",
                          {'mac': port['mac_address'], 'ip': ip,
                           'gateway': gateway_ip, 'options': options,
                           'port': port['id'],
                           'server': dhcp_service_id})

    def _delete_dhcp_binding(self, context, port):
        # Do not check device_owner here because Nova may have already
        # deleted that before Neutron's port deletion.
        bindings = nsx_db.get_nsx_dhcp_bindings(context.session, port['id'])
        for binding in bindings:
            self._delete_dhcp_binding_on_server(context, binding)
            try:
                nsx_db.delete_neutron_nsx_dhcp_binding(
                    context.session, binding['port_id'],
                    binding['nsx_binding_id'])
            except db_exc.DBError:
                LOG.error("Unable to delete mapping of DHCP binding "
                          "%(binding)s for port %(port)s",
                          {'binding': binding['nsx_binding_id'],
                           'port': binding['port_id']})

    def _delete_dhcp_binding_on_server(self, context, binding):
        try:
            self.nsxlib.dhcp_server.delete_binding(
                binding['nsx_service_id'], binding['nsx_binding_id'])
            LOG.debug("Deleted static binding for port %(port)s) on "
                      "logical DHCP server %(server)s",
                      {'port': binding['port_id'],
                       'server': binding['nsx_service_id']})
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to delete static binding for port "
                          "%(port)s) on logical DHCP server %(server)s",
                          {'port': binding['port_id'],
                           'server': binding['nsx_service_id']})

    def _find_dhcp_binding(self, subnet_id, ip_address, bindings):
        for binding in bindings:
            if (subnet_id == binding['subnet_id'] and
                ip_address == binding['ip_address']):
                return binding

    def _update_dhcp_binding(self, context, old_port, new_port):
        # First check if any IPv4 address in fixed_ips is changed.
        # Then update DHCP server setting or DHCP static binding
        # depending on the port type.
        # Note that Neutron allows a port with multiple IPs in the
        # same subnet. But backend DHCP server may not support that.

        if (utils.is_port_dhcp_configurable(old_port) !=
            utils.is_port_dhcp_configurable(new_port)):
            # Note that the device_owner could be changed,
            # but still needs DHCP binding.
            if utils.is_port_dhcp_configurable(old_port):
                self._delete_dhcp_binding(context, old_port)
            else:
                self._add_dhcp_binding(context, new_port)
            return

        # Collect IPv4 DHCP addresses from original and updated fixed_ips
        # in the form of [(subnet_id, ip_address)].
        old_fixed_ips = set([(fixed_ip['subnet_id'], fixed_ip['ip_address'])
                             for fixed_ip in self._filter_ipv4_dhcp_fixed_ips(
                                 context, old_port['fixed_ips'])])
        new_fixed_ips = set([(fixed_ip['subnet_id'], fixed_ip['ip_address'])
                             for fixed_ip in self._filter_ipv4_dhcp_fixed_ips(
                                 context, new_port['fixed_ips'])])
        # Find out the subnet/IP differences before and after the update.
        ips_to_add = list(new_fixed_ips - old_fixed_ips)
        ips_to_delete = list(old_fixed_ips - new_fixed_ips)
        ip_change = (ips_to_add or ips_to_delete)

        if old_port["device_owner"] == const.DEVICE_OWNER_DHCP and ip_change:
            # Update backend DHCP server address if the IP address of a DHCP
            # port is changed.
            if len(new_fixed_ips) != 1:
                msg = _("Can only configure one IP address on a DHCP server")
                LOG.error(msg)
                raise n_exc.InvalidInput(error_message=msg)
            # Locate the backend DHCP server for this DHCP port.
            dhcp_service = nsx_db.get_nsx_service_binding(
                context.session, old_port['network_id'],
                nsxlib_consts.SERVICE_DHCP)
            if dhcp_service:
                new_ip = ips_to_add[0][1]
                try:
                    self.nsxlib.dhcp_server.update(
                        dhcp_service['nsx_service_id'],
                        server_ip=new_ip)
                    LOG.debug("Updated IP %(ip)s for logical DHCP server "
                              "%(server)s",
                              {'ip': new_ip,
                               'server': dhcp_service['nsx_service_id']})
                except nsx_lib_exc.ManagerError:
                    with excutils.save_and_reraise_exception():
                        LOG.error("Unable to update IP %(ip)s for logical "
                                  "DHCP server %(server)s",
                                  {'ip': new_ip,
                                   'server': dhcp_service['nsx_service_id']})
        elif utils.is_port_dhcp_configurable(old_port):
            # Update static DHCP bindings for a compute port.
            bindings = nsx_db.get_nsx_dhcp_bindings(context.session,
                                                    old_port['id'])
            dhcp_opts = new_port.get(ext_edo.EXTRADHCPOPTS)
            dhcp_opts_changed = (old_port[ext_edo.EXTRADHCPOPTS] !=
                                 new_port[ext_edo.EXTRADHCPOPTS])
            if ip_change:
                # If IP address is changed, update associated DHCP bindings,
                # metadata route, and default hostname.
                # Mac address (if changed) will be updated at the same time.
                if ([subnet_id for (subnet_id, ip) in ips_to_add] ==
                    [subnet_id for (subnet_id, ip) in ips_to_delete]):
                    # No change on subnet_id, just update corresponding IPs.
                    for i, (subnet_id, ip) in enumerate(ips_to_delete):
                        binding = self._find_dhcp_binding(subnet_id, ip,
                                                          bindings)
                        if binding:
                            subnet = self.get_subnet(context,
                                                     binding['subnet_id'])
                            self._update_dhcp_binding_on_server(
                                context, binding, new_port['mac_address'],
                                ips_to_add[i][1], old_port['network_id'],
                                dhcp_opts=dhcp_opts, subnet=subnet)
                            # Update DB IP
                            nsx_db.update_nsx_dhcp_bindings(context.session,
                                                            old_port['id'],
                                                            ip,
                                                            ips_to_add[i][1])
                else:
                    for (subnet_id, ip) in ips_to_delete:
                        binding = self._find_dhcp_binding(subnet_id, ip,
                                                          bindings)
                        if binding:
                            self._delete_dhcp_binding_on_server(context,
                                                                binding)
                    if ips_to_add:
                        dhcp_service = nsx_db.get_nsx_service_binding(
                            context.session, new_port['network_id'],
                            nsxlib_consts.SERVICE_DHCP)
                        if dhcp_service:
                            for (subnet_id, ip) in ips_to_add:
                                self._add_dhcp_binding_on_server(
                                    context, dhcp_service['nsx_service_id'],
                                    subnet_id, ip, new_port)
            elif (old_port['mac_address'] != new_port['mac_address'] or
                  dhcp_opts_changed):
                # If only Mac address/dhcp opts is changed,
                # update it in all associated DHCP bindings.
                for binding in bindings:
                    subnet = self.get_subnet(context, binding['subnet_id'])
                    self._update_dhcp_binding_on_server(
                        context, binding, new_port['mac_address'],
                        binding['ip_address'], old_port['network_id'],
                        dhcp_opts=dhcp_opts, subnet=subnet)

    def _update_dhcp_binding_on_server(self, context, binding, mac, ip,
                                       net_id, gateway_ip=False,
                                       dhcp_opts=None, options=None,
                                       subnet=None):
        try:
            data = {'mac_address': mac, 'ip_address': ip}
            if ip != binding['ip_address']:
                data['host_name'] = 'host-%s' % ip.replace('.', '-')
                data['options'] = self._get_dhcp_options(
                    context, ip, dhcp_opts, net_id,
                    subnet)
            elif (dhcp_opts is not None or
                  options is not None):
                data['options'] = self._get_dhcp_options(
                    context, ip, dhcp_opts, net_id,
                    subnet)
            if gateway_ip is not False:
                # Note that None is valid for gateway_ip, means deleting it.
                data['gateway_ip'] = gateway_ip

            self.nsxlib.dhcp_server.update_binding(
                binding['nsx_service_id'], binding['nsx_binding_id'], **data)
            LOG.debug("Updated static binding (mac: %(mac)s, ip: %(ip)s, "
                      "gateway: %(gateway)s) for port %(port)s on "
                      "logical DHCP server %(server)s",
                      {'mac': mac, 'ip': ip, 'gateway': gateway_ip,
                       'port': binding['port_id'],
                       'server': binding['nsx_service_id']})
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to update static binding (mac: %(mac)s, "
                          "ip: %(ip)s, gateway: %(gateway)s) for port "
                          "%(port)s on logical DHCP server %(server)s",
                          {'mac': mac, 'ip': ip, 'gateway': gateway_ip,
                           'port': binding['port_id'],
                           'server': binding['nsx_service_id']})

    def _update_lport_with_security_groups(self, context, lport_id,
                                           original, updated):
        # translate the neutron sg ids to nsx ids, and call nsxlib
        nsx_origial = nsx_db.get_nsx_security_group_ids(context.session,
                                                        original)
        nsx_updated = nsx_db.get_nsx_security_group_ids(context.session,
                                                        updated)
        self.nsxlib.ns_group.update_lport_nsgroups(
            lport_id, nsx_origial, nsx_updated)

    def base_create_port(self, context, port):
        neutron_db = super(NsxV3Plugin, self).create_port(context, port)
        self._extension_manager.process_create_port(
            context, port['port'], neutron_db)
        return neutron_db

    def _validate_ens_create_port(self, context, port_data):
        qos_selected = validators.is_attr_set(port_data.get(
            qos_consts.QOS_POLICY_ID))
        if qos_selected:
            err_msg = _("Cannot configure QOS on ENS networks")
            raise n_exc.InvalidInput(error_message=err_msg)

        if (cfg.CONF.nsx_v3.disable_port_security_for_ens and
            not self._ens_psec_supported()):
            LOG.warning("Disabling port security for network %s",
                        port_data['network_id'])
            port_data[psec.PORTSECURITY] = False
            port_data['security_groups'] = []

    def create_port(self, context, port, l2gw_port_check=False):
        port_data = port['port']

        # validate the new port parameters
        self._validate_create_port(context, port_data)
        # Add the plugin specific validations
        dhcp_opts = port_data.get(ext_edo.EXTRADHCPOPTS)
        self._validate_extra_dhcp_options(dhcp_opts)
        self._assert_on_dhcp_relay_without_router(context, port_data)
        is_ens_tz_port = self._is_ens_tz_port(context, port_data)
        if is_ens_tz_port:
            self._validate_ens_create_port(context, port_data)

        is_external_net = self._network_is_external(
            context, port_data['network_id'])

        direct_vnic_type = self._validate_port_vnic_type(
            context, port_data, port_data['network_id'],
            projectpluginmap.NsxPlugins.NSX_T)

        with db_api.CONTEXT_WRITER.using(context):
            neutron_db = self.base_create_port(context, port)
            port["port"].update(neutron_db)

            self.fix_direct_vnic_port_sec(direct_vnic_type, port_data)
            (is_psec_on, has_ip, sgids, psgids) = (
                self._create_port_preprocess_security(context, port,
                                                      port_data, neutron_db,
                                                      is_ens_tz_port))
            self._process_portbindings_create_and_update(
                context, port['port'], port_data,
                vif_type=self._vif_type_by_vnic_type(direct_vnic_type))
            self._process_port_create_extra_dhcp_opts(
                context, port_data, dhcp_opts)

            # handle adding security groups to port
            self._process_port_create_security_group(
                context, port_data, sgids)
            self._process_port_create_provider_security_group(
                context, port_data, psgids)
            # add provider groups to other security groups list.
            # sgids is a set() so we need to | it in.
            if psgids:
                sgids = list(set(sgids) | set(psgids))

            # Handle port mac learning
            if validators.is_attr_set(port_data.get(mac_ext.MAC_LEARNING)):
                # Make sure mac_learning and port sec are not both enabled
                if port_data.get(mac_ext.MAC_LEARNING) and is_psec_on:
                    msg = _('Mac learning requires that port security be '
                            'disabled')
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                if (is_ens_tz_port and not self._ens_psec_supported() and
                    not port_data.get(mac_ext.MAC_LEARNING)):
                    msg = _('Cannot disable Mac learning for ENS TZ')
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                # save the mac learning value in the DB
                self._create_mac_learning_state(context, port_data)
            elif mac_ext.MAC_LEARNING in port_data:
                # This is due to the fact that the default is
                # ATTR_NOT_SPECIFIED
                port_data.pop(mac_ext.MAC_LEARNING)
            # For a ENZ TZ mac learning is always enabled
            if (is_ens_tz_port and not self._ens_psec_supported() and
                mac_ext.MAC_LEARNING not in port_data):
                # Set the default and add to the DB
                port_data[mac_ext.MAC_LEARNING] = True
                self._create_mac_learning_state(context, port_data)

        # Operations to backend should be done outside of DB transaction.
        # NOTE(arosen): ports on external networks are nat rules and do
        # not result in ports on the backend.
        if not is_external_net:
            try:
                lport = self._create_port_at_the_backend(
                    context, port_data, l2gw_port_check, is_psec_on,
                    is_ens_tz_port)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error('Failed to create port %(id)s on NSX '
                              'backend. Exception: %(e)s',
                              {'id': neutron_db['id'], 'e': e})
                    self._cleanup_port(context, neutron_db['id'], None)

            if not self.nsxlib.feature_supported(
                nsxlib_consts.FEATURE_DYNAMIC_CRITERIA):
                try:
                    self._update_lport_with_security_groups(
                        context, lport['id'], [], sgids or [])
                except Exception as e:
                    with excutils.save_and_reraise_exception(reraise=False):
                        LOG.debug("Couldn't associate port %s with "
                                  "one or more security-groups, reverting "
                                  "logical-port creation (%s).",
                                  port_data['id'], lport['id'])
                        self._cleanup_port(
                            context, neutron_db['id'], lport['id'])

                    # NOTE(arosen): this is to translate between nsxlib
                    # exceptions and the plugin exceptions. This should be
                    # later refactored.
                    if (e.__class__ is
                            nsx_lib_exc.SecurityGroupMaximumCapacityReached):
                        raise nsx_exc.SecurityGroupMaximumCapacityReached(
                            err_msg=e.msg)
                    else:
                        raise e
            try:
                net_id = self._get_network_nsx_id(
                    context, port_data['network_id'])
                nsx_db.add_neutron_nsx_port_mapping(
                    context.session, neutron_db['id'],
                    net_id, lport['id'])
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.debug('Failed to update mapping %s on NSX '
                              'backend. Reverting port creation. '
                              'Exception: %s', neutron_db['id'], e)
                    self._cleanup_port(context, neutron_db['id'], lport['id'])

        # this extra lookup is necessary to get the
        # latest db model for the extension functions
        port_model = self._get_port(context, port_data['id'])
        resource_extend.apply_funcs('ports', port_data, port_model)
        self._extend_nsx_port_dict_binding(context, port_data)
        self._remove_provider_security_groups_from_list(port_data)

        # Add Mac/IP binding to native DHCP server and neutron DB.
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            try:
                self._add_dhcp_binding(context, port_data)
            except nsx_lib_exc.ManagerError:
                # Rollback create port
                self.delete_port(context, port_data['id'],
                                 force_delete_dhcp=True)
                msg = _('Unable to create port. Please contact admin')
                LOG.exception(msg)
                raise nsx_exc.NsxPluginException(err_msg=msg)

        if not cfg.CONF.nsx_v3.native_dhcp_metadata:
            nsx_rpc.handle_port_metadata_access(self, context, neutron_db)
        kwargs = {'context': context, 'port': neutron_db}
        registry.notify(resources.PORT, events.AFTER_CREATE, self, **kwargs)
        return port_data

    def _pre_delete_port_check(self, context, port_id, l2gw_port_check):
        """Perform checks prior to deleting a port."""
        try:
            kwargs = {
                'context': context,
                'port_check': l2gw_port_check,
                'port_id': port_id,
            }
            # Send delete port notification to any interested service plugin
            registry.notify(
                resources.PORT, events.BEFORE_DELETE, self, **kwargs)
        except callback_exc.CallbackFailure as e:
            if len(e.errors) == 1:
                raise e.errors[0].error
            raise n_exc.ServicePortInUse(port_id=port_id, reason=e)

    def delete_port(self, context, port_id,
                    l3_port_check=True, l2gw_port_check=True,
                    force_delete_dhcp=False,
                    force_delete_vpn=False):
        # if needed, check to see if this is a port owned by
        # a l2 gateway.  If so, we should prevent deletion here
        self._pre_delete_port_check(context, port_id, l2gw_port_check)
        # if needed, check to see if this is a port owned by
        # a l3 router.  If so, we should prevent deletion here
        if l3_port_check:
            self.prevent_l3_port_deletion(context, port_id)
        port = self.get_port(context, port_id)
        # Prevent DHCP port deletion if native support is enabled
        if (cfg.CONF.nsx_v3.native_dhcp_metadata and
            not force_delete_dhcp and
            port['device_owner'] in [const.DEVICE_OWNER_DHCP]):
            msg = (_('Can not delete DHCP port %s') % port['id'])
            raise n_exc.BadRequest(resource='port', msg=msg)
        if not force_delete_vpn:
            self._assert_on_vpn_port_change(port)
        if not self._network_is_external(context, port['network_id']):
            _net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            self.nsxlib.logical_port.delete(nsx_port_id)
            if not self.nsxlib.feature_supported(
                nsxlib_consts.FEATURE_DYNAMIC_CRITERIA):
                self._update_lport_with_security_groups(
                    context, nsx_port_id,
                    port.get(ext_sg.SECURITYGROUPS, []), [])
            if (not self.nsxlib.feature_supported(
                nsxlib_consts.FEATURE_EXCLUDE_PORT_BY_TAG) and
                self._is_excluded_port(port.get('device_owner'),
                                       port.get('port_security_enabled'))):
                fs = self.nsxlib.firewall_section
                try:
                    fs.remove_member_from_fw_exclude_list(
                        nsx_port_id, nsxlib_consts.TARGET_TYPE_LOGICAL_PORT)
                except Exception as e:
                    LOG.warning("Unable to remove port from exclude list. "
                                "Reason: %s", e)
        self.disassociate_floatingips(context, port_id)

        # Remove Mac/IP binding from native DHCP server and neutron DB.
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            self._delete_dhcp_binding(context, port)
        else:
            nsx_rpc.handle_port_metadata_access(self, context, port,
                                                is_delete=True)
        super(NsxV3Plugin, self).delete_port(context, port_id)

    def _get_resource_type_for_device_id(self, device_owner, device_id):
        if device_owner in const.ROUTER_INTERFACE_OWNERS:
            return 'os-router-uuid'
        elif device_owner.startswith(const.DEVICE_OWNER_COMPUTE_PREFIX):
            return 'os-instance-uuid'

    def _update_port_on_backend(self, context, lport_id,
                                original_port, updated_port,
                                address_bindings,
                                switch_profile_ids,
                                is_ens_tz_port):
        original_device_owner = original_port.get('device_owner')
        original_device_id = original_port.get('device_id')
        updated_device_owner = updated_port.get('device_owner')
        updated_device_id = updated_port.get('device_id')
        tags_update = []
        if original_device_id != updated_device_id:
            # Determine if we need to update or drop the tag. If the
            # updated_device_id exists then the tag will be updated. This
            # is done using the updated port. If the updated_device_id does
            # not exist then we need to get the original resource type
            # from original_device_owner. This enables us to drop the tag.
            if updated_device_id:
                resource_type = self._get_resource_type_for_device_id(
                    updated_device_owner, updated_device_id)
            else:
                resource_type = self._get_resource_type_for_device_id(
                    original_device_owner, updated_device_id)
            if resource_type:
                tags_update = nsxlib_utils.add_v3_tag(
                    tags_update, resource_type, updated_device_id)

        if updated_device_owner in (original_device_owner,
                                    l3_db.DEVICE_OWNER_ROUTER_INTF,
                                    nsxlib_consts.BRIDGE_ENDPOINT):
            # no attachment change
            attachment_type = False
            vif_uuid = False
        elif updated_device_owner:
            # default attachment
            attachment_type = nsxlib_consts.ATTACHMENT_VIF
            vif_uuid = updated_port['id']
        else:
            # no attachment
            attachment_type = None
            vif_uuid = None

        name = self._build_port_name(context, updated_port)

        # Update exclude list if necessary
        updated_ps = updated_port.get('port_security_enabled')
        updated_excluded = self._is_excluded_port(updated_device_owner,
                                                  updated_ps)
        original_ps = original_port.get('port_security_enabled')
        original_excluded = self._is_excluded_port(original_device_owner,
                                                   original_ps)
        if updated_excluded != original_excluded:
            if self.nsxlib.feature_supported(
                nsxlib_consts.FEATURE_EXCLUDE_PORT_BY_TAG):
                if updated_excluded:
                    tags_update.append({'scope': security.PORT_SG_SCOPE,
                                        'tag': nsxlib_consts.EXCLUDE_PORT})
                else:
                    tags_update.append({'scope': security.PORT_SG_SCOPE,
                                        'tag': None})
            else:
                fs = self.nsxlib.firewall_section
                if updated_excluded:
                    fs.add_member_to_fw_exclude_list(
                        lport_id, nsxlib_consts.TARGET_TYPE_LOGICAL_PORT)
                else:
                    fs.remove_member_from_fw_exclude_list(
                        lport_id, nsxlib_consts.TARGET_TYPE_LOGICAL_PORT)

        if self.nsxlib.feature_supported(
            nsxlib_consts.FEATURE_DYNAMIC_CRITERIA):
            tags_update += self.nsxlib.ns_group.get_lport_tags(
                updated_port.get(ext_sg.SECURITYGROUPS, []) +
                updated_port.get(provider_sg.PROVIDER_SECURITYGROUPS, []))
            # Only set the default section tag if there is no port security
            if not updated_excluded:
                tags_update.append({'scope': security.PORT_SG_SCOPE,
                                    'tag': NSX_V3_DEFAULT_SECTION})
            else:
                # Ensure that the 'exclude' tag is set
                if self.nsxlib.feature_supported(
                    nsxlib_consts.FEATURE_EXCLUDE_PORT_BY_TAG):
                    tags_update.append({'scope': security.PORT_SG_SCOPE,
                                        'tag': nsxlib_consts.EXCLUDE_PORT})
        else:
            self._update_lport_with_security_groups(
                context, lport_id,
                original_port.get(ext_sg.SECURITYGROUPS, []) +
                original_port.get(provider_sg.PROVIDER_SECURITYGROUPS, []),
                updated_port.get(ext_sg.SECURITYGROUPS, []) +
                updated_port.get(provider_sg.PROVIDER_SECURITYGROUPS, []))

        # Add availability zone profiles first (so that specific profiles will
        # override them)
        port_az = self.get_network_az_by_net_id(context,
                                                updated_port['network_id'])
        if port_az.switching_profiles_objs:
            switch_profile_ids = (port_az.switching_profiles_objs +
                                  switch_profile_ids)

        # Update the DHCP profile
        if (updated_device_owner == const.DEVICE_OWNER_DHCP and
            (not is_ens_tz_port or self._ens_psec_supported()) and
            not cfg.CONF.nsx_v3.native_dhcp_metadata):
            switch_profile_ids.append(self._dhcp_profile)

        # Update QoS switch profile
        orig_compute = original_device_owner.startswith(
            const.DEVICE_OWNER_COMPUTE_PREFIX)
        updated_compute = updated_device_owner.startswith(
            const.DEVICE_OWNER_COMPUTE_PREFIX)
        is_new_compute = updated_compute and not orig_compute
        qos_policy_id, qos_profile_id = self._get_port_qos_ids(context,
                                                               updated_port,
                                                               is_new_compute)
        if qos_profile_id is not None:
            switch_profile_ids.append(qos_profile_id)

        psec_is_on = self._get_port_security_profile_id() in switch_profile_ids

        address_pairs = updated_port.get(addr_apidef.ADDRESS_PAIRS)
        mac_learning_profile_set = (
            validators.is_attr_set(address_pairs) and address_pairs and
            psec_is_on)
        # Add mac_learning profile if it exists and is configured
        if ((not is_ens_tz_port or self._ens_psec_supported()) and
            self._mac_learning_profile and
            (mac_learning_profile_set or
             updated_port.get(mac_ext.MAC_LEARNING) is True)):
            switch_profile_ids.append(self._mac_learning_profile)
            if is_ens_tz_port:
                if self._no_switch_security_ens not in switch_profile_ids:
                    switch_profile_ids.append(self._no_switch_security_ens)
            else:
                if self._no_switch_security not in switch_profile_ids:
                    switch_profile_ids.append(self._no_switch_security)

        try:
            self.nsxlib.logical_port.update(
                lport_id, vif_uuid, name=name,
                attachment_type=attachment_type,
                admin_state=updated_port.get('admin_state_up'),
                address_bindings=address_bindings,
                switch_profile_ids=switch_profile_ids,
                tags_update=tags_update,
                description=updated_port.get('description'))
        except nsx_lib_exc.ManagerError as inst:
            # we may fail if the QoS is not supported for this port
            # (for example - transport zone with KVM)
            LOG.exception("Unable to update port on the backend: %s",
                          inst)
            msg = _("Unable to update port on the backend")
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # Attach/Detach the QoS policies to the port in the neutron DB
        qos_com_utils.update_port_policy_binding(context,
                                                 updated_port['id'],
                                                 qos_policy_id)

    def _get_port_qos_ids(self, context, updated_port, is_new_compute):
        # when a port is updated, get the current QoS policy/profile ids
        policy_id = None
        profile_id = None
        if (qos_consts.QOS_POLICY_ID in updated_port):
            policy_id = updated_port[qos_consts.QOS_POLICY_ID]
        else:
            # Look for the previous QoS policy
            policy_id = qos_com_utils.get_port_policy_id(
                context, updated_port['id'])
        # If the port is now a 'compute' port (attached to a vm) and
        # Qos policy was not configured on the port directly,
        # try to take it from the ports network
        if policy_id is None and is_new_compute:
            # check if the network of this port has a policy
            policy_id = qos_com_utils.get_network_policy_id(
                context, updated_port.get('network_id'))

        if policy_id is not None:
            profile_id = self._get_qos_profile_id(context, policy_id)

        return policy_id, profile_id

    def update_port(self, context, id, port):
        with db_api.CONTEXT_WRITER.using(context):
            # get the original port, and keep it honest as it is later used
            # for notifications
            original_port = super(NsxV3Plugin, self).get_port(context, id)
            self._extend_get_port_dict_qos_and_binding(context, original_port)
            self._remove_provider_security_groups_from_list(original_port)
            port_data = port['port']
            validate_port_sec = self._should_validate_port_sec_on_update_port(
                port_data)
            nsx_lswitch_id, nsx_lport_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, id)

            # Validate the changes
            self._validate_update_port(context, id, original_port, port_data)
            self._assert_on_dhcp_relay_without_router(context, port_data,
                                                      original_port)
            is_ens_tz_port = self._is_ens_tz_port(context, original_port)
            qos_selected = validators.is_attr_set(port_data.get
                                                  (qos_consts.QOS_POLICY_ID))
            if is_ens_tz_port and qos_selected:
                err_msg = _("Cannot configure QOS on ENS networks")
                raise n_exc.InvalidInput(error_message=err_msg)
            dhcp_opts = port_data.get(ext_edo.EXTRADHCPOPTS)
            self._validate_extra_dhcp_options(dhcp_opts)

            direct_vnic_type = self._validate_port_vnic_type(
                context, port_data, original_port['network_id'])

            # Update the neutron port
            updated_port = super(NsxV3Plugin, self).update_port(context,
                                                                id, port)
            self._extension_manager.process_update_port(context, port_data,
                                                        updated_port)
            # copy values over - except fixed_ips as
            # they've already been processed
            port_data.pop('fixed_ips', None)
            updated_port.update(port_data)

            updated_port = self._update_port_preprocess_security(
                context, port, id, updated_port, is_ens_tz_port,
                validate_port_sec=validate_port_sec,
                direct_vnic_type=direct_vnic_type)

            self._update_extra_dhcp_opts_on_port(context, id, port,
                                                 updated_port)
            sec_grp_updated = self.update_security_group_on_port(
                context, id, port, original_port, updated_port)

            self._process_port_update_provider_security_group(
                context, port, original_port, updated_port)

            (port_security, has_ip) = self._determine_port_security_and_has_ip(
                context, updated_port)
            self._process_portbindings_create_and_update(
                context, port_data, updated_port,
                vif_type=self._vif_type_by_vnic_type(direct_vnic_type))
            self._extend_nsx_port_dict_binding(context, updated_port)
            mac_learning_state = updated_port.get(mac_ext.MAC_LEARNING)
            if mac_learning_state is not None:
                if (not mac_learning_state and is_ens_tz_port and
                    not self._ens_psec_supported()):
                    msg = _('Mac learning cannot be disabled with ENS TZ')
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                if port_security and mac_learning_state:
                    msg = _('Mac learning requires that port security be '
                            'disabled')
                    LOG.error(msg)
                    raise n_exc.InvalidInput(error_message=msg)
                self._update_mac_learning_state(context, id,
                                                mac_learning_state)
            self._remove_provider_security_groups_from_list(updated_port)

        address_bindings = self._build_address_bindings(updated_port)
        if port_security and address_bindings:
            switch_profile_ids = [self._get_port_security_profile_id()]
        else:
            switch_profile_ids = [self._no_psec_profile_id]
            if is_ens_tz_port:
                switch_profile_ids.append(self._no_switch_security_ens)
            else:
                switch_profile_ids.append(self._no_switch_security)
            address_bindings = []

        # update the port in the backend, only if it exists in the DB
        # (i.e not external net)
        if nsx_lport_id is not None:
            try:
                self._update_port_on_backend(context, nsx_lport_id,
                                             original_port, updated_port,
                                             address_bindings,
                                             switch_profile_ids,
                                             is_ens_tz_port)
            except (nsx_lib_exc.ManagerError,
                    nsx_lib_exc.SecurityGroupMaximumCapacityReached) as e:
                # In case if there is a failure on NSX-v3 backend, rollback the
                # previous update operation on neutron side.
                LOG.exception("Unable to update NSX backend, rolling back "
                              "changes on neutron")
                with excutils.save_and_reraise_exception(reraise=False):
                    with db_api.CONTEXT_WRITER.using(context):
                        self._revert_neutron_port_update(
                            context, id, original_port, updated_port,
                            port_security, sec_grp_updated)
                    # NOTE(arosen): this is to translate between nsxlib
                    # exceptions and the plugin exceptions. This should be
                    # later refactored.
                    if (e.__class__ is
                            nsx_lib_exc.SecurityGroupMaximumCapacityReached):
                        raise nsx_exc.SecurityGroupMaximumCapacityReached(
                            err_msg=e.msg)
                    else:
                        raise e

        # Update DHCP bindings.
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            self._update_dhcp_binding(context, original_port, updated_port)

        # Make sure the port revision is updated
        if 'revision_number' in updated_port:
            port_model = self._get_port(context, id)
            updated_port['revision_number'] = port_model.revision_number

        # Notifications must be sent after the above transaction is complete
        kwargs = {
            'context': context,
            'port': updated_port,
            'mac_address_updated': False,
            'original_port': original_port,
        }

        registry.notify(resources.PORT, events.AFTER_UPDATE, self, **kwargs)
        return updated_port

    def _extend_get_port_dict_qos_and_binding(self, context, port):
        # Not using the register api for this because we need the context
        self._extend_nsx_port_dict_binding(context, port)

        # add the qos policy id from the DB
        if 'id' in port:
            port[qos_consts.QOS_POLICY_ID] = qos_com_utils.get_port_policy_id(
                context, port['id'])

    def get_port(self, context, id, fields=None):
        port = super(NsxV3Plugin, self).get_port(context, id, fields=None)
        if 'id' in port:
            port_model = self._get_port(context, port['id'])
            resource_extend.apply_funcs('ports', port, port_model)
        self._extend_get_port_dict_qos_and_binding(context, port)
        self._remove_provider_security_groups_from_list(port)
        return db_utils.resource_fields(port, fields)

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        filters = filters or {}
        self._update_filters_with_sec_group(context, filters)
        with db_api.CONTEXT_READER.using(context):
            ports = (
                super(NsxV3Plugin, self).get_ports(
                    context, filters, fields, sorts,
                    limit, marker, page_reverse))
            # Add port extensions
            for port in ports[:]:
                if 'id' in port:
                    try:
                        port_model = self._get_port(context, port['id'])
                        resource_extend.apply_funcs('ports', port, port_model)
                    except n_exc.PortNotFound:
                        # Port might have been deleted by now
                        LOG.debug("Port %s was deleted during the get_ports "
                                  "process, and is being skipped", port['id'])
                        ports.remove(port)
                        continue
                self._extend_get_port_dict_qos_and_binding(context, port)
                self._remove_provider_security_groups_from_list(port)
        return (ports if not fields else
                [db_utils.resource_fields(port, fields) for port in ports])

    def _get_tier0_uuid_by_net_id(self, context, network_id):
        if not network_id:
            return
        network = self.get_network(context, network_id)
        if not network.get(pnet.PHYSICAL_NETWORK):
            az = self.get_network_az_by_net_id(context, network_id)
            return az._default_tier0_router
        else:
            return network.get(pnet.PHYSICAL_NETWORK)

    def _get_tier0_uuid_by_router(self, context, router):
        network_id = router.gw_port_id and router.gw_port.network_id
        return self._get_tier0_uuid_by_net_id(context, network_id)

    def _validate_router_tz(self, context, tier0_uuid, subnets):
        # make sure the related GW (Tier0 router) belongs to the same TZ
        # as the subnets attached to the Tier1 router
        if not subnets:
            return
        tier0_tzs = self.nsxlib.router.get_tier0_router_tz(tier0_uuid)
        if not tier0_tzs:
            return
        for sub in subnets:
            tz_uuid = self._get_net_tz(context, sub['network_id'])
            if tz_uuid not in tier0_tzs:
                msg = (_("Tier0 router %(rtr)s transport zone should match "
                         "transport zone %(tz)s of the network %(net)s") % {
                    'rtr': tier0_uuid,
                    'tz': tz_uuid,
                    'net': sub['network_id']})
                raise n_exc.InvalidInput(error_message=msg)

    def state_firewall_rules(self, context, router_id):
        if self.fwaas_callbacks and self.fwaas_callbacks.fwaas_enabled:
            ports = self._get_router_interfaces(context, router_id)
            return self.fwaas_callbacks.router_with_fwg(context, ports)

    def verify_sr_at_backend(self, context, router_id):
        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        return self.nsxlib.router.has_service_router(nsx_router_id)

    def service_router_has_services(self, context, router_id):
        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        router = self._get_router(context, router_id)
        snat_exist = router.enable_snat
        lb_exist = nsx_db.has_nsx_lbaas_loadbalancer_binding_by_router(
            context.session, nsx_router_id)
        fw_exist = self.state_firewall_rules(context, router_id)
        if snat_exist or lb_exist or fw_exist:
            return True
        return snat_exist or lb_exist or fw_exist

    def create_service_router(self, context, router_id):
        router = self._get_router(context, router_id)
        tier0_uuid = self._get_tier0_uuid_by_router(context, router)
        edge_cluster_uuid = self._get_edge_cluster(tier0_uuid)
        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        self.nsxlib.router.update_router_edge_cluster(nsx_router_id,
                                                      edge_cluster_uuid)

    def delete_service_router(self, context, router_id):
        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        self.nsxlib.router.change_edge_firewall_status(
                    nsx_router_id, nsxlib_consts.FW_DISABLE)
        self.nsxlib.router.update_router_edge_cluster(nsx_router_id, None)

    def _update_router_gw_info(self, context, router_id, info):
        router = self._get_router(context, router_id)
        org_tier0_uuid = self._get_tier0_uuid_by_router(context, router)
        org_enable_snat = router.enable_snat
        orgaddr, orgmask, _orgnexthop = (
            self._get_external_attachment_info(
                context, router))

        self._validate_router_gw(context, router_id, info, org_enable_snat)

        router_subnets = self._find_router_subnets(
            context.elevated(), router_id)

        if info and info.get('network_id'):
            new_tier0_uuid = self._get_tier0_uuid_by_net_id(context.elevated(),
                                                            info['network_id'])
            if new_tier0_uuid:
                self._validate_router_tz(context, new_tier0_uuid,
                                         router_subnets)

        # TODO(berlin): For nonat use case, we actually don't need a gw port
        # which consumes one external ip. But after looking at the DB logic
        # and we need to make a big change so don't touch it at present.
        super(NsxV3Plugin, self)._update_router_gw_info(
            context, router_id, info, router=router)

        new_tier0_uuid = self._get_tier0_uuid_by_router(context, router)
        new_enable_snat = router.enable_snat
        newaddr, newmask, _newnexthop = (
            self._get_external_attachment_info(
                context, router))
        nsx_router_id = nsx_db.get_nsx_router_id(context.session, router_id)

        lb_exist = nsx_db.has_nsx_lbaas_loadbalancer_binding_by_router(
            context.session, nsx_router_id)
        fw_exist = self.state_firewall_rules(context, router_id)

        actions = self._get_update_router_gw_actions(
            org_tier0_uuid, orgaddr, org_enable_snat,
            new_tier0_uuid, newaddr, new_enable_snat, lb_exist, fw_exist)

        if actions['add_service_router']:
            self.create_service_router(context, router_id)

        if actions['revocate_bgp_announce']:

            # TODO(berlin): revocate bgp announce on org tier0 router
            pass
        if actions['remove_snat_rules']:
            self.nsxlib.router.delete_gw_snat_rules(nsx_router_id, orgaddr)

        if actions['remove_no_dnat_rules']:
            for subnet in router_subnets:
                self._del_subnet_no_dnat_rule(context, nsx_router_id, subnet)
        if actions['remove_router_link_port']:
            # remove the link port and reset the router transport zone
            self.nsxlib.router.remove_router_link_port(nsx_router_id)
            if self.nsxlib.feature_supported(
                nsxlib_consts.FEATURE_ROUTER_TRANSPORT_ZONE):
                self.nsxlib.router.update_router_transport_zone(
                    nsx_router_id, None)
        if actions['add_router_link_port']:
            # Add the overlay transport zone to the router config
            if self.nsxlib.feature_supported(
                    nsxlib_consts.FEATURE_ROUTER_TRANSPORT_ZONE):
                tz_uuid = self.nsxlib.router.get_tier0_router_overlay_tz(
                    new_tier0_uuid)
                if tz_uuid:
                    self.nsxlib.router.update_router_transport_zone(
                        nsx_router_id, tz_uuid)
            tags = self.nsxlib.build_v3_tags_payload(
                    router, resource_type='os-neutron-rport',
                    project_name=context.tenant_name)
            self.nsxlib.router.add_router_link_port(nsx_router_id,
                                                    new_tier0_uuid,
                                                    tags=tags)
        if actions['add_snat_rules']:
            # Add SNAT rules for all the subnets which are in different scope
            # than the gw
            gw_address_scope = self._get_network_address_scope(
                context, router.gw_port.network_id)
            for subnet in router_subnets:
                self._add_subnet_snat_rule(context, router_id, nsx_router_id,
                                           subnet, gw_address_scope, newaddr)
        if actions['add_no_dnat_rules']:
            for subnet in router_subnets:
                self._add_subnet_no_dnat_rule(context, nsx_router_id, subnet)

        if actions['bgp_announce']:
            # TODO(berlin): bgp announce on new tier0 router
            pass

        self.nsxlib.router.update_advertisement(
            nsx_router_id,
            actions['advertise_route_nat_flag'],
            actions['advertise_route_connected_flag'])

        if actions['remove_service_router']:
            self.delete_service_router(context, router_id)

    def _add_subnet_snat_rule(self, context, router_id, nsx_router_id, subnet,
                              gw_address_scope, gw_ip):
        # if the subnets address scope is the same as the gateways:
        # no need for SNAT
        if gw_address_scope:
            subnet_address_scope = self._get_subnetpool_address_scope(
                context, subnet['subnetpool_id'])
            if (gw_address_scope == subnet_address_scope):
                LOG.info("No need for SNAT rule for router %(router)s "
                         "and subnet %(subnet)s because they use the "
                         "same address scope %(addr_scope)s.",
                         {'router': router_id,
                          'subnet': subnet['id'],
                          'addr_scope': gw_address_scope})
                return

        self.nsxlib.router.add_gw_snat_rule(nsx_router_id, gw_ip,
                                            source_net=subnet['cidr'],
                                            bypass_firewall=False)

    def _add_subnet_no_dnat_rule(self, context, nsx_router_id, subnet):
        # Add NO-DNAT rule to allow internal traffic between VMs, even if
        # they have floating ips (Only for routers with snat enabled)
        if self.nsxlib.feature_supported(
            nsxlib_consts.FEATURE_NO_DNAT_NO_SNAT):
            self.nsxlib.logical_router.add_nat_rule(
                nsx_router_id, "NO_DNAT", None,
                dest_net=subnet['cidr'],
                rule_priority=nsxlib_router.GW_NAT_PRI)

    def _del_subnet_no_dnat_rule(self, context, nsx_router_id, subnet):
        # Delete the previously created NO-DNAT rules
        if self.nsxlib.feature_supported(
            nsxlib_consts.FEATURE_NO_DNAT_NO_SNAT):
            self.nsxlib.logical_router.delete_nat_rule_by_values(
                nsx_router_id,
                action="NO_DNAT",
                match_destination_network=subnet['cidr'])

    def validate_router_dhcp_relay(self, context):
        """Fail router creation dhcp relay is configured without IPAM"""
        if (self._availability_zones_data.dhcp_relay_configured() and
            cfg.CONF.ipam_driver == 'internal'):
            err_msg = _("Neutron is configured with DHCP_Relay but no IPAM "
                        "plugin configured")
            LOG.warning(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)

    def create_router(self, context, router):
        r = router['router']
        self.validate_router_dhcp_relay(context)

        # validate the availability zone
        if az_def.AZ_HINTS in r:
            self._validate_availability_zones_forced(context, 'router',
                                                     r[az_def.AZ_HINTS])

        gw_info = self._extract_external_gw(context, router, is_extract=True)
        r['id'] = (r.get('id') or uuidutils.generate_uuid())
        tags = self.nsxlib.build_v3_tags_payload(
            r, resource_type='os-neutron-router-id',
            project_name=context.tenant_name)
        router = super(NsxV3Plugin, self).create_router(context, router)
        if az_def.AZ_HINTS in r:
            # Update the AZ hints in the neutron object
            az_hints = az_validator.convert_az_list_to_string(
                r[az_def.AZ_HINTS])
            super(NsxV3Plugin, self).update_router(
                context,
                router['id'],
                {'router': {az_def.AZ_HINTS: az_hints}})
        router_db = self._get_router(context, r['id'])
        with db_api.CONTEXT_WRITER.using(context):
            self._process_extra_attr_router_create(context, router_db, r)
        # Create backend entries here in case neutron DB exception
        # occurred during super.create_router(), which will cause
        # API retry and leaves dangling backend entries.
        try:
            result = self.nsxlib.logical_router.create(
                display_name=utils.get_name_and_uuid(
                    router['name'] or 'router', router['id']),
                description=router.get('description'),
                tags=tags)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to create logical router for "
                          "neutron router %s", router['id'])
                self.delete_router(context, router['id'])

        try:
            nsx_db.add_neutron_nsx_router_mapping(
                context.session, router['id'], result['id'])
        except db_exc.DBError:
            with excutils.save_and_reraise_exception():
                LOG.error("Unable to create router mapping for "
                          "router %s", router['id'])
                self.delete_router(context, router['id'])

        if gw_info and gw_info != const.ATTR_NOT_SPECIFIED:
            try:
                self._update_router_gw_info(context, router['id'], gw_info)
            except (db_exc.DBError, nsx_lib_exc.ManagerError):
                with excutils.save_and_reraise_exception():
                    LOG.error("Failed to set gateway info for router "
                              "being created: %s - removing router",
                              router['id'])
                    self.delete_router(context, router['id'])
                    LOG.info("Create router failed while setting external "
                             "gateway. Router:%s has been removed from "
                             "DB and backend",
                             router['id'])
        return self.get_router(context, router['id'])

    def delete_router(self, context, router_id):
        if not cfg.CONF.nsx_v3.native_dhcp_metadata:
            nsx_rpc.handle_router_metadata_access(self, context, router_id,
                                                  interface=None)
        router = self.get_router(context, router_id)
        if router.get(l3_apidef.EXTERNAL_GW_INFO):
            self._update_router_gw_info(context, router_id, {})
        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router_id)
        ret_val = super(NsxV3Plugin, self).delete_router(context,
                                                         router_id)
        # if delete was called due to create error, there might not be a
        # backend id
        if not nsx_router_id:
            return ret_val

        # Remove logical router from the NSX backend
        # It is safe to do now as db-level checks for resource deletion were
        # passed (and indeed the resource was removed from the Neutron DB
        try:
            self.nsxlib.logical_router.delete(nsx_router_id, force=True)
        except nsx_lib_exc.ResourceNotFound:
            # If the logical router was not found on the backend do not worry
            # about it. The conditions has already been logged, so there is no
            # need to do further logging
            pass
        except nsx_lib_exc.ManagerError:
            # if there is a failure in deleting the router do not fail the
            # operation, especially since the router object has already been
            # removed from the neutron DB. Take corrective steps to ensure the
            # resulting zombie object does not forward any traffic and is
            # eventually removed.
            LOG.warning("Backend router deletion for neutron router %s "
                        "failed. The object was however removed from the "
                        "Neutron database", router_id)

        return ret_val

    def get_router_availability_zones(self, router):
        """Return availability zones which a router belongs to."""
        # add the hints to the structure first
        l3_attrs_db.ExtraAttributesMixin._extend_extra_router_dict(
            router, router)
        # get the availability zones from the hints
        return [self.get_router_az(router).name]

    def _update_router_wrapper(self, context, router_id, router):
        if cfg.CONF.api_replay_mode:
            # NOTE(arosen): the mock.patch here is needed for api_replay_mode
            with mock.patch("neutron.plugins.common.utils._fixup_res_dict",
                            side_effect=api_replay_utils._fixup_res_dict):
                return super(NsxV3Plugin, self).update_router(
                    context, router_id, router)
        else:
            return super(NsxV3Plugin, self).update_router(
                context, router_id, router)

    def update_router(self, context, router_id, router):
        gw_info = self._extract_external_gw(context, router, is_extract=False)
        router_data = router['router']
        self._assert_on_router_admin_state(router_data)

        if validators.is_attr_set(gw_info):
            self._validate_update_router_gw(context, router_id, gw_info)
            router_ports = self._get_router_interfaces(context, router_id)
            for port in router_ports:
                # if setting this router as no-snat, make sure gw address scope
                # match those of the subnets
                if not gw_info.get('enable_snat',
                                   cfg.CONF.enable_snat_by_default):
                    for fip in port['fixed_ips']:
                        self._validate_address_scope_for_router_interface(
                            context.elevated(), router_id,
                            gw_info['network_id'], fip['subnet_id'])
                # If the network attached to a router is a VLAN backed network
                # then it must be attached to an edge cluster
                if (not gw_info and
                    not self._is_overlay_network(context, port['network_id'])):
                    msg = _("A router attached to a VLAN backed network "
                            "must have an external network assigned")
                    raise n_exc.InvalidInput(error_message=msg)

            # VPNaaS need to be notified on router GW changes (there is
            # currently no matching upstream registration for this)
            vpn_plugin = directory.get_plugin(plugin_const.VPN)
            if vpn_plugin:
                vpn_driver = vpn_plugin.drivers[vpn_plugin.default_provider]
                vpn_driver.validate_router_gw_info(context, router_id, gw_info)

        nsx_router_id = None
        routes_added = []
        routes_removed = []
        try:
            if 'routes' in router_data:
                routes_added, routes_removed = self._get_static_routes_diff(
                    context, router_id, gw_info, router_data)
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         router_id)
                for route in routes_removed:
                    self.nsxlib.router.delete_static_routes(nsx_router_id,
                                                            route)
                for route in routes_added:
                    self.nsxlib.router.add_static_routes(nsx_router_id, route)
            if 'name' in router_data:
                # Update the name of logical router.
                router_name = router_data['name'] or 'router'
                display_name = utils.get_name_and_uuid(router_name, router_id)
                nsx_router_id = nsx_router_id or nsx_db.get_nsx_router_id(
                    context.session, router_id)
                self.nsxlib.logical_router.update(nsx_router_id,
                                                  display_name=display_name)
                # Update the name of associated logical ports.
                filters = {'device_id': [router_id],
                           'device_owner': const.ROUTER_INTERFACE_OWNERS}
                ports = self.get_ports(context, filters=filters)
                for port in ports:
                    nsx_s_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                        context.session, port['id'])
                    if nsx_port_id:
                        name = utils.get_name_and_uuid(
                            router_name, port['id'], tag='port')
                        try:
                            self.nsxlib.logical_port.update(nsx_port_id, None,
                                                            name=name)
                        except Exception as e:
                            LOG.error("Unable to update port %(port_id)s. "
                                      "Reason: %(e)s",
                                      {'port_id': nsx_port_id,
                                       'e': e})
            if 'description' in router_data:
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         router_id)
                self.nsxlib.logical_router.update(
                    nsx_router_id,
                    description=router_data['description'])

            return self._update_router_wrapper(context, router_id, router)
        except nsx_lib_exc.ResourceNotFound:
            with db_api.CONTEXT_WRITER.using(context):
                router_db = self._get_router(context, router_id)
                router_db['status'] = const.NET_STATUS_ERROR
            raise nsx_exc.NsxPluginException(
                err_msg=(_("logical router %s not found at the backend")
                         % router_id))
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                router_db = self._get_router(context, router_id)
                curr_status = router_db['status']
                router_db['status'] = const.NET_STATUS_ERROR
                if nsx_router_id:
                    for route in routes_added:
                        self.nsxlib.router.delete_static_routes(
                            nsx_router_id, route)
                    for route in routes_removed:
                        self.nsxlib.router.add_static_routes(nsx_router_id,
                                                             route)
                router_db['status'] = curr_status

    def _get_nsx_router_and_fw_section(self, context, router_id):
        # find the backend router id in the DB
        nsx_router_id = nsx_db.get_nsx_router_id(context.session, router_id)
        if nsx_router_id is None:
            msg = _("Didn't find nsx router for router %s") % router_id
            LOG.error(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        # get the FW section id of the backend router
        try:
            section_id = self.nsxlib.logical_router.get_firewall_section_id(
                nsx_router_id)
        except Exception as e:
            msg = (_("Failed to find router firewall section for router "
                     "%(id)s: %(e)s") % {'id': router_id, 'e': e})
            LOG.error(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)
        if section_id is None:
            msg = (_("Failed to find router firewall section for router "
                     "%(id)s.") % {'id': router_id})
            LOG.error(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return nsx_router_id, section_id

    def update_router_firewall(self, context, router_id, from_fw=False):
        """Rewrite all the rules in the router edge firewall

        This method should be called on FWaaS v1/v2 updates, and on router
        interfaces changes.
        When FWaaS is disabled, there is no need to update the NSX router FW,
        as the default rule is allow-all.
        """
        if (self.fwaas_callbacks and
            self.fwaas_callbacks.fwaas_enabled):
            # find all the relevant ports of the router for FWaaS v2
            # TODO(asarfaty): Add vm ports as well
            ports = self._get_router_interfaces(context, router_id)

            nsx_router_id, section_id = self._get_nsx_router_and_fw_section(
                context, router_id)
            # let the fwaas callbacks update the router FW
            return self.fwaas_callbacks.update_router_firewall(
                context, self.nsxlib, router_id, ports,
                nsx_router_id, section_id, from_fw=from_fw)

    def _get_port_relay_servers(self, context, port_id, network_id=None):
        if not network_id:
            port = self.get_port(context, port_id)
            network_id = port['network_id']
        net_az = self.get_network_az_by_net_id(context, network_id)
        return net_az.dhcp_relay_servers

    def _get_port_relay_services(self):
        # DHCP services: UDP 67, 68, 2535
        #TODO(asarfaty): use configurable ports
        service1 = self.nsxlib.firewall_section.get_nsservice(
            nsxlib_consts.L4_PORT_SET_NSSERVICE,
            l4_protocol=nsxlib_consts.UDP,
            destination_ports=['67-68'])
        service2 = self.nsxlib.firewall_section.get_nsservice(
            nsxlib_consts.L4_PORT_SET_NSSERVICE,
            l4_protocol=nsxlib_consts.UDP,
            destination_ports=['2535'])
        return [service1, service2]

    def get_extra_fw_rules(self, context, router_id, port_id=None):
        """Return firewall rules that should be added to the router firewall

        This method should return a list of allow firewall rules that are
        required in order to enable different plugin features with north/south
        traffic.
        The returned rules will be added after the FWaaS rules, and before the
        default drop rule.
        if port_id is specified, only rules relevant for this router interface
        port should be returned, and the rules should be ingress/egress
        (but not both) and include the source/dest nsx logical port.
        """
        extra_rules = []

        # DHCP relay rules:
        # get the list of relevant relay servers
        elv_ctx = context.elevated()
        if port_id:
            relay_servers = self._get_port_relay_servers(elv_ctx, port_id)
        else:
            relay_servers = []
            filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                       'device_id': [router_id]}
            ports = self.get_ports(elv_ctx, filters=filters)
            for port in ports:
                port_relay_servers = self._get_port_relay_servers(
                    elv_ctx, port['id'], network_id=port['network_id'])
                if port_relay_servers:
                    relay_servers.extend(port_relay_servers)

        # Add rules to allow dhcp traffic relay servers
        if relay_servers:
            # if it is a single port, the source/dest is this logical switch
            if port_id:
                nsx_ls_id, _nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                    context.session, port_id)
                port_target = [{'target_type': 'LogicalSwitch',
                                'target_id': nsx_ls_id}]
            else:
                port_target = None
            # translate the relay server ips to the firewall format
            relay_target = []
            if self.fwaas_callbacks:
                relay_target = (self.fwaas_callbacks.fwaas_driver.
                    translate_addresses_to_target(set(relay_servers)))

            dhcp_services = self._get_port_relay_services()

            # ingress rule
            extra_rules.append({
                'display_name': "DHCP Relay ingress traffic",
                'action': nsxlib_consts.FW_ACTION_ALLOW,
                'sources': relay_target,
                'destinations': port_target,
                'services': dhcp_services,
                'direction': 'IN'})
            # egress rule
            extra_rules.append({
                'display_name': "DHCP Relay egress traffic",
                'action': nsxlib_consts.FW_ACTION_ALLOW,
                'destinations': relay_target,
                'sources': port_target,
                'services': dhcp_services,
                'direction': 'OUT'})

        # VPN rules:
        vpn_plugin = directory.get_plugin(plugin_const.VPN)
        if vpn_plugin:
            vpn_driver = vpn_plugin.drivers[vpn_plugin.default_provider]
            vpn_rules = (
                vpn_driver._generate_ipsecvpn_firewall_rules(
                    self.plugin_type(), context, router_id=router_id))
            if vpn_rules:
                extra_rules.extend(vpn_rules)

        return extra_rules

    def _get_ports_and_address_groups(self, context, router_id, network_id,
                                      exclude_sub_ids=None):
        exclude_sub_ids = [] if not exclude_sub_ids else exclude_sub_ids
        address_groups = []
        ports = self._get_router_interface_ports_by_network(
            context, router_id, network_id)
        ports = [port for port in ports
                 if port['fixed_ips'] and
                 port['fixed_ips'][0]['subnet_id'] not in exclude_sub_ids]
        for port in ports:
            address_group = {}
            gateway_ip = port['fixed_ips'][0]['ip_address']
            subnet = self.get_subnet(context,
                                     port['fixed_ips'][0]['subnet_id'])
            prefixlen = str(netaddr.IPNetwork(subnet['cidr']).prefixlen)
            address_group['ip_addresses'] = [gateway_ip]
            address_group['prefix_length'] = prefixlen
            address_groups.append(address_group)
        return (ports, address_groups)

    def _validate_multiple_subnets_routers(self, context, router_id, net_id):
        network = self.get_network(context, net_id)
        net_type = network.get(pnet.NETWORK_TYPE)
        if (net_type and
            not self.nsxlib.feature_supported(
                nsxlib_consts.FEATURE_VLAN_ROUTER_INTERFACE) and
            not self._is_overlay_network(context, net_id)):
            err_msg = (_("Only overlay networks can be attached to a logical "
                         "router. Network %(net_id)s is a %(net_type)s based "
                         "network") % {'net_id': net_id, 'net_type': net_type})
            LOG.error(err_msg)
            raise n_exc.InvalidInput(error_message=err_msg)
        # Unable to attach a trunked network to a router interface
        if cfg.CONF.vlan_transparent:
            if network.get('vlan_transparent') is True:
                err_msg = (_("Transparent VLAN networks cannot be attached to "
                             "a logical router."))
                LOG.error(err_msg)
                raise n_exc.InvalidInput(error_message=err_msg)
        port_filters = {'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF],
                        'network_id': [net_id]}
        intf_ports = self.get_ports(context.elevated(), filters=port_filters)
        router_ids = [port['device_id']
                      for port in intf_ports if port['device_id']]
        if len(router_ids) > 0:
            err_msg = _("Only one subnet of network %(net_id)s can be "
                        "attached to router, one subnet is already attached "
                        "to router %(router_id)s") % {
                'net_id': net_id,
                'router_id': router_ids[0]}
            LOG.error(err_msg)
            if router_id in router_ids:
                # attach to the same router again
                raise n_exc.InvalidInput(error_message=err_msg)
            else:
                # attach to multiple routers
                raise l3_exc.RouterInterfaceAttachmentConflict(reason=err_msg)

    def _add_router_interface_wrapper(self, context, router_id,
                                      interface_info):
        if cfg.CONF.api_replay_mode:
            # NOTE(arosen): the mock.patch here is needed for api_replay_mode
            with mock.patch("neutron.plugins.common.utils._fixup_res_dict",
                            side_effect=api_replay_utils._fixup_res_dict):
                return super(NsxV3Plugin, self).add_router_interface(
                    context, router_id, interface_info)
        else:
            return super(NsxV3Plugin, self).add_router_interface(
                 context, router_id, interface_info)

    def add_router_interface(self, context, router_id, interface_info):
        network_id = self._get_interface_network(context, interface_info)
        extern_net = self._network_is_external(context, network_id)
        overlay_net = self._is_overlay_network(context, network_id)
        router_db = self._get_router(context, router_id)
        gw_network_id = (router_db.gw_port.network_id if router_db.gw_port
                         else None)
        with locking.LockManager.get_lock(str(network_id)):
            # disallow more than one subnets belong to same network being
            # attached to routers
            self._validate_multiple_subnets_routers(
                context, router_id, network_id)

            # A router interface cannot be an external network
            if extern_net:
                msg = _("An external network cannot be attached as "
                        "an interface to a router")
                raise n_exc.InvalidInput(error_message=msg)

            # Non overlay networks should be configured with a centralized
            # router, which is allowed only if GW network is attached
            if not overlay_net and not gw_network_id:
                msg = _("A router attached to a VLAN backed network "
                        "must have an external network assigned")
                raise n_exc.InvalidInput(error_message=msg)

            # Update the interface of the neutron router
            info = self._add_router_interface_wrapper(context, router_id,
                                                      interface_info)
        try:
            subnet = self.get_subnet(context, info['subnet_ids'][0])
            port = self.get_port(context, info['port_id'])
            nsx_net_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port['id'])

            # If it is a no-snat router, interface address scope must be the
            # same as the gateways
            self._validate_interface_address_scope(context, router_db, info)

            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     router_id)
            _ports, address_groups = self._get_ports_and_address_groups(
                context, router_id, network_id)
            display_name = utils.get_name_and_uuid(
                subnet['name'] or 'subnet', subnet['id'])
            tags = self.nsxlib.build_v3_tags_payload(
                port, resource_type='os-neutron-rport-id',
                project_name=context.tenant_name)
            tags.append({'scope': 'os-subnet-id', 'tag': subnet['id']})

            # Add the dhcp relay service to the NSX interface
            relay_service = None
            if subnet['enable_dhcp']:
                net_az = self.get_network_az_by_net_id(context, network_id)
                relay_service = net_az.dhcp_relay_service

            resource_type = (None if overlay_net else
                             nsxlib_consts.LROUTERPORT_CENTRALIZED)

            # IF this is an ENS case - check GW & subnets
            subnets = self._find_router_subnets(context.elevated(),
                                                router_id)
            tier0_uuid = self._get_tier0_uuid_by_router(context.elevated(),
                                                        router_db)
            self._validate_router_tz(context.elevated(), tier0_uuid, subnets)

            # create the interface ports on the NSX
            self.nsxlib.router.create_logical_router_intf_port_by_ls_id(
                logical_router_id=nsx_router_id,
                display_name=display_name,
                tags=tags,
                ls_id=nsx_net_id,
                logical_switch_port_id=nsx_port_id,
                address_groups=address_groups,
                relay_service_uuid=relay_service,
                resource_type=resource_type)

            if router_db.gw_port and not router_db.enable_snat:
                # TODO(berlin): Announce the subnet on tier0 if enable_snat
                # is False
                pass
            if not cfg.CONF.nsx_v3.native_dhcp_metadata:
                # Ensure the NSX logical router has a connection to a
                # 'metadata access' network (with a proxy listening on
                # its DHCP port), by creating it if needed.
                nsx_rpc.handle_router_metadata_access(self, context, router_id,
                                                      interface=info)

            # add the SNAT/NO_DNAT rules for this interface
            if router_db.enable_snat and gw_network_id:
                if router_db.gw_port.get('fixed_ips'):
                    gw_ip = router_db.gw_port['fixed_ips'][0]['ip_address']
                    gw_address_scope = self._get_network_address_scope(
                        context, gw_network_id)
                    self._add_subnet_snat_rule(
                        context, router_id, nsx_router_id,
                        subnet, gw_address_scope, gw_ip)
                self._add_subnet_no_dnat_rule(context, nsx_router_id, subnet)

            # update firewall rules
            self.update_router_firewall(context, router_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error("Neutron failed to add_router_interface on "
                          "router %s, and would try to rollback.",
                          router_id)
                try:
                    self.remove_router_interface(
                        context, router_id, interface_info)
                except Exception:
                    # rollback also failed
                    LOG.error("Neutron rollback failed to remove router "
                              "interface on router %s.", router_id)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        subnet = None
        subnet_id = None
        port_id = None
        self._validate_interface_info(interface_info, for_removal=True)
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            # find subnet_id - it is need for removing the SNAT rule
            port = self._get_port(context, port_id)
            if port.get('fixed_ips'):
                subnet_id = port['fixed_ips'][0]['subnet_id']
                self._confirm_router_interface_not_in_use(
                    context, router_id, subnet_id)
            if not (port['device_owner'] in const.ROUTER_INTERFACE_OWNERS and
                    port['device_id'] == router_id):
                raise l3_exc.RouterInterfaceNotFound(
                    router_id=router_id, port_id=port_id)
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            self._confirm_router_interface_not_in_use(
                context, router_id, subnet_id)
            subnet = self._get_subnet(context, subnet_id)
            rport_qry = context.session.query(models_v2.Port)
            ports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF,
                network_id=subnet['network_id'])
            for p in ports:
                if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                    port_id = p['id']
                    break
            else:
                raise l3_exc.RouterInterfaceNotFoundForSubnet(
                    router_id=router_id, subnet_id=subnet_id)
        try:
            # TODO(berlin): Revocate announce the subnet on tier0 if
            # enable_snat is False
            router_db = self._get_router(context, router_id)
            if router_db.gw_port and not router_db.enable_snat:
                pass

            nsx_net_id, _nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                context.session, port_id)
            subnet = self.get_subnet(context, subnet_id)
            ports, address_groups = self._get_ports_and_address_groups(
                context, router_id, subnet['network_id'],
                exclude_sub_ids=[subnet['id']])
            nsx_router_id = nsx_db.get_nsx_router_id(
                context.session, router_id)
            if len(ports) >= 1:
                new_using_port_id = ports[0]['id']
                _net_id, new_nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
                    context.session, new_using_port_id)
                self.nsxlib.logical_router_port.update_by_lswitch_id(
                    nsx_router_id, nsx_net_id,
                    linked_logical_switch_port_id={
                        'target_id': new_nsx_port_id},
                    subnets=address_groups)
            else:
                self.nsxlib.logical_router_port.delete_by_lswitch_id(
                    nsx_net_id)
            # try to delete the SNAT/NO_DNAT rules of this subnet
            if router_db.gw_port and router_db.enable_snat:
                if router_db.gw_port.get('fixed_ips'):
                    gw_ip = router_db.gw_port['fixed_ips'][0]['ip_address']
                    self.nsxlib.router.delete_gw_snat_rule_by_source(
                        nsx_router_id, gw_ip, subnet['cidr'],
                        skip_not_found=True)
                self._del_subnet_no_dnat_rule(context, nsx_router_id, subnet)

        except nsx_lib_exc.ResourceNotFound:
            LOG.error("router port on router %(router_id)s for net "
                      "%(net_id)s not found at the backend",
                      {'router_id': router_id,
                       'net_id': subnet['network_id']})

        # inform the FWaaS that interface port was removed
        if self.fwaas_callbacks:
            self.fwaas_callbacks.delete_port(context, port_id)

        info = super(NsxV3Plugin, self).remove_router_interface(
            context, router_id, interface_info)
        if not cfg.CONF.nsx_v3.native_dhcp_metadata:
            # Ensure the connection to the 'metadata access network' is removed
            # (with the network) if this is the last DHCP-disabled subnet on
            # the router.
            nsx_rpc.handle_router_metadata_access(self, context, router_id)

        # update firewall rules
        self.update_router_firewall(context, router_id)

        return info

    def _update_lb_vip(self, port, vip_address):
        # update the load balancer virtual server's VIP with
        # floating ip, but don't add NAT rules
        device_id = port['device_id']
        lb_tag = [{'scope': 'os-lbaas-lb-id', 'tag': device_id}]
        vs_list = self.nsxlib.search_by_tags(
            tags=lb_tag, resource_type='LbVirtualServer')
        if vs_list['results']:
            vs_client = self.nsxlib.load_balancer.virtual_server
            for vs in vs_list['results']:
                vs_client.update_virtual_server_with_vip(vs['id'],
                                                         vip_address)

    def _create_floating_ip_wrapper(self, context, floatingip):
        if cfg.CONF.api_replay_mode:
            # NOTE(arosen): the mock.patch here is needed for api_replay_mode
            with mock.patch("neutron.plugins.common.utils._fixup_res_dict",
                            side_effect=api_replay_utils._fixup_res_dict):
                return super(NsxV3Plugin, self).create_floatingip(
                    context, floatingip, initial_status=(
                        const.FLOATINGIP_STATUS_ACTIVE
                        if floatingip['floatingip']['port_id']
                        else const.FLOATINGIP_STATUS_DOWN))
        else:
            return super(NsxV3Plugin, self).create_floatingip(
                context, floatingip, initial_status=(
                    const.FLOATINGIP_STATUS_ACTIVE
                    if floatingip['floatingip']['port_id']
                    else const.FLOATINGIP_STATUS_DOWN))

    def create_floatingip(self, context, floatingip):
        new_fip = self._create_floating_ip_wrapper(context, floatingip)
        router_id = new_fip['router_id']
        if not router_id:
            return new_fip
        port_id = floatingip['floatingip']['port_id']
        if port_id:
            port_data = self.get_port(context, port_id)
            device_owner = port_data.get('device_owner')
            fip_address = new_fip['floating_ip_address']
            if (device_owner == const.DEVICE_OWNER_LOADBALANCERV2 or
                device_owner == oct_const.DEVICE_OWNER_OCTAVIA):
                try:
                    self._update_lb_vip(port_data, fip_address)
                except nsx_lib_exc.ManagerError:
                    with excutils.save_and_reraise_exception():
                        super(NsxV3Plugin, self).delete_floatingip(
                            context, new_fip['id'])
                return new_fip
        try:
            nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                     router_id)
            self.nsxlib.router.add_fip_nat_rules(
                nsx_router_id, new_fip['floating_ip_address'],
                new_fip['fixed_ip_address'],
                bypass_firewall=False)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                self.delete_floatingip(context, new_fip['id'])
        return new_fip

    def delete_floatingip(self, context, fip_id):
        fip = self.get_floatingip(context, fip_id)
        router_id = fip['router_id']
        port_id = fip['port_id']
        is_lb_port = False
        if port_id:
            port_data = self.get_port(context, port_id)
            device_owner = port_data.get('device_owner')
            fixed_ip_address = fip['fixed_ip_address']
            if (device_owner == const.DEVICE_OWNER_LOADBALANCERV2 or
                device_owner == oct_const.DEVICE_OWNER_OCTAVIA):
                # If the port is LB VIP port, after deleting the FIP,
                # update the virtual server VIP back to fixed IP.
                is_lb_port = True
                try:
                    self._update_lb_vip(port_data, fixed_ip_address)
                except nsx_lib_exc.ManagerError as e:
                    LOG.error("Exception when updating vip ip_address"
                              "on vip_port %(port)s: %(err)s",
                              {'port': port_id, 'err': e})

        if router_id and not is_lb_port:
            try:
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         router_id)
                self.nsxlib.router.delete_fip_nat_rules(
                    nsx_router_id, fip['floating_ip_address'],
                    fip['fixed_ip_address'])
            except nsx_lib_exc.ResourceNotFound:
                LOG.warning("Backend NAT rules for fip: %(fip_id)s "
                            "(ext_ip: %(ext_ip)s int_ip: %(int_ip)s) "
                            "not found",
                            {'fip_id': fip_id,
                             'ext_ip': fip['floating_ip_address'],
                             'int_ip': fip['fixed_ip_address']})
        super(NsxV3Plugin, self).delete_floatingip(context, fip_id)

    def update_floatingip(self, context, fip_id, floatingip):
        old_fip = self.get_floatingip(context, fip_id)
        old_port_id = old_fip['port_id']
        new_status = (const.FLOATINGIP_STATUS_ACTIVE
                      if floatingip['floatingip'].get('port_id')
                      else const.FLOATINGIP_STATUS_DOWN)
        new_fip = super(NsxV3Plugin, self).update_floatingip(
            context, fip_id, floatingip)
        router_id = new_fip['router_id']
        new_port_id = new_fip['port_id']
        try:
            is_lb_port = False
            if old_port_id:
                old_port_data = self.get_port(context, old_port_id)
                old_device_owner = old_port_data['device_owner']
                old_fixed_ip = old_fip['fixed_ip_address']
                if (old_device_owner == const.DEVICE_OWNER_LOADBALANCERV2 or
                    old_device_owner == oct_const.DEVICE_OWNER_OCTAVIA):
                    is_lb_port = True
                    self._update_lb_vip(old_port_data, old_fixed_ip)

            # Delete old router's fip rules if old_router_id is not None.
            if old_fip['router_id'] and not is_lb_port:

                try:
                    old_nsx_router_id = nsx_db.get_nsx_router_id(
                        context.session, old_fip['router_id'])
                    self.nsxlib.router.delete_fip_nat_rules(
                        old_nsx_router_id, old_fip['floating_ip_address'],
                        old_fip['fixed_ip_address'])
                except nsx_lib_exc.ResourceNotFound:
                    LOG.warning("Backend NAT rules for fip: %(fip_id)s "
                                "(ext_ip: %(ext_ip)s int_ip: %(int_ip)s) "
                                "not found",
                                {'fip_id': old_fip['id'],
                                 'ext_ip': old_fip['floating_ip_address'],
                                 'int_ip': old_fip['fixed_ip_address']})

            # Update LB VIP if the new port is LB port
            is_lb_port = False
            if new_port_id:
                new_port_data = self.get_port(context, new_port_id)
                new_dev_own = new_port_data['device_owner']
                new_fip_address = new_fip['floating_ip_address']
                if (new_dev_own == const.DEVICE_OWNER_LOADBALANCERV2 or
                    new_dev_own == oct_const.DEVICE_OWNER_OCTAVIA):
                    is_lb_port = True
                    self._update_lb_vip(new_port_data, new_fip_address)

            # TODO(berlin): Associating same FIP to different internal IPs
            # would lead to creating multiple times of FIP nat rules at the
            # backend. Let's see how to fix the problem latter.

            # Update current router's nat rules if router_id is not None.
            if router_id and not is_lb_port:
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         router_id)
                self.nsxlib.router.add_fip_nat_rules(
                    nsx_router_id, new_fip['floating_ip_address'],
                    new_fip['fixed_ip_address'],
                    bypass_firewall=False)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                super(NsxV3Plugin, self).update_floatingip(
                    context, fip_id, {'floatingip': {'port_id': old_port_id}})
                self.update_floatingip_status(context, fip_id,
                                              const.FLOATINGIP_STATUS_ERROR)
        if new_fip['status'] != new_status:
            new_fip['status'] = new_status
            self.update_floatingip_status(context, fip_id, new_status)
        return new_fip

    def disassociate_floatingips(self, context, port_id):
        fip_qry = context.session.query(l3_db_models.FloatingIP)
        fip_dbs = fip_qry.filter_by(fixed_port_id=port_id)

        for fip_db in fip_dbs:
            if not fip_db.router_id:
                continue
            try:
                nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                         fip_db.router_id)
                self.nsxlib.router.delete_fip_nat_rules(
                    nsx_router_id, fip_db.floating_ip_address,
                    fip_db.fixed_ip_address)
            except nsx_lib_exc.ResourceNotFound:
                LOG.warning("Backend NAT rules for fip: %(fip_id)s "
                            "(ext_ip: %(ext_ip)s int_ip: %(int_ip)s) "
                            "not found",
                            {'fip_id': fip_db.id,
                             'ext_ip': fip_db.floating_ip_address,
                             'int_ip': fip_db.fixed_ip_address})
            self.update_floatingip_status(context, fip_db.id,
                                          const.FLOATINGIP_STATUS_DOWN)

        super(NsxV3Plugin, self).disassociate_floatingips(
            context, port_id, do_notify=False)

    def _ensure_default_security_group(self, context, tenant_id):
        # NOTE(arosen): if in replay mode we'll create all the default
        # security groups for the user with their data so we don't
        # want this to be called.
        if (cfg.CONF.api_replay_mode is False):
            return super(NsxV3Plugin, self)._ensure_default_security_group(
                context, tenant_id)

    def _create_fw_section_for_secgroup(self, nsgroup, is_provider):
        # NOTE(arosen): if a security group is provider we want to
        # insert our rules at the top.
        operation = (nsxlib_consts.FW_INSERT_TOP
                     if is_provider
                     else nsxlib_consts.FW_INSERT_BEFORE)

        # security-group rules are located in a dedicated firewall section.
        firewall_section = (
            self.nsxlib.firewall_section.create_empty(
                nsgroup.get('display_name'), nsgroup.get('description'),
                [nsgroup.get('id')], nsgroup.get('tags'),
                operation=operation,
                other_section=self.default_section))
        return firewall_section

    def _create_security_group_backend_resources(self, secgroup):
        tags = self.nsxlib.build_v3_tags_payload(
            secgroup, resource_type='os-neutron-secgr-id',
            project_name=secgroup['tenant_id'])
        name = self.nsxlib.ns_group.get_name(secgroup)

        if self.nsxlib.feature_supported(
            nsxlib_consts.FEATURE_DYNAMIC_CRITERIA):
                tag_expression = (
                    self.nsxlib.ns_group.get_port_tag_expression(
                        security.PORT_SG_SCOPE, secgroup['id']))
        else:
            tag_expression = None

        ns_group = self.nsxlib.ns_group.create(
            name, secgroup['description'], tags, tag_expression)
        # security-group rules are located in a dedicated firewall section.
        firewall_section = self._create_fw_section_for_secgroup(
            ns_group, secgroup.get(provider_sg.PROVIDER))
        return ns_group, firewall_section

    def _create_firewall_rules(self, context, section_id, nsgroup_id,
                               logging_enabled, action, sg_rules):
        # since the nsxlib does not have access to the nsx db,
        # we need to provide a mapping for the remote nsgroup ids.
        ruleid_2_remote_nsgroup_map = {}
        _sg_rules = copy.deepcopy(sg_rules)
        for sg_rule in _sg_rules:
            self._fix_sg_rule_dict_ips(sg_rule)
            remote_nsgroup_id = None
            remote_group_id = sg_rule.get('remote_group_id')
            # skip unnecessary db access when possible
            if remote_group_id == sg_rule['security_group_id']:
                remote_nsgroup_id = nsgroup_id
            elif remote_group_id:
                remote_nsgroup_id = nsx_db.get_nsx_security_group_id(
                    context.session, remote_group_id)
            ruleid_2_remote_nsgroup_map[sg_rule['id']] = remote_nsgroup_id

        return self.nsxlib.firewall_section.create_section_rules(
            section_id, nsgroup_id,
            logging_enabled, action, _sg_rules,
            ruleid_2_remote_nsgroup_map)

    def _handle_api_replay_default_sg(self, context, secgroup_db):
        """Set default api-replay migrated SG as default manually"""
        if (secgroup_db['name'] == 'default'):
            # this is a default security group copied from another cloud
            # Ugly patch! mark it as default manually
            with context.session.begin(subtransactions=True):
                try:
                    default_entry = securitygroup_model.DefaultSecurityGroup(
                        security_group_id=secgroup_db['id'],
                        project_id=secgroup_db['project_id'])
                    context.session.add(default_entry)
                except Exception as e:
                    LOG.error("Failed to mark migrated security group %(id)s "
                              "as default %(e)s",
                              {'id': secgroup_db['id'], 'e': e})

    def create_security_group(self, context, security_group, default_sg=False):
        secgroup = security_group['security_group']
        secgroup['id'] = secgroup.get('id') or uuidutils.generate_uuid()
        ns_group = {}
        firewall_section = {}

        if not default_sg:
            tenant_id = secgroup['tenant_id']
            self._ensure_default_security_group(context, tenant_id)
        try:
            ns_group, firewall_section = (
                self._create_security_group_backend_resources(secgroup))
            # REVISIT(roeyc): Ideally, at this point we need not be under an
            # open db transactions, however, unittests fail if omitting
            # subtransactions=True.
            with db_api.CONTEXT_WRITER.using(context):
                # NOTE(arosen): a neutron security group be default adds rules
                # that allow egress traffic. We do not want this behavior for
                # provider security_groups
                if secgroup.get(provider_sg.PROVIDER) is True:
                    secgroup_db = self.create_provider_security_group(
                        context, security_group)
                else:
                    secgroup_db = (
                        super(NsxV3Plugin, self).create_security_group(
                            context, security_group, default_sg))

                nsx_db.save_sg_mappings(context,
                                        secgroup_db['id'],
                                        ns_group['id'],
                                        firewall_section['id'])

                self._process_security_group_properties_create(context,
                                                               secgroup_db,
                                                               secgroup,
                                                               default_sg)
                if cfg.CONF.api_replay_mode:
                    self._handle_api_replay_default_sg(context, secgroup_db)

        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.exception("Unable to create security-group on the "
                              "backend.")
                if ns_group:
                    self.nsxlib.ns_group.delete(ns_group['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                section_id = firewall_section.get('id')
                nsgroup_id = ns_group.get('id')
                LOG.debug("Neutron failed to create security-group, "
                          "deleting backend resources: "
                          "section %s, ns-group %s.",
                          section_id, nsgroup_id)
                if nsgroup_id:
                    self.nsxlib.ns_group.delete(nsgroup_id)
                if section_id:
                    self.nsxlib.firewall_section.delete(section_id)
        try:
            sg_rules = secgroup_db['security_group_rules']
            # skip if there are no rules in group. i.e provider case
            if sg_rules:
                # translate and creates firewall rules.
                logging = (
                    cfg.CONF.nsx_v3.log_security_groups_allowed_traffic or
                    secgroup.get(sg_logging.LOGGING, False))
                action = (nsxlib_consts.FW_ACTION_DROP
                          if secgroup.get(provider_sg.PROVIDER)
                          else nsxlib_consts.FW_ACTION_ALLOW)
                rules = self._create_firewall_rules(
                    context, firewall_section['id'], ns_group['id'],
                    logging, action, sg_rules)
                self.save_security_group_rule_mappings(context, rules['rules'])
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.exception("Failed to create backend firewall rules "
                              "for security-group %(name)s (%(id)s), "
                              "rolling back changes.", secgroup_db)
                # default security group deletion requires admin context
                if default_sg:
                    context = context.elevated()
                super(NsxV3Plugin, self).delete_security_group(
                    context, secgroup_db['id'])
                self.nsxlib.ns_group.delete(ns_group['id'])
                self.nsxlib.firewall_section.delete(firewall_section['id'])

        return secgroup_db

    def update_security_group(self, context, id, security_group):
        orig_secgroup = self.get_security_group(
            context, id, fields=['id', 'name', 'description'])
        self._prevent_non_admin_edit_provider_sg(context, id)
        with db_api.CONTEXT_WRITER.using(context):
            secgroup_res = (
                super(NsxV3Plugin, self).update_security_group(context, id,
                                                               security_group))
            self._process_security_group_properties_update(
                context, secgroup_res, security_group['security_group'])
        try:
            nsgroup_id, section_id = nsx_db.get_sg_mappings(
                context.session, id)
            self.nsxlib.ns_group.update_nsgroup_and_section(
                secgroup_res, nsgroup_id, section_id,
                cfg.CONF.nsx_v3.log_security_groups_allowed_traffic)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                LOG.exception("Failed to update security-group %(name)s "
                              "(%(id)s), rolling back changes in "
                              "Neutron.", orig_secgroup)
                super(NsxV3Plugin, self).update_security_group(
                    context, id, {'security_group': orig_secgroup})

        return secgroup_res

    def delete_security_group(self, context, id):
        self._prevent_non_admin_edit_provider_sg(context, id)
        nsgroup_id, section_id = nsx_db.get_sg_mappings(
            context.session, id)
        super(NsxV3Plugin, self).delete_security_group(context, id)
        self.nsxlib.firewall_section.delete(section_id)
        self.nsxlib.ns_group.delete(nsgroup_id)

    def create_security_group_rule(self, context, security_group_rule):
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk(context, bulk_rule)[0]

    def create_security_group_rule_bulk(self, context, security_group_rules):
        sg_rules = security_group_rules['security_group_rules']
        for r in sg_rules:
            self._check_local_ip_prefix(context, r['security_group_rule'])
            # Generate id for security group rule or use one specified,
            # if specified we are running in api-replay as server doesn't
            # allow id to be specified by default
            r['security_group_rule']['id'] = (
                r['security_group_rule'].get('id') or
                uuidutils.generate_uuid())

        with db_api.CONTEXT_WRITER.using(context):

            rules_db = (super(NsxV3Plugin,
                              self).create_security_group_rule_bulk_native(
                                  context, security_group_rules))
            for i, r in enumerate(sg_rules):
                self._process_security_group_rule_properties(
                    context, rules_db[i], r['security_group_rule'])

            # NOTE(arosen): here are assuming that all of the security
            # group rules being added are part of the same security
            # group. We should be validating that this is the case though...
            sg_id = sg_rules[0]['security_group_rule']['security_group_id']
            self._prevent_non_admin_edit_provider_sg(context, sg_id)

            security_group = self.get_security_group(
                context, sg_id)
            action = nsxlib_consts.FW_ACTION_ALLOW
            if security_group.get(provider_sg.PROVIDER) is True:
                # provider security groups are drop rules.
                action = nsxlib_consts.FW_ACTION_DROP

        sg_id = rules_db[0]['security_group_id']
        nsgroup_id, section_id = nsx_db.get_sg_mappings(context.session,
                                                        sg_id)
        logging_enabled = (
            cfg.CONF.nsx_v3.log_security_groups_allowed_traffic or
            self._is_security_group_logged(context, sg_id))
        try:
            rules = self._create_firewall_rules(
                context, section_id, nsgroup_id,
                logging_enabled, action, rules_db)
        except nsx_lib_exc.ManagerError:
            with excutils.save_and_reraise_exception():
                for rule in rules_db:
                    super(NsxV3Plugin, self).delete_security_group_rule(
                        context, rule['id'])
        self.save_security_group_rule_mappings(context, rules['rules'])
        return rules_db

    def delete_security_group_rule(self, context, id):
        rule_db = self._get_security_group_rule(context, id)
        sg_id = rule_db['security_group_id']
        self._prevent_non_admin_edit_provider_sg(context, sg_id)
        nsgroup_id, section_id = nsx_db.get_sg_mappings(context.session, sg_id)
        fw_rule_id = nsx_db.get_sg_rule_mapping(context.session, id)
        self.nsxlib.firewall_section.delete_rule(section_id, fw_rule_id)
        super(NsxV3Plugin, self).delete_security_group_rule(context, id)

    def save_security_group_rule_mappings(self, context, firewall_rules):
        rules = [(rule['display_name'], rule['id']) for rule in firewall_rules]
        nsx_db.save_sg_rule_mappings(context.session, rules)

    def _list_availability_zones(self, context, filters=None):
        # If no native_dhcp_metadata - use neutron AZs
        if not cfg.CONF.nsx_v3.native_dhcp_metadata:
            return super(NsxV3Plugin, self)._list_availability_zones(
                context, filters=filters)

        result = {}
        for az in self._availability_zones_data.list_availability_zones():
            # Add this availability zone as a network & router resource
            if filters:
                if 'name' in filters and az not in filters['name']:
                    continue
            for res in ['network', 'router']:
                if 'resource' not in filters or res in filters['resource']:
                    result[(az, res)] = True
        return result

    def _validate_availability_zones_forced(self, context, resource_type,
                                            availability_zones):
        return self.validate_availability_zones(context, resource_type,
                                                availability_zones,
                                                force=True)

    def validate_availability_zones(self, context, resource_type,
                                    availability_zones, force=False):
        # This method is called directly from this plugin but also from
        # registered callbacks
        if self._is_sub_plugin and not force:
            # validation should be done together for both plugins
            return
        # If no native_dhcp_metadata - use neutron AZs
        if not cfg.CONF.nsx_v3.native_dhcp_metadata:
            return super(NsxV3Plugin, self).validate_availability_zones(
                context, resource_type, availability_zones)
        # Validate against the configured AZs
        return self.validate_obj_azs(availability_zones)

    def get_network_availability_zones(self, net_db):
        if cfg.CONF.nsx_v3.native_dhcp_metadata:
            hints = az_validator.convert_az_string_to_list(
                net_db[az_def.AZ_HINTS])
            # When using the configured AZs, the az will always be the same
            # as the hint (or default if none)
            if hints:
                az_name = hints[0]
            else:
                az_name = self.get_default_az().name
            return [az_name]
        else:
            return []

    def recalculate_snat_rules_for_router(self, context, router, subnets):
        """Recalculate router snat rules for specific subnets.
        Invoked when subnetpool address scope changes.
        """
        nsx_router_id = nsx_db.get_nsx_router_id(context.session,
                                                 router['id'])

        if not router['external_gateway_info']:
            return

        LOG.info("Recalculating snat rules for router %s", router['id'])
        fip = router['external_gateway_info']['external_fixed_ips'][0]
        ext_addr = fip['ip_address']
        gw_address_scope = self._get_network_address_scope(
            context, router['external_gateway_info']['network_id'])

        # TODO(annak): improve amount of backend calls by rebuilding all
        # snat rules when API is available
        for subnet in subnets:
            if gw_address_scope:
                subnet_address_scope = self._get_subnetpool_address_scope(
                    context, subnet['subnetpool_id'])
                LOG.info("Deleting SNAT rule for %(router)s "
                         "and subnet %(subnet)s",
                         {'router': router['id'],
                          'subnet': subnet['id']})

                # Delete rule for this router/subnet pair if it exists
                self.nsxlib.router.delete_gw_snat_rule_by_source(
                    nsx_router_id, ext_addr, subnet['cidr'],
                    skip_not_found=True)

                if (gw_address_scope != subnet_address_scope):
                    # subnet is no longer under same address scope with GW
                    LOG.info("Adding SNAT rule for %(router)s "
                             "and subnet %(subnet)s",
                             {'router': router['id'],
                              'subnet': subnet['id']})
                    self.nsxlib.router.add_gw_snat_rule(
                        nsx_router_id, ext_addr,
                        source_net=subnet['cidr'],
                        bypass_firewall=False)
