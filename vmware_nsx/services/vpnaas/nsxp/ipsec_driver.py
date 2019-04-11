# Copyright 2019 VMware, Inc.
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

import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context as n_context
from neutron_lib import exceptions as nexception
from neutron_lib.plugins import directory
from neutron_vpnaas.services.vpn import service_drivers

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.services.vpnaas.common_v3 import ipsec_driver as common_driver
from vmware_nsx.services.vpnaas.nsxv3 import ipsec_utils
from vmware_nsx.services.vpnaas.nsxp import ipsec_validator
from vmware_nsxlib.v3 import exceptions as nsx_lib_exc
from vmware_nsxlib.v3 import nsx_constants as consts
from vmware_nsxlib.v3 import vpn_ipsec

LOG = logging.getLogger(__name__)
IPSEC = 'ipsec'


#DEBUG ADIT - this should already be allowed
class RouterWithSNAT(nexception.BadRequest):
    message = _("Router %(router_id)s has a VPN service and cannot enable "
                "SNAT")


class RouterWithOverlapNoSnat(nexception.BadRequest):
    message = _("Router %(router_id)s has a subnet overlapping with a VPN "
                "local subnet, and cannot disable SNAT")


class RouterOverlapping(nexception.BadRequest):
    message = _("Router %(router_id)s interface is overlapping with a VPN "
                "local subnet and cannot be added")


class NSXpIPsecVpnDriver(common_driver.NSXcommonIPsecVpnDriver):

    def __init__(self, service_plugin):
        validator = ipsec_validator.IPsecPValidator(service_plugin)
        super(NSXpIPsecVpnDriver, self).__init__(service_plugin, validator)

        registry.subscribe(
            self._delete_local_endpoint, resources.ROUTER_GATEWAY,
            events.AFTER_DELETE)

        registry.subscribe(
            self._verify_overlap_subnet, resources.ROUTER_INTERFACE,
            events.BEFORE_CREATE)

    def _translate_cidr(self, cidr):
        return self._nsxlib.firewall_section.get_ip_cidr_reference(
            cidr,
            consts.IPV6 if netaddr.valid_ipv6(cidr) else consts.IPV4)

    def _translate_addresses_to_target(self, cidrs):
        return [self._translate_cidr(ip) for ip in cidrs]

    def _generate_ipsecvpn_firewall_rules(self, plugin_type, context,
                                          router_id=None):
        """Return the firewall rules needed to allow vpn traffic"""
        fw_rules = []
        # get all the active services of this router
        filters = {'router_id': [router_id],
                   'status': [constants.ACTIVE]}
        services = self.vpn_plugin.get_vpnservices(
            context.elevated(), filters=filters)
        if not services:
            return fw_rules
        for srv in services:
            subnet = self.l3_plugin.get_subnet(
                context.elevated(), srv['subnet_id'])
            local_cidrs = [subnet['cidr']]
            # get all the active connections of this service
            filters = {'vpnservice_id': [srv['id']],
                       'status': [constants.ACTIVE]}
            connections = self.vpn_plugin.get_ipsec_site_connections(
                context.elevated(), filters=filters)
            for conn in connections:
                peer_cidrs = conn['peer_cidrs']
                fw_rules.append({
                    'display_name': 'VPN connection ' + conn['id'],
                    'action': consts.FW_ACTION_ALLOW,
                    'destinations': self._translate_addresses_to_target(
                        peer_cidrs),
                    'sources': self._translate_addresses_to_target(
                        local_cidrs)})

        return fw_rules

    def _update_firewall_rules(self, context, vpnservice):
        LOG.debug("Updating vpn firewall rules for router %s",
                  vpnservice['router_id'])
        self._core_plugin.update_router_firewall(
            context, vpnservice['router_id'])

    def _update_router_advertisement(self, context, vpnservice):
        # DEBUG ADIT not yet
        LOG.error("DEBUG ADIT need to update router advertisement")
        # LOG.debug("Updating router advertisement rules for router %s",
        #           vpnservice['router_id'])

        # router_id = vpnservice['router_id']
        # # skip no-snat router as it is already advertised,
        # # and router with no gw
        # rtr = self.l3_plugin.get_router(context, router_id)
        # if (not rtr.get('external_gateway_info') or
        #     not rtr['external_gateway_info'].get('enable_snat', True)):
        #     return

        # rules = []

        # # get all the active services of this router
        # filters = {'router_id': [router_id], 'status': [constants.ACTIVE]}
        # services = self.vpn_plugin.get_vpnservices(
        #     context.elevated(), filters=filters)
        # rule_name_pref = 'VPN advertisement service'
        # for srv in services:
        #     # use only services with active connections
        #     filters = {'vpnservice_id': [srv['id']],
        #                'status': [constants.ACTIVE]}
        #     connections = self.vpn_plugin.get_ipsec_site_connections(
        #         context.elevated(), filters=filters)
        #     if not connections:
        #         continue
        #     subnet = self.l3_plugin.get_subnet(
        #         context.elevated(), srv['subnet_id'])
        #     rules.append({
        #         'display_name': "%s %s" % (rule_name_pref, srv['id']),
        #         'action': consts.FW_ACTION_ALLOW,
        #         'networks': [subnet['cidr']]})

        # if rules:
        #     logical_router_id = db.get_nsx_router_id(context.session,
        #                                              router_id)
        #     self._nsxlib.logical_router.update_advertisement_rules(
        #         logical_router_id, rules, name_prefix=rule_name_pref)

    def _update_status(self, context, vpn_service_id, ipsec_site_conn_id,
                       status, updated_pending_status=True):
        ipsec_site_conn = {'status': status,
                           'updated_pending_status': updated_pending_status}
        vpn_status = {'id': vpn_service_id,
                      'updated_pending_status': updated_pending_status,
                      'status': status,
                      'ipsec_site_connections': {ipsec_site_conn_id:
                                                 ipsec_site_conn}}
        status_list = [vpn_status]
        self.service_plugin.update_status_by_agent(context, status_list)

    # DEBUG ADIT - to delete
    def _nsx_tags(self, context, object, resoruce_type='os-vpn-connection-id'):
        return self._policy.build_v3_tags_payload(
            object, resource_type=resoruce_type,
            project_name=context.tenant_name)

    # DEBUG ADIT - to delete
    def _nsx_tags_for_reused(self):
        # Service & Local endpoint can be reused cross tenants,
        # so we do not add the tenant/object id.
        return self._policy.build_v3_api_version_tag()

    def _create_ike_profile(self, context, connection):
        """Create an ike profile for a connection
        Creating/overwriting IKE profile based on the openstack ike policy
        upon connection creation.
        There is no driver callback for profiles creation so it has to be
        done on connection creation.
        """
        ike_policy_id = connection['ikepolicy_id']
        ikepolicy = self.vpn_plugin.get_ikepolicy(context, ike_policy_id)
        tags = self._policy.build_v3_tags_payload(
            ikepolicy, resource_type='os-vpn-ikepolicy-id',
            project_name=context.tenant_name)
        try:
            profile_id = self._nsx_vpn.ike_profile.create_or_overwrite(
                ikepolicy['name'] or ikepolicy['id'],
                profile_id=ikepolicy['id'],
                description=ikepolicy['description'],
                encryption_algorithm=ipsec_utils.ENCRYPTION_ALGORITHM_MAP[
                    ikepolicy['encryption_algorithm']],
                digest_algorithm=ipsec_utils.AUTH_ALGORITHM_MAP[
                    ikepolicy['auth_algorithm']],
                ike_version=ipsec_utils.IKE_VERSION_MAP[
                    ikepolicy['ike_version']],
                dh_group=ipsec_utils.PFS_MAP[ikepolicy['pfs']],
                sa_life_time=ikepolicy['lifetime']['value'],
                tags=tags)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create an ike profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return profile_id

    def _delete_ike_profile(self, ikeprofile_id):
        try:
            self._nsx_vpn.ike_profile.delete(ikeprofile_id)
        except Exception as e:
            # DEBUG ADIT use exact exception
            # Still in use by another connection
            # DEBUG ADIT - consider checking usage via vpn db?
            LOG.info("IKE profile %s cannot be deleted yet, because another "
                     "connection still uses it: %s", ikeprofile_id, e)

    def _create_ipsec_profile(self, context, connection):
        """Create a tunnel profile for a connection
        Creating/overwriting tunnel profile based on the openstack ipsec policy
        upon connection creation.
        There is no driver callback for profiles creation so it has to be
        done on connection creation.
        """
        ipsec_policy_id = connection['ipsecpolicy_id']
        ipsecpolicy = self.vpn_plugin.get_ipsecpolicy(
            context, ipsec_policy_id)
        tags = self._policy.build_v3_tags_payload(
            ikepolicy, resource_type='os-vpn-ipsecpolicy-id',
            project_name=context.tenant_name)

        try:
            profile_id = self._nsx_vpn.tunnel_profile.create_or_overwrite(
                ipsecpolicy['name'] or ipsecpolicy['id'],
                profile_id=ipsecpolicy['id'],
                description=ipsecpolicy['description'],
                encryption_algorithm=ipsec_utils.ENCRYPTION_ALGORITHM_MAP[
                    ipsecpolicy['encryption_algorithm']],
                digest_algorithm=ipsec_utils.AUTH_ALGORITHM_MAP[
                    ipsecpolicy['auth_algorithm']],
                dh_group=ipsec_utils.PFS_MAP[ipsecpolicy['pfs']],
                pfs=True,
                sa_life_time=ipsecpolicy['lifetime']['value'],
                tags=tags)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a tunnel profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return profile_id

    def _delete_ipsec_profile(self, ipsecprofile_id):
        try:
            self._nsx_vpn.tunnel_profile.delete(ipsecprofile_id)
        except Exception as e:
            # DEBUG ADIT use exact exception
            # Still in use by another connection
            # DEBUG ADIT - consider checking usage via vpn db?
            LOG.info("Tunnel profile %s cannot be deleted yet, because another "
                     "connection still uses it: %s", ipsecprofile_id, e)

    def _create_dpd_profile(self, context, connection):
        """Create a DPD profile for a connection
        Creating/overwriting DPD profile based on the openstack ipsec
        connection configuration upon connection creation.
        There is no driver callback for profiles creation so it has to be
        done on connection creation.
        """
        # TODO(asarfaty) consider reusing profiles based on values
        dpd_info = connection['dpd']
        try:
            profile_id = self._nsx_vpn.dpd_profile.create_or_overwrite(
                self._get_dpd_profile_name(connection),
                project_id=connection['id'],
                description='neutron dpd profile',
                timeout=dpd_info.get('timeout'),
                enabled=True if dpd_info.get('action') == 'hold' else False,
                tags=self._nsx_tags(context, connection))
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a DPD profile: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return profile_id

    def _delete_dpd_profile(self, dpdprofile_id):
        self._nsx_vpn.dpd_profile.delete(dpdprofile_id)

    def _update_dpd_profile(self, connection, dpdprofile_id):
        dpd_info = connection['dpd']
        self._nsx_vpn.dpd_profile.update(dpdprofile_id,
                name=self._get_dpd_profile_name(connection),
                timeout=dpd_info.get('timeout'),
                enabled=True if dpd_info.get('action') == 'hold' else False)

    def _create_local_endpoint(self, context, local_addr, nsx_service_id,
                               router_id, project_id):
        """Creating an NSX local endpoint for a logical router

        This endpoint can be reused by other connections, and will be deleted
        when the router is deleted or gateway is removed
        """
        # Add the neutron router-id to the tags to help search later
        tags = self._nsxlib.build_v3_tags_payload(
            {'id': router_id, 'project_id': project_id},
            resource_type='os-neutron-router-id',
            project_name=context.tenant_name)

        try:
            local_endpoint = self._nsx_vpn.local_endpoint.create(
                'Local endpoint for OS VPNaaS',
                local_addr,
                nsx_service_id,
                tags=tags)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a local endpoint: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return local_endpoint['id']

    def _search_local_endpint(self, router_id):
        tags = [{'scope': 'os-neutron-router-id', 'tag': router_id}]
        ep_list = self._nsxlib.search_by_tags(
            tags=tags,
            resource_type=self._nsx_vpn.local_endpoint.resource_type)
        if ep_list['results']:
            return ep_list['results'][0]['id']

    def _get_local_endpoint(self, context, connection, vpnservice):
        """Get the id of the local endpoint for a service

        The NSX allows only one local endpoint per local address
        This method will create it if there is not matching endpoint
        """
        # use the router GW as the local ip
        router_id = vpnservice['router']['id']

        # check if we already have this endpoint on the NSX
        local_ep_id = self._search_local_endpint(router_id)
        if local_ep_id:
            return local_ep_id

        # create a new one
        local_addr = vpnservice['external_v4_ip']
        local_ep_id = self._create_local_endpoint(
            context, local_addr, router_id, router_id,
            vpnservice['project_id'])
        return local_ep_id

    def _delete_local_endpoint(self, resource, event, trigger, **kwargs):
        """Upon router deletion / gw removal delete the matching endpoint"""
        router_id = kwargs.get('router_id')
        # delete the local endpoint from the NSX
        local_ep_id = self._search_local_endpint(router_id)
        if local_ep_id:
            self._nsx_vpn.local_endpoint.delete(local_ep_id)
        # delete the neutron port with this IP
        ctx = n_context.get_admin_context()
        port = self._find_vpn_service_port(ctx, router_id)
        if port:
            self.l3_plugin.delete_port(ctx, port['id'], force_delete_vpn=True)

    def _check_subnets_overlap_with_all_conns(self, context, subnets):
        # find all vpn services with connections
        filters = {'status': [constants.ACTIVE]}
        connections = self.vpn_plugin.get_ipsec_site_connections(
            context, filters=filters)
        for conn in connections:
            srv_id = conn.get('vpnservice_id')
            srv = self.vpn_plugin._get_vpnservice(context, srv_id)
            srv_subnet = self.l3_plugin.get_subnet(
                context, srv['subnet_id'])
            if netaddr.IPSet(subnets) & netaddr.IPSet([srv_subnet['cidr']]):
                return False

        return True

    def _verify_overlap_subnet(self, resource, event, trigger, **kwargs):
        """Upon router interface creation validation overlapping with vpn"""
        router_db = kwargs.get('router_db')
        port = kwargs.get('port')
        if not port or not router_db:
            LOG.warning("NSX V3 VPNaaS ROUTER_INTERFACE BEFORE_CRAETE "
                        "callback didn't get all the relevant information")
            return

        if router_db.enable_snat:
            # checking only no-snat routers
            return

        admin_con = n_context.get_admin_context()
        subnet_id = port['fixed_ips'][0].get('subnet_id')
        if subnet_id:
            subnet = self._core_plugin.get_subnet(admin_con, subnet_id)
            # find all vpn services with connections
            if not self._check_subnets_overlap_with_all_conns(
                admin_con, [subnet['cidr']]):
                raise RouterOverlapping(router_id=kwargs.get('router_id'))

    def validate_router_gw_info(self, context, router_id, gw_info):
        """Upon router gw update - verify no-snat"""
        # check if this router has a vpn service
        admin_con = context.elevated()
        # get all relevant services, except those waiting to be deleted or in
        # ERROR state
        filters = {'router_id': [router_id],
                   'status': [constants.ACTIVE, constants.PENDING_CREATE,
                              constants.INACTIVE, constants.PENDING_UPDATE]}
        services = self.vpn_plugin.get_vpnservices(admin_con, filters=filters)
        if services:
            # do not allow enable-snat
            if (gw_info and
                gw_info.get('enable_snat', cfg.CONF.enable_snat_by_default)):
                raise RouterWithSNAT(router_id=router_id)
        else:
            # if this is a non-vpn router. if snat was disabled, should check
            # there is no overlapping with vpn connections
            if (gw_info and
                not gw_info.get('enable_snat',
                                cfg.CONF.enable_snat_by_default)):
                # get router subnets
                subnets = self._core_plugin._find_router_subnets_cidrs(
                    context, router_id)
                # find all vpn services with connections
                if not self._check_subnets_overlap_with_all_conns(
                    admin_con, subnets):
                    raise RouterWithOverlapNoSnat(router_id=router_id)

    def _get_session_rules(self, context, connection, vpnservice):
        # TODO(asarfaty): support vpn-endpoint-groups too
        peer_cidrs = connection['peer_cidrs']
        local_cidrs = [vpnservice['subnet']['cidr']]
        rule = self._nsx_vpn.session.get_rule_obj(local_cidrs, peer_cidrs)
        return [rule]

    def _create_session(self, context, connection, local_ep_id,
                        peer_ep_id, rules, enabled=True):
        try:
            session = self._nsx_vpn.session.create(
                connection['name'] or connection['id'],
                local_ep_id, peer_ep_id, rules,
                description=connection['description'],
                tags=self._nsx_tags(context, connection),
                enabled=enabled)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create a session: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

        return session['id']

    def _update_session(self, session_id, connection, rules=None,
                        enabled=True):
        self._nsx_vpn.session.update(
            session_id,
            name=connection['name'] or connection['id'],
            description=connection['description'],
            policy_rules=rules,
            enabled=enabled)

    def get_ipsec_site_connection_status(self, context, ipsec_site_conn_id):
        # DEBUG ADIT - not yet
        LOG.error("DEBUG ADIT get_ipsec_site_connection_status needs to be implemented")
        # mapping = db.get_nsx_vpn_connection_mapping(
        #     context.session, ipsec_site_conn_id)
        # if not mapping or not mapping['session_id']:
        #     LOG.info("Couldn't find NSX session for VPN connection %s",
        #              ipsec_site_conn_id)
        #     return

        # status_result = self._nsx_vpn.session.get_status(mapping['session_id'])
        # if status_result and 'session_status' in status_result:
        #     status = status_result['session_status']
        #     # NSX statuses are UP, DOWN, DEGRADE
        #     # VPNaaS connection status should be ACTIVE or DOWN
        #     if status == 'UP':
        #         return 'ACTIVE'
        #     elif status == 'DOWN' or status == 'DEGRADED':
        #         return 'DOWN'

    def _delete_session(self, session_id):
        self._nsx_vpn.session.delete(session_id)

    def create_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Creating ipsec site connection %(conn_info)s.',
                  {"conn_info": ipsec_site_conn})
        # Note(asarfaty) the plugin already calls the validator
        # which also validated the policies and service

        ikeprofile_id = None
        ipsecprofile_id = None
        dpdprofile_id = None
        session_id = None
        vpnservice_id = ipsec_site_conn['vpnservice_id']
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)
        ipsec_id = ipsec_site_conn["id"]

        try:
            # create the ike profile
            ikeprofile_id = self._create_ike_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX ike profile %s", ikeprofile_id)

            # create the ipsec profile
            ipsecprofile_id = self._create_ipsec_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX ipsec profile %s", ipsecprofile_id)

            # create the dpd profile
            dpdprofile_id = self._create_dpd_profile(
                context, ipsec_site_conn)
            LOG.debug("Created NSX dpd profile %s", dpdprofile_id)

            # # create or reuse a local endpoint using the vpn service
            # local_ep_id = self._get_local_endpoint(
            #     context, ipsec_site_conn, vpnservice)

            # # Finally: create the session with policy rules
            # rules = self._get_session_rules(
            #     context, ipsec_site_conn, vpnservice)
            # connection_enabled = (vpnservice['admin_state_up'] and
            #                       ipsec_site_conn['admin_state_up'])
            # session_id = self._create_session(
            #     context, ipsec_site_conn, local_ep_id, ikeprofile_id, ipsecprofile_id, dpdprofile_id, rules,
            #     enabled=connection_enabled)

            self._update_status(context, vpnservice_id, ipsec_id,
                                constants.ACTIVE)

        except nsx_exc.NsxPluginException:
            with excutils.save_and_reraise_exception():
                self._update_status(context, vpnservice_id, ipsec_id,
                                    constants.ERROR)
                # delete the NSX objects that were already created
                # Do not delete reused objects: service, local endpoint
                if session_id:
                    self._delete_session(session_id)
                if dpdprofile_id:
                    self._delete_dpd_profile(dpdprofile_id)
                if ipsecprofile_id:
                    self._delete_ipsec_profile(ipsecprofile_id)
                if ikeprofile_id:
                    self._delete_ike_profile(ikeprofile_id)

        # update router firewall rules
        self._update_firewall_rules(context, vpnservice)

        # update router advertisement rules
        self._update_router_advertisement(context, vpnservice)

    def delete_ipsec_site_connection(self, context, ipsec_site_conn):
        LOG.debug('Deleting ipsec site connection %(site)s.',
                  {"site": ipsec_site_conn})

        vpnservice_id = ipsec_site_conn['vpnservice_id']
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)

        self._delete_session(ipsec_site_conn['id'])
        self._delete_dpd_profile(ipsec_site_conn['id'])
        self._delete_ipsec_profile(ipsec_site_conn['ipsecpolicy_id'])
        self._delete_ike_profile(ipsec_site_conn['ikepolicy_id'])

        # update router firewall rules
        self._update_firewall_rules(context, vpnservice)

        # update router advertisement rules
        self._update_router_advertisement(context, vpnservice)

    def update_ipsec_site_connection(self, context, old_ipsec_conn,
                                     ipsec_site_conn):
        LOG.debug('Updating ipsec site connection new %(site)s.',
                  {"site": ipsec_site_conn})
        LOG.debug('Updating ipsec site connection old %(site)s.',
                  {"site": old_ipsec_conn})

        # Note(asarfaty) the plugin already calls the validator
        # which also validated the policies and service
        # DEBUG ADIT - check if it is allowed to change ike/tunnel policy
        # of a connection or update it?
        ipsec_id = old_ipsec_conn['id']
        vpnservice_id = old_ipsec_conn['vpnservice_id']
        vpnservice = self.service_plugin._get_vpnservice(
            context, vpnservice_id)
        mapping = db.get_nsx_vpn_connection_mapping(
            context.session, ipsec_site_conn['id'])
        if not mapping:
            LOG.error("Couldn't find nsx ids for VPN connection %s",
                      ipsec_site_conn['id'])
            self._update_status(context, vpnservice_id, ipsec_id, "ERROR")
            raise nsx_exc.NsxIPsecVpnMappingNotFound(conn=ipsec_id)

        # check if the dpd configuration changed
        old_dpd = old_ipsec_conn['dpd']
        new_dpd = ipsec_site_conn['dpd']
        if (old_dpd['action'] != new_dpd['action'] or
            old_dpd['timeout'] != new_dpd['timeout'] or
            old_ipsec_conn['name'] != ipsec_site_conn['name']):
            self._update_dpd_profile(ipsec_site_conn,
                                     mapping['dpd_profile_id'])

        rules = self._get_session_rules(
            context, ipsec_site_conn, vpnservice)
        connection_enabled = (vpnservice['admin_state_up'] and
                              ipsec_site_conn['admin_state_up'])
        # DEBUG ADIT need profiles ids?
        self._update_session(mapping['session_id'], ipsec_site_conn, rules,
                             enabled=connection_enabled)

        if ipsec_site_conn['peer_cidrs'] != old_ipsec_conn['peer_cidrs']:
            # Update firewall
            self._update_firewall_rules(context, vpnservice)

        # No service updates. No need to update router advertisement rules

    def _create_vpn_service(self, context, vpnservice):
        """Create or overwrite tier1 vpn service
        The service is created on the TIER1 router attached to the service
        The NSX can keep only one service per tier1 router so we reuse it
        """
        router_id = vpnservice['router_id']
        try:
            self._nsx_vpn.service.create_or_overwrite(
                'Neutron VPN service for T1 router ' + router_id,
                router_id,
                vpn_service_id=router_id,
                enabled=True,
                ike_log_level=ipsec_utils.DEFAULT_LOG_LEVEL)
        except nsx_lib_exc.ManagerError as e:
            msg = _("Failed to create vpn service: %s") % e
            raise nsx_exc.NsxPluginException(err_msg=msg)

    def _delete_vpn_service_if_needed(self, context, vpnservice):
        # Delete the VPN service on the NSX if no other service uses it
        router_id = vpnservice['router_id']
        filters = {'router_id': [router_id]}
        services = self.vpn_plugin.get_vpnservices(
            context.elevated(), filters=filters)
        if not services:
            try:
                self._nsx_vpn.service.delete(router_id)
            except Exception as e:
                LOG.error("Failed to delete VPN service %s: %s",
                          router_id, e)

    def create_vpnservice(self, context, new_vpnservice):
        #TODO(asarfaty) support vpn-endpoint-group-create for local & peer
        # cidrs too
        LOG.info('Creating VPN service %(vpn)s', {'vpn': new_vpnservice})
        vpnservice_id = new_vpnservice['id']
        vpnservice = self.service_plugin._get_vpnservice(context,
                                                         vpnservice_id)
        try:
            self.validator.validate_vpnservice(context, vpnservice)
            local_address = self._get_service_local_address(
                context.elevated(), vpnservice)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Rolling back change on the neutron
                self.service_plugin.delete_vpnservice(context, vpnservice_id)

        vpnservice['external_v4_ip'] = local_address
        self.service_plugin.set_external_tunnel_ips(context,
                                                    vpnservice_id,
                                                    v4_ip=local_address)
        self._create_vpn_service(context, vpnservice)

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        # Only handle the case of admin-state-up changes
        if old_vpnservice['admin_state_up'] != vpnservice['admin_state_up']:
            # update all relevant connections
            filters = {'vpnservice_id': [vpnservice['id']]}
            connections = self.vpn_plugin.get_ipsec_site_connections(
                context, filters=filters)
            for conn in connections:
                self._update_session(conn['id'], conn,
                                     enabled=connection_enabled)

    def delete_vpnservice(self, context, vpnservice):
        self._delete_vpn_service_if_needed(context, vpnservice)
