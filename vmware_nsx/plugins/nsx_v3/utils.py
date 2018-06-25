# Copyright 2016 VMware, Inc.
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
import os
import random

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import fileutils

from neutron import version as n_version
from neutron_lib import context as q_context

from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.db import db as nsx_db
from vmware_nsx.plugins.nsx_v3 import cert_utils
from vmware_nsxlib import v3
from vmware_nsxlib.v3 import client_cert
from vmware_nsxlib.v3 import config
from vmware_nsxlib.v3 import nsx_constants

NSX_NEUTRON_PLUGIN = 'NSX Neutron plugin'
OS_NEUTRON_ID_SCOPE = 'os-neutron-id'

LOG = logging.getLogger(__name__)


class DbCertProvider(client_cert.ClientCertProvider):
    """Write cert data from DB to file and delete after use

       New provider object with random filename is created for each request.
       This is not most efficient, but the safest way to avoid race conditions,
       since backend connections can occur both before and after neutron
       fork, and several concurrent requests can occupy the same thread.
       Note that new cert filename for each request does not result in new
       connection for each request (at least for now..)
    """
    EXPIRATION_ALERT_DAYS = 30          # days prior to expiration

    def __init__(self):
        super(DbCertProvider, self).__init__(None)
        random.seed()
        self._filename = '/tmp/.' + str(random.randint(1, 10000000))

    def _check_expiration(self, expires_in_days):
        if expires_in_days > self.EXPIRATION_ALERT_DAYS:
            return

        if expires_in_days < 0:
            LOG.error("Client certificate has expired %d days ago.",
                      expires_in_days * -1)
        else:
            LOG.warning("Client certificate expires in %d days. "
                        "Once expired, service will become unavailable.",
                        expires_in_days)

    def __enter__(self):
        try:
            context = q_context.get_admin_context()
            db_storage_driver = cert_utils.DbCertificateStorageDriver(
                context)
            with client_cert.ClientCertificateManager(
                cert_utils.NSX_OPENSTACK_IDENTITY,
                None,
                db_storage_driver) as cert_manager:
                if not cert_manager.exists():
                    msg = _("Unable to load from nsx-db")
                    raise nsx_exc.ClientCertificateException(err_msg=msg)

                filename = self._filename
                if not os.path.exists(os.path.dirname(filename)):
                    if len(os.path.dirname(filename)) > 0:
                        fileutils.ensure_tree(os.path.dirname(filename))
                cert_manager.export_pem(filename)

                expires_in_days = cert_manager.expires_in_days()
                self._check_expiration(expires_in_days)
        except Exception as e:
            self._on_exit()
            raise e

        return self

    def _on_exit(self):
        if os.path.isfile(self._filename):
            os.remove(self._filename)

        self._filename = None

    def __exit__(self, type, value, traceback):
        self._on_exit()

    def filename(self):
        return self._filename


def get_client_cert_provider():
    if not cfg.CONF.nsx_v3.nsx_use_client_auth:
        return None

    if cfg.CONF.nsx_v3.nsx_client_cert_storage.lower() == 'none':
        # Admin is responsible for providing cert file, the plugin
        # should not touch it
        return client_cert.ClientCertProvider(
                cfg.CONF.nsx_v3.nsx_client_cert_file)

    if cfg.CONF.nsx_v3.nsx_client_cert_storage.lower() == 'nsx-db':
        # Cert data is stored in DB, and written to file system only
        # when new connection is opened, and deleted immediately after.
        return DbCertProvider


def get_nsxlib_wrapper(nsx_username=None, nsx_password=None, basic_auth=False):
    client_cert_provider = None
    if not basic_auth:
        # if basic auth requested, dont use cert file even if provided
        client_cert_provider = get_client_cert_provider()

    nsxlib_config = config.NsxLibConfig(
        username=nsx_username or cfg.CONF.nsx_v3.nsx_api_user,
        password=nsx_password or cfg.CONF.nsx_v3.nsx_api_password,
        client_cert_provider=client_cert_provider,
        retries=cfg.CONF.nsx_v3.http_retries,
        insecure=cfg.CONF.nsx_v3.insecure,
        ca_file=cfg.CONF.nsx_v3.ca_file,
        concurrent_connections=cfg.CONF.nsx_v3.concurrent_connections,
        http_timeout=cfg.CONF.nsx_v3.http_timeout,
        http_read_timeout=cfg.CONF.nsx_v3.http_read_timeout,
        conn_idle_timeout=cfg.CONF.nsx_v3.conn_idle_timeout,
        http_provider=None,
        max_attempts=cfg.CONF.nsx_v3.retries,
        nsx_api_managers=cfg.CONF.nsx_v3.nsx_api_managers,
        plugin_scope=OS_NEUTRON_ID_SCOPE,
        plugin_tag=NSX_NEUTRON_PLUGIN,
        plugin_ver=n_version.version_info.release_string(),
        dns_nameservers=cfg.CONF.nsx_v3.nameservers,
        dns_domain=cfg.CONF.nsx_v3.dns_domain)
    return v3.NsxLib(nsxlib_config)


def get_orphaned_dhcp_servers(plugin, nsxlib, dhcp_profile_uuid=None):
    # An orphaned DHCP server means the associated neutron network
    # does not exist or has no DHCP-enabled subnet.

    orphaned_servers = []
    server_net_pairs = []

    # Find matching DHCP servers (for a given dhcp_profile_uuid).
    response = nsxlib.dhcp_server.list()
    for dhcp_server in response['results']:
        if (dhcp_profile_uuid and
            dhcp_server['dhcp_profile_id'] != dhcp_profile_uuid):
            continue
        found = False
        neutron_obj = False
        for tag in dhcp_server.get('tags', []):
            if tag['scope'] == 'os-neutron-net-id':
                server_net_pairs.append((dhcp_server, tag['tag']))
                found = True
            if tag['scope'] == 'os-api-version':
                neutron_obj = True
        if not found and neutron_obj:
            # The associated neutron network is not defined.
            dhcp_server['neutron_net_id'] = None
            orphaned_servers.append(dhcp_server)

    # Check if there is DHCP-enabled subnet in each network.
    for dhcp_server, net_id in server_net_pairs:
        try:
            network = plugin.get_network(net_id)
        except Exception:
            # The associated neutron network is not found in DB.
            dhcp_server['neutron_net_id'] = None
            orphaned_servers.append(dhcp_server)
            continue
        dhcp_enabled = False
        for subnet_id in network['subnets']:
            subnet = plugin.get_subnet(subnet_id)
            if subnet['enable_dhcp']:
                dhcp_enabled = True
                break
        if not dhcp_enabled:
            dhcp_server['neutron_net_id'] = net_id
            orphaned_servers.append(dhcp_server)

    return orphaned_servers


def delete_orphaned_dhcp_server(context, nsxlib, server):
    # Delete an orphaned DHCP server:
    # (1) delete the attached logical DHCP port,
    # (2) delete the logical DHCP server,
    # (3) clean corresponding neutron DB entry.
    # Return True if it was deleted, or false + error if not
    try:
        response = nsxlib.logical_port.get_by_attachment('DHCP_SERVICE',
                                                         server['id'])
        if response and response['result_count'] > 0:
            nsxlib.logical_port.delete(response['results'][0]['id'])
        nsxlib.dhcp_server.delete(server['id'])
        net_id = server.get('neutron_net_id')
        if net_id:
            # Delete neutron_net_id -> dhcp_service_id mapping from the DB.
            nsx_db.delete_neutron_nsx_service_binding(
                context.session, net_id,
                nsx_constants.SERVICE_DHCP)
        return True, None
    except Exception as e:
        return False, e


def get_orphaned_networks(context, nsxlib):
    nsx_switches = nsxlib.logical_switch.list()['results']
    missing_networks = []
    for nsx_switch in nsx_switches:
        # check if it exists in the neutron DB
        net_ids = nsx_db.get_net_ids(context.session, nsx_switch['id'])
        if not net_ids:
            # Skip non-neutron networks, by tags
            neutron_net = False
            for tag in nsx_switch.get('tags', []):
                if tag.get('scope') == 'os-neutron-net-id':
                    neutron_net = True
                    nsx_switch['neutron_net_id'] = tag.get('value')
                    break
            if neutron_net:
                missing_networks.append(nsx_switch)
    return missing_networks


def get_orphaned_routers(context, nsxlib):
    nsx_routers = nsxlib.logical_router.list()['results']
    missing_routers = []
    for nsx_router in nsx_routers:
        # check if it exists in the neutron DB
        neutron_id = nsx_db.get_neutron_from_nsx_router_id(context.session,
                                                           nsx_router['id'])
        if not neutron_id:
            # Skip non-neutron routers, by tags
            for tag in nsx_router.get('tags', []):
                if tag.get('scope') == 'os-neutron-router-id':
                    nsx_router['neutron_router_id'] = tag.get('value')
                    missing_routers.append(nsx_router)
                    break
    return missing_routers
