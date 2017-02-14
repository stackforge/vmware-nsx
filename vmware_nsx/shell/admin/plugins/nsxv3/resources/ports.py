# Copyright 2016 VMware, Inc.  All rights reserved.
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


import logging

from oslo_config import cfg
from sqlalchemy.orm import exc

from vmware_nsx._i18n import _LE, _LI, _LW
from vmware_nsx.db import db as nsx_db
from vmware_nsx.db import nsx_models
from vmware_nsx.dvs import dvs
from vmware_nsx.plugins.nsx_v3 import plugin
from vmware_nsx.services.qos.common import utils as qos_utils
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import formatters
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils as v3_utils
from vmware_nsx.shell import resources as shell
from vmware_nsxlib.v3 import exceptions as nsx_exc
from vmware_nsxlib.v3 import resources

from neutron.callbacks import registry
from neutron import context as neutron_context
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import portsecurity_db
from neutron.extensions import allowedaddresspairs
from neutron_lib import constants as const
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)


class PortsPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                  portsecurity_db.PortSecurityDbMixin,
                  addr_pair_db.AllowedAddressPairsMixin):
    def __enter__(self):
        directory.add_plugin(const.CORE, self)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        directory.add_plugin(const.CORE, None)


def get_port_nsx_id(session, neutron_id):
    # get the nsx port id from the DB mapping
    try:
        mapping = (session.query(nsx_models.NeutronNsxPortMapping).
                   filter_by(neutron_id=neutron_id).
                   one())
        return mapping['nsx_port_id']
    except exc.NoResultFound:
        pass


def get_network_nsx_id(session, neutron_id):
    # get the nsx switch id from the DB mapping
    mappings = nsx_db.get_nsx_switch_ids(session, neutron_id)
    if not mappings or len(mappings) == 0:
        LOG.debug("Unable to find NSX mappings for neutron "
                  "network %s.", neutron_id)
        # fallback in case we didn't find the id in the db mapping
        # This should not happen, but added here in case the network was
        # created before this code was added.
        return neutron_id
    else:
        return mappings[0]


def get_port_and_profile_clients():
    _nsx_client = v3_utils.get_nsxv3_client()
    return (resources.LogicalPort(_nsx_client),
            resources.SwitchingProfile(_nsx_client))


def get_dhcp_profile_id(profile_client):
    profiles = profile_client.find_by_display_name(
        plugin.NSX_V3_DHCP_PROFILE_NAME)
    if profiles and len(profiles) == 1:
        return profiles[0]['id']
    LOG.warning(_LW("Could not find DHCP profile on backend"))


def get_spoofguard_profile_id(profile_client):
    profiles = profile_client.find_by_display_name(
        plugin.NSX_V3_PSEC_PROFILE_NAME)
    if profiles and len(profiles) == 1:
        return profiles[0]['id']
    LOG.warning(_LW("Could not find Spoof Guard profile on backend"))


def add_profile_mismatch(problems, neutron_id, nsx_id, prf_id, title):
    msg = (_LI('Wrong %(title)s profile %(prf_id)s') % {'title': title,
                                                        'prf_id': prf_id})
    problems.append({'neutron_id': neutron_id,
                     'nsx_id': nsx_id,
                     'error': msg})


@admin_utils.output_header
def list_missing_ports(resource, event, trigger, **kwargs):
    """List neutron ports that are missing the NSX backend port
    And ports with wrong switch profiles
    """
    admin_cxt = neutron_context.get_admin_context()

    with PortsPlugin() as plugin:
        neutron_ports = plugin.get_ports(admin_cxt)
        port_client, profile_client = get_port_and_profile_clients()

        # get pre-defined profile ids
        dhcp_profile_id = get_dhcp_profile_id(profile_client)
        dhcp_profile_key = resources.SwitchingProfileTypes.SWITCH_SECURITY
        spoofguard_profile_id = get_spoofguard_profile_id(profile_client)
        spoofguard_profile_key = resources.SwitchingProfileTypes.SPOOF_GUARD
        qos_profile_key = resources.SwitchingProfileTypes.QOS

        problems = []
        for port in neutron_ports:
            neutron_id = port['id']
            # get the network nsx id from the mapping table
            nsx_id = get_port_nsx_id(admin_cxt.session, neutron_id)
            if not nsx_id:
                # skip external ports
                pass
            else:
                try:
                    nsx_port = port_client.get(nsx_id)
                except nsx_exc.ResourceNotFound:
                    problems.append({'neutron_id': neutron_id,
                                     'nsx_id': nsx_id,
                                     'error': _LI('Missing from backend')})
                    continue

                # Port found on backend!
                # Check that it has all the expected switch profiles.
                # create a dictionary of the current profiles:
                profiles_dict = {}
                for prf in nsx_port['switching_profile_ids']:
                    profiles_dict[prf['key']] = prf['value']

                # DHCP port: neutron dhcp profile should be attached
                # to logical ports created for neutron DHCP but not
                # for native DHCP.
                if (port.get('device_owner') == const.DEVICE_OWNER_DHCP and
                    not cfg.CONF.nsx_v3.native_dhcp_metadata):
                    prf_id = profiles_dict[dhcp_profile_key]
                    if prf_id != dhcp_profile_id:
                        add_profile_mismatch(problems, neutron_id, nsx_id,
                                             prf_id, "DHCP security")

                # Port with QoS policy: a matching profile should be attached
                qos_policy_id = qos_utils.get_port_policy_id(admin_cxt,
                                                             neutron_id)
                if qos_policy_id:
                    qos_profile_id = nsx_db.get_switch_profile_by_qos_policy(
                        admin_cxt.session, qos_policy_id)
                    prf_id = profiles_dict[qos_profile_key]
                    if prf_id != qos_profile_id:
                        add_profile_mismatch(problems, neutron_id, nsx_id,
                                             prf_id, "QoS")

                # Port with security & fixed ips/address pairs:
                # neutron spoofguard profile should be attached
                port_sec, has_ip = plugin._determine_port_security_and_has_ip(
                    admin_cxt, port)
                addr_pair = port.get(allowedaddresspairs.ADDRESS_PAIRS)
                if port_sec and (has_ip or addr_pair):
                    prf_id = profiles_dict[spoofguard_profile_key]
                    if prf_id != spoofguard_profile_id:
                        add_profile_mismatch(problems, neutron_id, nsx_id,
                                             prf_id, "Spoof Guard")

    if len(problems) > 0:
        title = _LI("Found internal ports misconfiguration on the "
                    "NSX manager:")
        LOG.info(formatters.output_formatter(
            title, problems,
            ['neutron_id', 'nsx_id', 'error']))
    else:
        LOG.info(_LI("All internal ports verified on the NSX manager"))


def get_vm_network_device(vm_mng, vm_moref, mac_address):
    """Return the network device with MAC 'mac_address'.

    This code was inspired by Nova vif.get_network_device
    """
    hardware_devices = vm_mng.get_vm_interfaces_info(vm_moref)
    if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
        hardware_devices = hardware_devices.VirtualDevice
    for device in hardware_devices:
        if hasattr(device, 'macAddress'):
            if device.macAddress == mac_address:
                return device


def migrate_compute_ports_vms(resource, event, trigger, **kwargs):
    """Update the VMs ports on the backend after migrating nsx-v -> nsx-v3

    After using api_replay to migrate the neutron data from NSX-V to NSX-T
    we need to update the VM ports to use OpaqueNetwork instead of
    DistributedVirtualPortgroup
    """
    # Connect to the DVS manager, using the configuration parameters
    try:
        vm_mng = dvs.VMManager()
    except Exception as e:
        LOG.error(_LE("Cannot connect to the DVS: Please update the [dvs] "
                      "section in the nsx.ini file: %s"), e)
        return

    # Go over all the compute ports from the plugin
    admin_cxt = neutron_context.get_admin_context()
    port_filters = {'device_owner': ['compute:None']}
    with PortsPlugin() as plugin:
        neutron_ports = plugin.get_ports(admin_cxt, filters=port_filters)

    for port in neutron_ports:
        device_id = port.get('device_id')

        # get the vm moref & spec from the DVS
        vm_moref = vm_mng.get_vm_moref_obj(device_id)
        vm_spec = vm_mng.get_vm_spec(vm_moref)

        # Go over the VM interfaces and check if it should be updated
        update_spec = False
        for prop in vm_spec.propSet:
            if (prop.name == 'network' and
                hasattr(prop.val, 'ManagedObjectReference')):
                for net in prop.val.ManagedObjectReference:
                    if net._type == 'DistributedVirtualPortgroup':
                        update_spec = True

        if not update_spec:
            LOG.info(_LI("No need to update the spec of vm %s"), device_id)
            continue

        # find the old interface by it's mac and delete it
        device = get_vm_network_device(vm_mng, vm_moref, port['mac_address'])
        if device is None:
            LOG.warning(_LW("No device with MAC address %s exists on the VM"),
                        port['mac_address'])
            continue
        device_type = device.__class__.__name__

        LOG.info(_LI("Detaching old interface from VM %s"), device_id)
        vm_mng.detach_vm_interface(vm_moref, device)

        # add the new interface as OpaqueNetwork
        LOG.info(_LI("Attaching new interface to VM %s"), device_id)
        nsx_net_id = get_network_nsx_id(admin_cxt.session, port['network_id'])
        vm_mng.attach_vm_interface(vm_moref, port['id'], port['mac_address'],
                                   nsx_net_id, device_type)


registry.subscribe(list_missing_ports,
                   constants.PORTS,
                   shell.Operations.LIST_MISMATCHES.value)

registry.subscribe(migrate_compute_ports_vms,
                   constants.PORTS,
                   shell.Operations.NSX_MIGRATE_V_V3.value)
