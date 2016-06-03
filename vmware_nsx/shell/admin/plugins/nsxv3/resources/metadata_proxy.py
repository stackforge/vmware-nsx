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

from neutron.callbacks import registry
from oslo_config import cfg

from vmware_nsx._i18n import _LI, _LE
from vmware_nsx.common import nsx_constants
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils
import vmware_nsx.shell.nsxadmin as shell

LOG = logging.getLogger(__name__)
neutron_client = utils.NeutronDbClient()


@admin_utils.output_header
def nsx_update_metadata_proxy(resource, event, trigger, **kwargs):
    """Update Metadata proxy on NSXv3 CrossHairs."""

    if not kwargs['property']:
        LOG.error(_LE("Need to specify NSX manager"))
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    if 'mgr-ip' not in properties:
        LOG.error(_LE("Need to specify mgr-ip"))
        return
    mgr_ip = properties['mgr-ip']
    mgr_user = properties.get('mgr-user', 'admin')
    mgr_passwd = properties.get('mgr-passwd', 'default')
    nsx_client = utils.NSXClient(mgr_ip, mgr_user, mgr_passwd)

    for network in neutron_client.get_networks():
        # For each Neutron network, create a logical switch port with
        # MD-Proxy attachment.
        lswitch_id = neutron_client.net_id_to_lswitch_id(network['id'])
        if lswitch_id:
            attachment = {'attachment_type': nsx_constants.ATTACHMENT_MDPROXY,
                          'id': cfg.CONF.nsx_v3.metadata_proxy_uuid}
            nsx_client.create_logical_switch_port(lswitch_id, attachment)
            LOG.info(_LI("Enabled native metadata proxy for network %s") %
                     network['id'])
        else:
            LOG.error(_LE("Unable to find logical switch for network %s") %
                      network['id'])

registry.subscribe(nsx_update_metadata_proxy,
                   constants.METADATA_PROXY,
                   shell.Operations.NSX_UPDATE.value)
