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

import time

from neutron.api.v2 import attributes as attr
from neutron import context as neutron_context
from neutron.extensions import providernet as pnet
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx.neutron.plugins.vmware.common import exceptions as nsxv_exc
from vmware_nsx.neutron.plugins.vmware.common import nsxv_constants
from vmware_nsx.neutron.plugins.vmware.dbexts import db as nsx_db
from vmware_nsx.neutron.plugins.vmware.dbexts import nsxv_db
from vmware_nsx.openstack.common._i18n import _LE

NET_WAIT_INTERVAL = 240
NET_CHECK_INTERVAL = 10

LOG = logging.getLogger(__name__)


class NsxvInternalNet(object):

    def __init__(self, nsxv_plugin):
        self.nsxv_plugin = nsxv_plugin
        self.context = neutron_context.get_admin_context()

    def get_internal_network_at_backend(self, network_purpose,
                                        net_type='vxlan'):
        internal_net = self.get_internal_network(network_purpose, net_type)
        if internal_net:
            mappings = nsx_db.get_nsx_switch_ids(self.context.session,
                                                 internal_net)
            if mappings:
                return mappings[0]
        LOG.error(_LE("Failed to get the network ref at the backend"))

    def get_internal_network(self, network_purpose, net_type='vxlan'):
        internal_net = None

        try:
            nsxv_db.create_nsxv_internal_network(
                self.context.session,
                network_purpose,
                None)
        except db_exc.DBDuplicateEntry:
            # We may have a race condition, where another Neutron instance
            #  initialized these elements. Use existing elements
            try:
                return self._get_internal_net_wait_for_creation(
                    network_purpose)
            except Exception as e:
                LOG.exception(_LE("Exception %(exc)s while get internal"
                                  "network for %(purpose)s"),
                              {'exc': e,
                               'purpose': network_purpose})
                return

        try:
            internal_net = self._create_internal_network(
                network_purpose, net_type)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                nsxv_db.delete_nsxv_internal_network(
                    self.context.session,
                    network_purpose)

                # if network is created, clean up
                if internal_net:
                    self.nsxv_plugin.delete_network(self.context, internal_net)

                LOG.exception(_LE("Exception %(exc)s while creating internal "
                                  "network for %(purpose)s"),
                              {'exc': e,
                               'purpose': network_purpose})

        # Update the new network_id in DB
        nsxv_db.update_nsxv_internal_network(
            self.context.session,
            network_purpose,
            internal_net)

        return internal_net

    def _get_internal_net_wait_for_creation(self, network_purpose):
        ctr = 0
        net_id = None
        while net_id is None and ctr < NET_WAIT_INTERVAL:
            # Another neutron instance may be in the process of creating this
            # network. If so, we will have a network with a NULL network id.
            # Therefore, if we have a network entry, we wail for its ID to show
            # up in the DB entry. If no entry exists, we exit and create the
            # network.
            net_list = nsxv_db.get_nsxv_internal_network(
                self.context.session,
                network_purpose)

            if net_list:
                net_id = net_list[0]['network_id']

                # Network found - do we have an ID?
                if net_id:
                    return net_id
            else:
                # No network creation in progress - exit.
                return

            self.context.session.expire_all()
            ctr += NET_CHECK_INTERVAL
            time.sleep(NET_CHECK_INTERVAL)

        error = _('Network creation on other neutron instance timed out')
        raise nsxv_exc.NsxPluginException(err_msg=error)

    def _create_internal_network(self, network_purpose, net_type='vxlan'):
        # Neutron requires a network to have some tenant_id
        tenant_id = nsxv_constants.INTERNAL_TENANT_ID

        net_data = {'network': {'name': network_purpose,
                                'admin_state_up': True,
                                'port_security_enabled': False,
                                'shared': False,
                                'tenant_id': tenant_id}}
        if net_type == 'flat':
            net_data['network'][pnet.NETWORK_TYPE] = 'flat'
            net_data['network'][pnet.PHYSICAL_NETWORK] = (
                attr.ATTR_NOT_SPECIFIED)
            net_data['network'][pnet.SEGMENTATION_ID] = (
                attr.ATTR_NOT_SPECIFIED)
        net = self.nsxv_plugin.create_network(self.context, net_data)

        return net['id']
