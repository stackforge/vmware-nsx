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
from oslo_db import exception as d_exc

from neutron.api.v2 import attributes as attr
from neutron import context as neutron_context
from neutron.db import db_base_plugin_v2
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.plugins.vmware.extensions import vnicindex as vnicidx
from neutron.tests.unit import test_db_plugin
from vmware_nsx.neutron.plugins.vmware.dbexts import vnic_index_db
from vmware_nsx.neutron.tests.unit import vmware


DB_PLUGIN_KLASS = ('vmware_nsx.neutron.tests.unit.vmware.extensions.'
                   'test_vnic_index.VnicIndexTestPlugin')

_uuid = uuidutils.generate_uuid


class VnicIndexTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                          vnic_index_db.VnicIndexDbMixin):

    supported_extension_aliases = ["vnic-index"]

    def update_port(self, context, id, port):
        p = port['port']
        current_port = super(VnicIndexTestPlugin, self).get_port(context, id)
        vnic_idx = p.get(vnicidx.VNIC_INDEX)
        device_id = current_port['device_id']
        if attr.is_attr_set(vnic_idx) and device_id != '':
            self._set_port_vnic_index_mapping(
                context, id, device_id, vnic_idx)

        with context.session.begin(subtransactions=True):
            p = port['port']
            ret_port = super(VnicIndexTestPlugin, self).update_port(
                context, id, port)
            vnic_idx = current_port.get(vnicidx.VNIC_INDEX)
            if (attr.is_attr_set(vnic_idx) and
                device_id != ret_port['device_id']):
                self._delete_port_vnic_index_mapping(
                    context, id)
        return ret_port

    def delete_port(self, context, id):
        port_db = self.get_port(context, id)
        vnic_idx = port_db.get(vnicidx.VNIC_INDEX)
        if attr.is_attr_set(vnic_idx):
            self._delete_port_vnic_index_mapping(context, id)
        with context.session.begin(subtransactions=True):
            super(VnicIndexTestPlugin, self).delete_port(context, id)


class VnicIndexDbTestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        plugin = plugin or DB_PLUGIN_KLASS
        cfg.CONF.set_override('api_extensions_path', vmware.NSXEXT_PATH)
        super(VnicIndexDbTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def _port_index_update(self, port_id, index):
        data = {'port': {'vnic_index': index}}
        req = self.new_update_request('ports', data, port_id)
        res = self.deserialize('json', req.get_response(self.api))
        return res

    def test_vnic_index_db(self):
        plugin = manager.NeutronManager.get_plugin()
        vnic_index = 2
        device_id = _uuid()
        context = neutron_context.get_admin_context()
        with self.port(device_id=device_id,
                       device_owner='compute:None') as port:
            port_id = port['port']['id']
            res = self._port_index_update(port_id, vnic_index)
            self.assertEqual(res['port'][vnicidx.VNIC_INDEX], vnic_index)
            # Port should be associated with at most one vnic index
            self.assertRaises(d_exc.DBDuplicateEntry,
                              plugin._set_port_vnic_index_mapping,
                              context, port_id, device_id, 1)
            # Only one Port can be associated with a specific index on a device
            self.assertRaises(d_exc.DBDuplicateEntry,
                              plugin._set_port_vnic_index_mapping,
                              context, _uuid(), device_id, vnic_index)
        # Check that the call for _delete_port_vnic_index remove the row from
        # the table

        # TODO(kobis): deletion was removed from port - fix this assert
        # self.assertIsNone(plugin._get_port_vnic_index(context, port_id))


class TestVnicIndex(VnicIndexDbTestCase):
    pass
