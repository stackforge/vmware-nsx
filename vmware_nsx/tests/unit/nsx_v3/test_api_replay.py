# Copyright (c) 2015 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_config import cfg

from vmware_nsx.tests.unit.nsx_v3 import test_plugin


class TestApiReplay(test_plugin.NsxV3PluginTestCaseMixin):

    def setUp(self, plugin=None, ext_mgr=None, service_plugins=None):
        # enables api_replay_mode for these tests

        cfg.CONF.set_override('api_replay_mode', True, 'nsx_v3')
        super(TestApiReplay, self).setUp()

    def test_create_port_specify_id(self):
        with self.subnet() as subnet:
            with self.port(subnet=subnet) as port:
                data = {'port': {'id': 'my_port_id'}}
                req = self.new_update_request('ports',
                                              data, port['port']['id'])
                res = self.deserialize('json', req.get_response(self.api))
                self.assertEqual(res['port']['id'],
                                 data['port']['id'])
                print res
                raise TypeError
