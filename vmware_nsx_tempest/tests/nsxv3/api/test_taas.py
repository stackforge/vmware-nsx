# Copyright 2016 VMware Inc
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

from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test
from tempest.lib import exceptions as lib_exc
from vmware_nsx_tempest.services import taas_client  
from vmware_nsx_tempest._i18n import _LI
from vmware_nsx_tempest._i18n import _LW


from vmware_nsx_tempest.services import nsxv3_client

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TaaSJsonTest(base.BaseNetworkTest):

    @classmethod
    def skip_checks(cls):
        super(TaaSJsonTest,cls).skip_checks()
        if not test.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)
        if not CONF.network.public_network_id:
            msg = "Public network id not found."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TaaSJsonTest,cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id
        # Create the topology to test floating IP
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        for i in range(4):
            cls.create_port(cls.network)


    @classmethod
    def setup_clients(cls):
        super(TaaSJsonTest,cls).setup_clients()
        try :
          cls.tclient = taas_client.get_client(cls.manager)
          cls.nsx = nsxv3_client.NSXV3Client(CONF.nsxv3.nsx_manager,
                                             CONF.nsxv3.nsx_user,
                                             CONF.nsxv3.nsx_password)
        except AttributeError as attribute_err:
          LOG.warning(
              _LW("Failed to locate the attribute, Error: %(err_msg)s") %
              {"err_msg": attribute_err.__str__()})


    def _createfloating_ip(self,portindex):
        create_body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[int(portindex)]['id'])
        fip = create_body['floatingip']
        return fip


    def _resource_clean(self,fip,tapservice_id,tapflow_id ):
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        fip['id'])
        if tapflow_id != 'null' :
            self.tclient.delete_tf(tapflow_id)
        if tapservice_id != 'null' :
            self.tclient.delete_ts(tapservice_id)


       

    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc2b1c-85d7-11e6-ae22-56b6b6499611')
    def test_create_tap_service_new(self):
        """
         Tap service create api is tested , Tap Service is created with destination port associated with floating ip
        """
        LOG.info(_LI("Testing Tap Service Create api with floating ip associated to destination port "))
        # Create a floating ip
        fip = self._createfloating_ip(0)
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device1 = {"description": 'mytap555', "name": tap_service_name,
                   "port_id": self.ports[0]['id'],
                   "tenant_id": self.ports[0]['tenant_id']}
        rsp = self.tclient.create_ts(**device1)
        LOG.info(_LI("response from tap serive create : %(rsp)s") % {"rsp": rsp})
        self.assertEqual('201',
                         rsp.response["status"],
                         "Response code is not 201 ")
        self.assertIn(self.ports[0]['id'],rsp['tap_service']['port_id'])
        self._resource_clean(fip,rsp['tap_service']['id'],'null')
       

    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc2b1c-85d7-11e6-ae22-56b6b6499611')
    def test_create_tap_service(self):
        """
         Tap service create api is tested , Tap Service is created with destination port associated with floating ip
        """
        LOG.info(_LI("Testing Tap Service Create api with floating ip associated to destination port "))
        # Create a floating ip
        fip = self._createfloating_ip(0)
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device1 = {"description": 'mytap555', "name": tap_service_name,
                   "port_id": self.ports[0]['id'],
                   "tenant_id": self.ports[0]['tenant_id']}
        rsp = self.tclient.create_ts(**device1)
        LOG.info(_LI("response from tap serive create : %(rsp)s") % {"rsp": rsp})
        self.assertEqual('201',
                         rsp.response["status"],
                         "Response code is not 201 ")
        self.assertIn(self.ports[0]['id'],rsp['tap_service']['port_id'])
        self._resource_clean(fip, rsp['tap_service']['id'], 'null')


    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc2ee6-85d7-11e6-ae22-56b6b6499611')
    def test_list_tap_service(self):
        """
         Tap Service List api is tested
        """
        LOG.info(_LI("Testing Tap Service List api with floating ip associated to destination port "))
        # Create a floating ip
        fip = self._createfloating_ip(0)
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device1 = {"description": 'mytap555', "name": tap_service_name,
                   "port_id": self.ports[0]['id'],
                   "tenant_id": self.ports[0]['tenant_id']}
        rsp_create = self.tclient.create_ts(**device1)
        rsp_list = self.tclient.list_ts()
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_list})
        self.assertEqual('200',
                         rsp_list.response["status"],
                         "Response code is not 200 ")
        self.assertIn(tap_service_name,rsp_list['tap_services'][0]['name'])
        self.assertIn(self.ports[0]['id'], rsp_list['tap_services'][0]['port_id'])
        self._resource_clean(fip, 'null', 'null')

 
    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc309e-85d7-11e6-ae22-56b6b6499611')
    def test_show_tap_service(self):
        """
         Tap Service List api is tested
        """
        LOG.info(_LI("Testing Tap Service Show api with floating ip associated to destination port "))
        # Create a floating ip
        fip = self._createfloating_ip(0)
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device1 = {"description": 'mytap555', "name": tap_service_name,
                   "port_id": self.ports[0]['id'],
                   "tenant_id": self.ports[0]['tenant_id']}
        rsp_create = self.tclient.create_ts(**device1)
        rsp_show = self.tclient.show_ts(rsp_create['tap_service']['id'])
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_show})
        self.assertEqual('200',
                         rsp_show.response["status"],
                         "Response code is not 200 ")
        self.assertIn(tap_service_name,rsp_show['tap_service']['name'])
        self.assertIn(self.ports[0]['id'], rsp_show['tap_service']['port_id'])
        self._resource_clean(fip, rsp_create['tap_service']['id'], 'null')


    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc3210-85d7-11e6-ae22-56b6b6499611')
    def test_delete_tap_service(self):
        """
         Tap Service Delete api is tested
        """
        LOG.info(_LI("Testing Tap delete api with floating ip associated to destination port "))
        # Create a floating ip
        fip = self._createfloating_ip(0)
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device1 = {"description": 'mytap555', "name": tap_service_name,
                   "port_id": self.ports[0]['id'],
                   "tenant_id": self.ports[0]['tenant_id']}
        rsp_create = self.tclient.create_ts(**device1)
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_create})
        self.assertEqual('201',
                         rsp_create.response["status"],
                         "Response code is not 201 ")
        rsp_delete = self.tclient.delete_ts(rsp_create['tap_service']['id'])
        self.assertEqual('204',
                         rsp_delete.response["status"],
                         "Response code is not 204 ")
        rsp_list = self.tclient.list_ts()
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_list})
        self._resource_clean(fip,'null' , 'null')


    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc3666-85d7-11e6-ae22-56b6b6499611')
    def test_create_tap_flow(self):
        """
         Tap flow create api is tested , Tap Service is created with destination port associated with floating ip
        """
        LOG.info(_LI("Testing Tap flow create api with direction BOTH and  floating ip associated to destination port "))
        # Create a floating ip
        fip = self._createfloating_ip(0)
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device_tap_service = {"description": 'tapservice1', "name": tap_service_name,
                              "port_id": self.ports[0]['id'],
                              "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_service = self.tclient.create_ts(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") % {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        tap_flow_name = data_utils.rand_name('tapflow-ch')
        device_tap_flow = {"description": 'tapflow1', "direction": "BOTH",
                           "name": tap_flow_name,"source_port": self.ports[1]['id'],
                           "tap_service_id": rsp_tap_service['tap_service']['id'] , "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_flow = self.tclient.create_tf(**device_tap_flow)
        LOG.info(_LI("response from flow : %(rsp)s") % {"rsp": rsp_tap_flow})
        self.assertEqual('201',
                         rsp_tap_flow.response["status"],
                         "Response code is not 201 ")
        self.assertIn(self.ports[1]['id'], rsp_tap_flow['tap_flow']['source_port'])
        self.assertEqual(tap_flow_name,rsp_tap_flow['tap_flow']['name'])
        self.assertEqual(device_tap_flow['direction'],rsp_tap_flow['tap_flow']['direction'])
        self.assertEqual(rsp_tap_service['tap_service']['id'], rsp_tap_flow['tap_flow']['tap_service_id'])
        self._resource_clean(fip, rsp_tap_service['tap_service']['id'],rsp_tap_flow['tap_flow']['id'] )



    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc37f6-85d7-11e6-ae22-56b6b6499611')
    def test_create_tap_flow_multiple(self):
        """
         Tap flow create api is tested , Tap Service is created with destination port associated with floating ip
        """
        LOG.info(_LI("Multiple Tap flow's created  with direction IN and OUT and  floating ip associated to destination port "))
        # Create a floating ip 1
        fip1 = self._createfloating_ip(0)
        # Create a floating ip 2
        fip2 = self._createfloating_ip(1)
        tap_service_name1 = data_utils.rand_name('tapservice-ch')
        device_tap_service1 = {"description": 'tapservice1', "name": tap_service_name1,
                              "port_id": self.ports[0]['id'],
                              "tenant_id": self.ports[0]['tenant_id']}
        tap_service_name2 = data_utils.rand_name('tapservice-ch')
        device_tap_service2 = {"description": 'tapservice2', "name": tap_service_name2,
                              "port_id": self.ports[1]['id'],
                              "tenant_id": self.ports[1]['tenant_id']}
        rsp_tap_service1 = self.tclient.create_ts(**device_tap_service1)
        rsp_tap_service2 = self.tclient.create_ts(**device_tap_service2)
        LOG.info(_LI("response from tap service1 and tap service2  : %(rsp1)s  %(rsp2)s ") % {"rsp1": rsp_tap_service1 ,"rsp2": rsp_tap_service2 })
        tap_flow_name1 = data_utils.rand_name('tapflow-ch')
        device_tap_flow1 = {"description": 'tapflow1', "direction": "IN",
                           "name": tap_flow_name1,"source_port": self.ports[2]['id'],
                           "tap_service_id": rsp_tap_service1['tap_service']['id'] , "tenant_id": self.ports[0]['tenant_id']}
        tap_flow_name2 = data_utils.rand_name('tapflow-ch')
        device_tap_flow2 = {"description": 'tapflow2', "direction": "OUT",
                           "name": tap_flow_name2,"source_port": self.ports[3]['id'],
                           "tap_service_id": rsp_tap_service2['tap_service']['id'] , "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_flow1 = self.tclient.create_tf(**device_tap_flow1)
        rsp_tap_flow2 = self.tclient.create_tf(**device_tap_flow2)
        LOG.info(_LI("response from tap flow1 and tap flow2  : %(rsp1)s  %(rsp2)s ") % {"rsp1": rsp_tap_flow1,
                                                                                        "rsp2": rsp_tap_flow2})
        self.assertEqual(tap_flow_name1,rsp_tap_flow1['tap_flow']['name'])
        self.assertEqual(tap_flow_name2,rsp_tap_flow2['tap_flow']['name'])
        self.assertEqual(device_tap_flow1['direction'],rsp_tap_flow1['tap_flow']['direction'])
        self.assertEqual(device_tap_flow2['direction'], rsp_tap_flow2['tap_flow']['direction'])
        self._resource_clean(fip1, rsp_tap_service1['tap_service']['id'], rsp_tap_flow1['tap_flow']['id'])
        self._resource_clean(fip2, rsp_tap_service2['tap_service']['id'], rsp_tap_flow2['tap_flow']['id'])


    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc395e-85d7-11e6-ae22-56b6b6499611')
    def test_list_tap_flow(self):
        """
         Tap flow list api is tested , Tap Service is created with destination port associated with floating ip
        """
        LOG.info(_LI("Testing Tap Flow list api with floating ip associated to destination port "))
        # Create a floating ip
        fip = self._createfloating_ip(0)
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device_tap_service = {"description": 'tapservice1', "name": tap_service_name,
                              "port_id": self.ports[0]['id'],
                              "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_service = self.tclient.create_ts(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") % {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        tap_flow_name = data_utils.rand_name('tapflow-ch')
        device_tap_flow = {"description": 'tapflow1', "direction": "BOTH",
                           "name": tap_flow_name,"source_port": self.ports[1]['id'],
                           "tap_service_id": rsp_tap_service['tap_service']['id'] , "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_flow = self.tclient.create_tf(**device_tap_flow)
        LOG.info(_LI("response from flow : %(rsp)s") % {"rsp": rsp_tap_flow})
        self.assertEqual('201',
                         rsp_tap_flow.response["status"],
                         "Response code is not 201 ")
        self.assertIn(self.ports[1]['id'], rsp_tap_flow['tap_flow']['source_port'])
        self.assertEqual(tap_flow_name,rsp_tap_flow['tap_flow']['name'])
        self.assertEqual(device_tap_flow['direction'],rsp_tap_flow['tap_flow']['direction'])
        self.assertEqual(rsp_tap_service['tap_service']['id'], rsp_tap_flow['tap_flow']['tap_service_id'])
        rsp_tap_list_flow = self.tclient.list_tf()
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_tap_list_flow})
        self.assertEqual('200',
                         rsp_tap_list_flow.response["status"],
                         "Response code is not 200 ")
        self.assertIn(tap_flow_name,rsp_tap_list_flow['tap_flows'][0]['name'])
        self.assertIn(self.ports[1]['id'], rsp_tap_list_flow['tap_flows'][0]['source_port'])
        self._resource_clean(fip, rsp_tap_service['tap_service']['id'], rsp_tap_flow['tap_flow']['id'])



    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc3ac6-85d7-11e6-ae22-56b6b6499611')
    def test_show_tap_flow(self):
        """
         Tap flow show api is tested , Tap Service is created with destination port associated with floating ip
        """
        LOG.info(_LI("Testing Tap Service Show api with floating ip associated to destination port "))
        # Create a floating ip
        fip = self._createfloating_ip(0)
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device_tap_service = {"description": 'tapservice1', "name": tap_service_name,
                              "port_id": self.ports[0]['id'],
                              "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_service = self.tclient.create_ts(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") % {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        tap_flow_name = data_utils.rand_name('tapflow-ch')
        device_tap_flow = {"description": 'tapflow1', "direction": "BOTH",
                           "name": tap_flow_name,"source_port": self.ports[1]['id'],
                           "tap_service_id": rsp_tap_service['tap_service']['id'] , "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_flow = self.tclient.create_tf(**device_tap_flow)
        LOG.info(_LI("response from flow : %(rsp)s") % {"rsp": rsp_tap_flow})
        self.assertEqual('201',
                         rsp_tap_flow.response["status"],
                         "Response code is not 201 ")
        self.assertIn(self.ports[1]['id'], rsp_tap_flow['tap_flow']['source_port'])
        self.assertEqual(tap_flow_name,rsp_tap_flow['tap_flow']['name'])
        self.assertEqual(device_tap_flow['direction'],rsp_tap_flow['tap_flow']['direction'])
        self.assertEqual(rsp_tap_service['tap_service']['id'], rsp_tap_flow['tap_flow']['tap_service_id'])
        rsp_tap_flow_show = self.tclient.show_tf(rsp_tap_flow['tap_flow']['id'])
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_tap_flow_show})
        self.assertEqual('200',
                         rsp_tap_flow_show.response["status"],
                         "Response code is not 200 ")
        self.assertIn(tap_flow_name,rsp_tap_flow_show['tap_flow']['name'])
        self.assertIn(self.ports[1]['id'], rsp_tap_flow_show['tap_flow']['source_port'])
        self._resource_clean(fip, rsp_tap_service['tap_service']['id'], rsp_tap_flow['tap_flow']['id'])



    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc3bde-85d7-11e6-ae22-56b6b6499611')
    def test_delete_tap_flow(self):
        """
         Tap flow delete api is tested , Tap Service is created with destination port associated with floating ip
        """
        LOG.info(_LI("Testing Tap flow delete api with floating ip associated to destination port "))
        # Create a floating ip
        fip = self._createfloating_ip(0)
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device_tap_service = {"description": 'tapservice1', "name": tap_service_name,
                              "port_id": self.ports[0]['id'],
                              "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_service = self.tclient.create_ts(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") % {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        tap_flow_name = data_utils.rand_name('tapflow-ch')
        device_tap_flow = {"description": 'tapflow1', "direction": "BOTH",
                           "name": tap_flow_name,"source_port": self.ports[1]['id'],
                           "tap_service_id": rsp_tap_service['tap_service']['id'] , "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_flow = self.tclient.create_tf(**device_tap_flow)
        LOG.info(_LI("response from flow : %(rsp)s") % {"rsp": rsp_tap_flow})
        self.assertEqual('201',
                         rsp_tap_flow.response["status"],
                         "Response code is not 201 ")
        self.assertIn(self.ports[1]['id'], rsp_tap_flow['tap_flow']['source_port'])
        self.assertEqual(tap_flow_name,rsp_tap_flow['tap_flow']['name'])
        self.assertEqual(device_tap_flow['direction'],rsp_tap_flow['tap_flow']['direction'])
        self.assertEqual(rsp_tap_service['tap_service']['id'], rsp_tap_flow['tap_flow']['tap_service_id'])
        rsp_tap_flow_delete = self.tclient.delete_tf(rsp_tap_flow['tap_flow']['id'])
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_tap_flow_delete})
        self.assertEqual('204',
                         rsp_tap_flow_delete.response["status"],
                         "Response code is not 204 ")
        rsp_tap_list_flow = self.tclient.list_tf()
        LOG.info(_LI("response from tap list : %(rsp)s") % {"rsp": rsp_tap_list_flow})
        self._resource_clean(fip, rsp_tap_service['tap_service']['id'], 'null')


    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc3cba-85d7-11e6-ae22-56b6b6499611')
    def test_create_tap_flow_negative_nofloatingip(self):
        """
         Tap flow create api is tested , Tap Service is created with destination port associated to non floating ip
        """
        LOG.info(_LI("Testing Tap flow create api with non floating ip associated to destination port "))
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device_tap_service = {"description": 'tapservice1', "name": tap_service_name,
                              "port_id": self.ports[0]['id'],
                              "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_service = self.tclient.create_ts(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") % {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        tap_flow_name = data_utils.rand_name('tapflow-ch')
        device_tap_flow = {"description": 'tapflow1', "direction": "BOTH",
                           "name": tap_flow_name,"source_port": self.ports[1]['id'],
                           "tap_service_id": rsp_tap_service['tap_service']['id'] , "tenant_id": self.ports[0]['tenant_id']}
        try :
           self.tclient.create_ts(**device_tap_service)
        except exception as e :
           print(e)
           LOG.info(_LI("response from  exception  %(rsp)s") % {"rsp": e})

          
    @test.attr(type='nsxv3')
    @test.idempotent_id('66bc3dd2-85d7-11e6-ae22-56b6b6499611')
    def test_create_tap_flow_negative_nosrcport(self):
        """
         Tap flow create api is tested with non existent src port
        """
        LOG.info(_LI("Testing Tap flow create api with non existent src port  "))
        tap_service_name = data_utils.rand_name('tapservice-ch')
        device_tap_service = {"description": 'tapservice1', "name": tap_service_name,
                              "port_id": self.ports[0]['id'],
                              "tenant_id": self.ports[0]['tenant_id']}
        rsp_tap_service = self.tclient.create_ts(**device_tap_service)
        LOG.info(_LI("response from tap service : %(rsp)s") % {"rsp": rsp_tap_service})
        self.assertEqual('201',
                         rsp_tap_service.response["status"],
                         "Response code is not 201 ")
        tap_flow_name = data_utils.rand_name('tapflow-ch')
        device_tap_flow = {"description": 'tapflow1', "direction": "BOTH",
                           "name": tap_flow_name,"source_port": '2ad76061-252e-xxxx-9d0f-dd94188be9cc',
                           "tap_service_id": rsp_tap_service['tap_service']['id'] , "tenant_id": self.ports[0]['tenant_id']}
        try :
           self.tclient.create_ts(**device_tap_service)
        except exception as e :
           print(e)
           LOG.info(_LI("response from  exception  %(rsp)s") % {"rsp": e})

 
