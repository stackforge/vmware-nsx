# Copyright 2017 VMware Inc
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

from tempest.lib import decorators

from vmware_nsx_tempest.heat import heat


class HeatTest(heat.HeatSmokeTest):
    """
     Deploy and Test Neutron Resources using HEAT.

     The script loads the neutron resources from template and fully
    validates successful deployment of all resources from the template.

    """

    @decorators.idempotent_id('f693a425-b018-4cde-96ab-cdd5b858e15c')
    def test_topo1_created_resources(self):
        """Verifies created resources from template ."""
        self.check_created_resources()

    @decorators.idempotent_id('3c3ccfcb-e50b-4372-82dc-d5b473acd506')
    def test_topo1_created_network(self):
        """Verifies created neutron networks."""
        self.check_created_network()

    @decorators.idempotent_id('b3b103a7-69b2-42ea-a1b8-aa11cc551df9')
    def test_topo1_created_router(self):
        """Verifies created router."""
        self.check_created_router()

    @decorators.idempotent_id('2b29dfef-6d9f-4a70-9377-af432100ef10')
    def test_topo1_created_server(self):
        """Verifies created sever."""
        self.check_created_server()

    @decorators.idempotent_id('d937a607-aa5e-4cf1-bbf9-00044cbe7190')
    def test_topo1_same_network(self):
        """Verifies same network connnectivity for Topology 1 """
        self.check_topo1_same_network_connectivity()

    @decorators.idempotent_id('fdbc8b1a-755a-4b37-93e7-0a268e422f05')
    def test_topo1_cross_network(self):
        """Verifies cross network connnectivity for Topology 1 """
        self.check_topo1_cross_network_connectivity()
