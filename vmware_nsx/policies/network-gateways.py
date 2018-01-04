# Copyright 2017 VMware, Inc.
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

from oslo_policy import policy


rules = [
    policy.RuleDefault('create_network_gateway',
                       'rule:admin_or_owner',
                       description='Rule of creating network gateway'),
    policy.RuleDefault('update_network_gateway',
                       'rule:admin_or_owner',
                       description='Rule of updating network gateway'),
    policy.RuleDefault('delete_network_gateway',
                       'rule:admin_or_owner',
                       description='Rule of deleting network gateway'),
    policy.RuleDefault('connect_network',
                       'rule:admin_or_owner',
                       description='Rule of connecting network'),
    policy.RuleDefault('disconnect_network',
                       'rule:admin_or_owner',
                       description='Rule of disconnecting network'),
    policy.RuleDefault('create_gateway_device',
                       'rule:admin_or_owner',
                       description='Rule of creating gateway device'),
    policy.RuleDefault('update_gateway_device',
                       'rule:admin_or_owner',
                       description='Rule of updating gateway device'),
    policy.RuleDefault('delete_gateway_device',
                       'rule:admin_or_owner',
                       description='Rule of deleting gateway device'),


]


def list_rules():
    return rules