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

# This set of policies covers l2GW and l2GW connection
# create/delete/update/get, limiting actions only to admin

rules = [
    policy.RuleDefault('create_l2_gateway',
                       'rule:admin_only',
                       description='Rule for creating l2gw'),
    policy.RuleDefault('update_l2_gateway',
                       'rule:admin_only',
                       description='Rule for updating l2gw'),
    policy.RuleDefault('get_l2_gateway',
                       'rule:admin_only',
                       description='Rule for getting l2gw'),
    policy.RuleDefault('delete_l2_gateway',
                       'rule:admin_only',
                       description='Rule for deleting l2gw'),
    policy.RuleDefault('create_l2_gateway_connection',
                       'rule:admin_only',
                       description='Rule for creating l2gw connection'),
    policy.RuleDefault('get_l2_gateway_connections',
                       'rule:admin_only',
                       description='Rule for getting l2gw connections'),
    policy.RuleDefault('get_l2_gateway_connection',
                       'rule:admin_only',
                       description='Rule for getting l2gw connection'),
    policy.RuleDefault('delete_l2_gateway_connection',
                       'rule:admin_only',
                       description='Rule for deleting l2gw connection'),

]


def list_rules():
    return rules
