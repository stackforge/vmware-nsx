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
    policy.RuleDefault('create_network_profile',
                       'rule:admin_only',
                       description='Rule of creating network profile'),
    policy.RuleDefault('update_network_profile',
                       'rule:admin_only',
                       description='Rule of updating network profile'),
    policy.RuleDefault('delete_network_profile',
                       'rule:admin_only',
                       description='Rule of deleting network profile'),
    policy.RuleDefault('get_network_profile',
                       '',
                       description='Rule of getting network profile'),
    policy.RuleDefault('get_network_profiles',
                       '',
                       description='Rule of getting network profiles'),
    policy.RuleDefault('update_policy_profiles',
                       'rule:admin_only',
                       description='Rule of getting network profiles'),
    policy.RuleDefault('get_policy_profile',
                       '',
                       description='Rule of getting policy profile'),
    policy.RuleDefault('get_policy_profiles',
                       '',
                       description='Rule of getting policy profile'),
]


def list_rules():
    return rules