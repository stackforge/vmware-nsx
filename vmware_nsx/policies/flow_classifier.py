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
    policy.RuleDefault('create_flow_classifier',
                       'rule:admin_only',
                       description='Rule of creating flow classifier'),
    policy.RuleDefault('update_flow_classifier',
                       'rule:admin_only',
                       description='Rule of updating flow classifier'),
    policy.RuleDefault('delete_flow_classifier',
                       'rule:admin_only',
                       description='Rule of delete flow classifier'),
    policy.RuleDefault('get_flow_classifier',
                       'rule:admin_only',
                       description='Rule of getting flow classifier'),
]


def list_rules():
    return rules
