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

# This set of policies covers provider security group extension permissions,
# limiting actions only to admin

rules = [
    policy.RuleDefault('create_port:provider_security_groups',
                       'rule:admin_only',
                       description='Rule for creating port security groups'),
    policy.RuleDefault('update_port:provider_security_groups',
                       'rule:admin_only',
                       description='Rule for updating port security groups'),
]


def list_rules():
    return rules
