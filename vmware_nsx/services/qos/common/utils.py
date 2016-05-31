# Copyright 2016 VMware, Inc.
#
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

from neutron.objects.qos import policy as qos_policy


def update_network_policy_binding(context, net_id, new_policy_id):
    # detach the old policy (if exists) from the network
    old_policy = qos_policy.QosPolicy.get_network_policy(
        context, net_id)
    if old_policy:
        if old_policy.id == new_policy_id:
            return
        old_policy.detach_network(net_id)

    # attach the new policy (if exists) to the network
    if new_policy_id is not None:
        new_policy = qos_policy.QosPolicy.get_object(
            context, id=new_policy_id)
        if new_policy:
            new_policy.attach_network(net_id)


def update_port_policy_binding(context, port_id, new_policy_id):
    # detach the old policy (if exists) from the port
    old_policy = qos_policy.QosPolicy.get_port_policy(
        context, port_id)
    if old_policy:
        if old_policy.id == new_policy_id:
            return
        old_policy.detach_port(port_id)

    # attach the new policy (if exists) to the port
    if new_policy_id is not None:
        new_policy = qos_policy.QosPolicy.get_object(
            context, id=new_policy_id)
        if new_policy:
            new_policy.attach_port(port_id)


def get_port_policy_id(context, port_id):
    policy = qos_policy.QosPolicy.get_port_policy(
        context, port_id)
    if policy:
        return policy.id


def get_network_policy_id(context, net_id):
    policy = qos_policy.QosPolicy.get_network_policy(
        context, net_id)
    if policy:
        return policy.id
