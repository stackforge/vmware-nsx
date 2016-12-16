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


import abc
import six

from neutron.plugins.common import constants

from oslo_log import helpers as log_helpers

from vmware_nsx.services.lbaas.nsx_v.common import base_mgr
from vmware_nsx.services.lbaas.nsx_v.common import healthmon_mgr as hm_mgr
from vmware_nsx.services.lbaas.nsx_v.common import l7policy_mgr
from vmware_nsx.services.lbaas.nsx_v.common import l7rule_mgr
from vmware_nsx.services.lbaas.nsx_v.common import listener_mgr
from vmware_nsx.services.lbaas.nsx_v.common import loadbalancer_mgr as lb_mgr
from vmware_nsx.services.lbaas.nsx_v.common import member_mgr
from vmware_nsx.services.lbaas.nsx_v.common import pool_mgr


@six.add_metaclass(abc.ABCMeta)
class EdgeLBaaSv2BaseManager(base_mgr.EdgeLoadbalancerBaseManager):
    _lbv2_driver = None

    def __init__(self, vcns_driver):
        super(EdgeLBaaSv2BaseManager, self).__init__(vcns_driver)

    @property
    def lbv2_driver(self):
        if not EdgeLBaaSv2BaseManager._lbv2_driver:
            plugin = self._get_plugin(
                constants.LOADBALANCERV2)
            EdgeLBaaSv2BaseManager._lbv2_driver = (
                plugin.drivers['vmwareedge'])

        return EdgeLBaaSv2BaseManager._lbv2_driver

    @property
    @abc.abstractmethod
    def lbv2_mgr(self):
        return

    def complete_success(self, context, obj, *args, **kwargs):
        self.lbv2_mgr.successful_completion(context, obj, *args, **kwargs)

    def complete_failed(self, context, obj):
        self.lbv2_mgr.failed_completion(context, obj)


class EdgeLBaaSv2LoadBalancerManager(EdgeLBaaSv2BaseManager,
                                     lb_mgr.EdgeLoadBalancerManager):
    def __init__(self, vcns_driver):
        super(EdgeLBaaSv2LoadBalancerManager, self).__init__(vcns_driver)

    @property
    def lbv2_mgr(self):
        return self.lbv2_driver.load_balancer

    def create(self, context, lb):
        super(EdgeLBaaSv2LoadBalancerManager, self).base_create(
            context, lb, lb.id, lb.vip_address, lb.vip_subnet_id, lb.tenant_id)

    def update(self, context, old_lb, new_lb):
        super(EdgeLBaaSv2LoadBalancerManager, self).base_update(
            context, old_lb, new_lb)

    def delete(self, context, lb):
        super(EdgeLBaaSv2LoadBalancerManager, self).base_delete(
            context, lb, lb.id)


class EdgeLBaaSv2ListenerManager(EdgeLBaaSv2BaseManager,
                                 listener_mgr.EdgeListenerManager):
    def __init__(self, vcns_driver):
        super(EdgeLBaaSv2ListenerManager, self).__init__(vcns_driver)

    @property
    def lbv2_mgr(self):
        return self.lbv2_driver.listener

    def create(self, context, listener, certificate=None):
        super(EdgeLBaaSv2ListenerManager, self).base_create(
            context, listener, certificate=None)

    def update(self, context, old_listener, new_listener, certificate=None):
        super(EdgeLBaaSv2ListenerManager, self).base_update(
            context, old_listener, new_listener, certificate=None)

    def delete(self, context, listener):
        super(EdgeLBaaSv2ListenerManager, self).base_delete(
            context, listener)


class EdgeLBaaSv2PoolManager(EdgeLBaaSv2BaseManager,
                             pool_mgr.EdgePoolManager):
    def __init__(self, vcns_driver):
        super(EdgeLBaaSv2PoolManager, self).__init__(vcns_driver)

    @property
    def lbv2_mgr(self):
        return self.lbv2_driver.pool


class EdgeLBaaSv2MemberManager(EdgeLBaaSv2BaseManager,
                               member_mgr.EdgeMemberManager):
    def __init__(self, vcns_driver):
        super(EdgeLBaaSv2MemberManager, self).__init__(vcns_driver)

    @property
    def lbv2_mgr(self):
        return self.lbv2_driver.member


class EdgeLBaaSv2HealthMonitorManager(EdgeLBaaSv2BaseManager,
                                      hm_mgr.EdgeHealthMonitorManager):
    def __init__(self, vcns_driver):
        super(EdgeLBaaSv2HealthMonitorManager, self).__init__(vcns_driver)

    @property
    def lbv2_mgr(self):
        return self.lbv2_driver.health_monitor


class EdgeLBaaSv2L7PolicyManager(EdgeLBaaSv2BaseManager,
                                 l7policy_mgr.EdgeL7PolicyManager):
    def __init__(self, vcns_driver):
        super(EdgeLBaaSv2L7PolicyManager, self).__init__(vcns_driver)

    @property
    def lbv2_mgr(self):
        return self.lbv2_driver.l7policy


class EdgeLBaaSv2L7RuleManager(EdgeLBaaSv2BaseManager,
                               l7rule_mgr.EdgeL7RuleManager):
    def __init__(self, vcns_driver):
        super(EdgeLBaaSv2L7RuleManager, self).__init__(vcns_driver)

    @property
    def lbv2_mgr(self):
        return self.lbv2_driver.l7rule


class EdgeLoadbalancerDriverV2(object):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeLoadbalancerDriverV2, self).__init__()
        self.loadbalancer = EdgeLBaaSv2LoadBalancerManager(self)
        self.listener = EdgeLBaaSv2ListenerManager(self)
        self.pool = EdgeLBaaSv2PoolManager(self)
        self.member = EdgeLBaaSv2MemberManager(self)
        self.healthmonitor = EdgeLBaaSv2HealthMonitorManager(self)
        self.l7policy = EdgeLBaaSv2L7PolicyManager(self)
        self.l7rule = EdgeLBaaSv2L7RuleManager(self)
