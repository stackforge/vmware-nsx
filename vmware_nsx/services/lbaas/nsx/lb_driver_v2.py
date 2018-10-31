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

from oslo_log import helpers as log_helpers
from oslo_log import log as logging

from neutron_lib import exceptions as n_exc

from vmware_nsx.services.lbaas import base_mgr

LOG = logging.getLogger(__name__)


class EdgeLoadbalancerDriverV2(object):
    @log_helpers.log_method_call
    def __init__(self):
        super(EdgeLoadbalancerDriverV2, self).__init__()

        self.loadbalancer = EdgeLoadBalancerManager()
        self.listener = EdgeListenerManager()
        self.pool = EdgePoolManager()
        self.member = EdgeMemberManager()
        self.healthmonitor = EdgeHealthMonitorManager()
        self.l7policy = EdgeL7PolicyManager()
        self.l7rule = EdgeL7RuleManager()


class EdgeLoadBalancerManager(base_mgr.LoadbalancerBaseManager):

    @log_helpers.log_method_call
    def create(self, context, lb):
        # verify that the subnet belongs to the same plugin as the lb
        lb_p = self.core_plugin._get_plugin_from_project(context,
                                                         lb.tenant_id)
        subnet_p = self.core_plugin._get_subnet_plugin_by_id(
            context, lb.vip_subnet_id)
        if lb_p.plugin_type() != subnet_p.plugin_type():
            self.lbv2_driver.load_balancer.failed_completion(context, lb)
            msg = (_('Subnet must belong to the plugin %s, as the '
                     'loadbalancer') % lb_p.plugin_type())
            raise n_exc.BadRequest(resource='edge-lbaas', msg=msg)
        return lb_p.lbv2_driver.loadbalancer.create(context, lb)

    @log_helpers.log_method_call
    def update(self, context, old_lb, new_lb):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      new_lb.tenant_id)
        return p.lbv2_driver.loadbalancer.update(context, old_lb, new_lb)

    @log_helpers.log_method_call
    def delete(self, context, lb):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      lb.tenant_id)
        return p.lbv2_driver.loadbalancer.delete(context, lb)

    @log_helpers.log_method_call
    def refresh(self, context, lb):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      lb.tenant_id)
        return p.lbv2_driver.loadbalancer.refresh(context, lb)

    @log_helpers.log_method_call
    def stats(self, context, lb):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      lb.tenant_id)
        return p.lbv2_driver.loadbalancer.stats(context, lb)

    @log_helpers.log_method_call
    def get_operating_status(self, context, id, with_members=False):
        p = self.core_plugin._get_plugin_from_project(context,
                                                      context.project_id)
        return p.lbv2_driver.loadbalancer.get_operating_status(
            context, id, with_members=with_members)


class EdgeListenerManager(base_mgr.LoadbalancerBaseManager):

    def _get_tenant_id(self, listener):
        """Get the tenant of the loadbalancer itself if possible"""
        if listener.loadbalancer:
            return listener.loadbalancer.tenant_id
        return listener.tenant_id

    @log_helpers.log_method_call
    def create(self, context, listener, certificate=None):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(listener))
        return p.lbv2_driver.listener.create(context, listener,
                                             certificate=certificate)

    @log_helpers.log_method_call
    def update(self, context, old_listener, new_listener, certificate=None):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(new_listener))
        return p.lbv2_driver.listener.update(context,
                                             old_listener,
                                             new_listener,
                                             certificate=certificate)

    @log_helpers.log_method_call
    def delete(self, context, listener):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(listener))
        return p.lbv2_driver.listener.delete(context, listener)


class EdgePoolManager(base_mgr.LoadbalancerBaseManager):

    def _get_tenant_id(self, pool):
        """Get the tenant of the loadbalancer itself if possible"""
        if pool.loadbalancer:
            return pool.loadbalancer.tenant_id
        return pool.tenant_id

    @log_helpers.log_method_call
    def create(self, context, pool):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(pool))
        return p.lbv2_driver.pool.create(context, pool)

    @log_helpers.log_method_call
    def update(self, context, old_pool, new_pool):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(new_pool))
        return p.lbv2_driver.pool.update(context, old_pool, new_pool)

    @log_helpers.log_method_call
    def delete(self, context, pool):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(pool))
        return p.lbv2_driver.pool.delete(context, pool)


class EdgeMemberManager(base_mgr.LoadbalancerBaseManager):

    def _get_tenant_id(self, member):
        """Get the tenant of the loadbalancer itself if possible"""
        if member.pool and member.pool.loadbalancer:
            return member.pool.loadbalancer.tenant_id
        return member.tenant_id

    @log_helpers.log_method_call
    def create(self, context, member):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(member))
        return p.lbv2_driver.member.create(context, member)

    @log_helpers.log_method_call
    def update(self, context, old_member, new_member):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(new_member))
        return p.lbv2_driver.member.update(context, old_member, new_member)

    @log_helpers.log_method_call
    def delete(self, context, member):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(member))
        return p.lbv2_driver.member.delete(context, member)


class EdgeHealthMonitorManager(base_mgr.LoadbalancerBaseManager):

    def _get_tenant_id(self, hm):
        """Get the tenant of the loadbalancer itself if possible"""
        if hm.pool and hm.pool.loadbalancer:
            return hm.pool.loadbalancer.tenant_id
        return hm.tenant_id

    @log_helpers.log_method_call
    def create(self, context, hm):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(hm))
        return p.lbv2_driver.healthmonitor.create(context, hm)

    @log_helpers.log_method_call
    def update(self, context, old_hm, new_hm):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(new_hm))
        return p.lbv2_driver.healthmonitor.update(context, old_hm, new_hm)

    @log_helpers.log_method_call
    def delete(self, context, hm):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(hm))
        return p.lbv2_driver.healthmonitor.delete(context, hm)


class EdgeL7PolicyManager(base_mgr.LoadbalancerBaseManager):

    def _get_tenant_id(self, policy):
        """Get the tenant of the loadbalancer itself if possible"""
        if policy.listener and policy.listener.loadbalancer:
            return policy.listener.loadbalancer.tenant_id
        return policy.tenant_id

    @log_helpers.log_method_call
    def create(self, context, policy):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(policy))
        return p.lbv2_driver.l7policy.create(context, policy)

    @log_helpers.log_method_call
    def update(self, context, old_policy, new_policy):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(new_policy))
        return p.lbv2_driver.l7policy.update(context, old_policy, new_policy)

    @log_helpers.log_method_call
    def delete(self, context, policy):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(policy))
        return p.lbv2_driver.l7policy.delete(context, policy)


class EdgeL7RuleManager(base_mgr.LoadbalancerBaseManager):

    def _get_tenant_id(self, rule):
        """Get the tenant of the loadbalancer itself if possible"""
        if (rule.policy and rule.policy.listener and
            rule.policy.listener.loadbalancer):
            return rule.policy.listener.loadbalancer.tenant_id
        return rule.tenant_id

    @log_helpers.log_method_call
    def create(self, context, rule):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(rule))
        return p.lbv2_driver.l7rule.create(context, rule)

    @log_helpers.log_method_call
    def update(self, context, old_rule, new_rule):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(new_rule))
        return p.lbv2_driver.l7rule.update(context, old_rule, new_rule)

    @log_helpers.log_method_call
    def delete(self, context, rule):
        p = self.core_plugin._get_plugin_from_project(
            context, self._get_tenant_id(rule))
        return p.lbv2_driver.l7rule.delete(context, rule)
