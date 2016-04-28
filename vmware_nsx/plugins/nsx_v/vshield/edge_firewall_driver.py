# Copyright 2013 VMware, Inc
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

from neutron.db import db_base_plugin_v2
from oslo_log import log as logging
from oslo_utils import excutils

from vmware_nsx._i18n import _, _LE
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield.common import (
    exceptions as vcns_exc)
from vmware_nsx.plugins.nsx_v.vshield.tasks import (
    constants as task_const)
from vmware_nsx.plugins.nsx_v.vshield.tasks import tasks

LOG = logging.getLogger(__name__)

VSE_FWAAS_ALLOW = "accept"
VSE_FWAAS_DENY = "deny"

FWAAS_ALLOW = "allow"
FWAAS_DENY = "deny"


class EdgeFirewallDriver(db_base_plugin_v2.NeutronDbPluginV2):
    """Implementation of driver APIs for
       Edge Firewall feature configuration
    """
    def _convert_firewall_action(self, action):
        if action == FWAAS_ALLOW:
            return VSE_FWAAS_ALLOW
        elif action == FWAAS_DENY:
            return VSE_FWAAS_DENY
        else:
            msg = _("Invalid action value %s in a firewall rule") % action
            raise vcns_exc.VcnsBadRequest(resource='firewall_rule', msg=msg)

    def _restore_firewall_action(self, action):
        if action == VSE_FWAAS_ALLOW:
            return FWAAS_ALLOW
        elif action == VSE_FWAAS_DENY:
            return FWAAS_DENY
        else:
            msg = (_("Invalid action value %s in "
                     "a vshield firewall rule") % action)
            raise vcns_exc.VcnsBadRequest(resource='firewall_rule', msg=msg)

    def _get_port_range_from_min_max_ports(self, min_port, max_port):
        if not min_port:
            return None
        if min_port == max_port:
            return str(min_port)
        else:
            return '%d:%d' % (min_port, max_port)

    def _get_ports_list_from_string(self, port_str):
        """Receives a string representation of the service ports,
        and return a list of integers
        Supported formats:
        Empty string - no ports
        "number" - a single port
        "num1:num2" - a range
        "num1,num2,num3" - a list
        """
        if not port_str:
            return []
        if ':' in port_str:
            min_port, sep, max_port = port_str.partition(":")
            return list(range(int(min_port.strip()),
                              int(max_port.strip()) + 1))
        if ',' in port_str:
            # remove duplications (using set) and empty/non numeric entries
            ports_set = set()
            for orig_port in port_str.split(','):
                port = orig_port.strip()
                if port and port.isdigit():
                    ports_set.add(int(port))
            return sorted(list(ports_set))
        else:
            return [int(port_str.strip())]

    def _convert_firewall_rule(self, context, rule, index=None):
        vcns_rule = {
            "action": self._convert_firewall_action(rule['action']),
            "enabled": rule.get('enabled', True)}
        if rule.get('name'):
            vcns_rule['name'] = rule['name']
        if rule.get('description'):
            vcns_rule['description'] = rule['description']
        if rule.get('source_ip_address'):
            vcns_rule['source'] = {
                "ipAddress": rule['source_ip_address']
            }
        if rule.get('source_vnic_groups'):
            vcns_rule['source'] = {
                "vnicGroupId": rule['source_vnic_groups']
            }
        if rule.get('destination_ip_address'):
            vcns_rule['destination'] = {
                "ipAddress": rule['destination_ip_address']
            }
        if rule.get('destination_vnic_groups'):
            vcns_rule['destination'] = {
                "vnicGroupId": rule['destination_vnic_groups']
            }
        if rule.get('application'):
            vcns_rule['application'] = rule['application']
        service = {}
        if rule.get('source_port'):
            service['sourcePort'] = self._get_ports_list_from_string(
                rule['source_port'])
        if rule.get('destination_port'):
            service['port'] = self._get_ports_list_from_string(
                rule['destination_port'])
        if rule.get('protocol'):
            service['protocol'] = rule['protocol']
            if rule['protocol'] == 'icmp':
                if rule.get('icmp_type'):
                    service['icmpType'] = rule['icmp_type']
                else:
                    service['icmpType'] = 'any'
        if rule.get('ruleId'):
            vcns_rule['ruleId'] = rule.get('ruleId')
        if service:
            vcns_rule['application'] = {
                'service': [service]
            }
        if index:
            vcns_rule['ruleTag'] = index
        return vcns_rule

    def _restore_firewall_rule(self, context, edge_id, response):
        rule = response
        rule_binding = nsxv_db.get_nsxv_edge_firewallrule_binding_by_vseid(
            context.session, edge_id, rule['ruleId'])
        service = rule['application']['service'][0]
        src_port_range = self._get_port_range_from_min_max_ports(
            service['sourcePort'][0], service['sourcePort'][-1])
        dst_port_range = self._get_port_range_from_min_max_ports(
            service['port'][0], service['port'][-1])
        fw_rule = {
            'firewall_rule': {
                'id': rule_binding['rule_id'],
                'source_ip_address': rule['source']['ipAddress'],
                'destination_ip_address': rule['destination']['ipAddress'],
                'protocol': service['protocol'],
                'destination_port': dst_port_range,
                'source_port': src_port_range,
                'action': self._restore_firewall_action(rule['action']),
                'enabled': rule['enabled']}}
        if rule.get('name'):
            fw_rule['firewall_rule']['name'] = rule['name']
        if rule.get('description'):
            fw_rule['firewall_rule']['description'] = rule['description']
        return fw_rule

    def _convert_firewall(self, context, firewall, allow_external=False):
        #bulk configuration on firewall and rescheduling the rule binding
        ruleTag = 1
        vcns_rules = []
        for rule in firewall['firewall_rule_list']:
            vcns_rule = self._convert_firewall_rule(context, rule, ruleTag)
            vcns_rules.append(vcns_rule)
            ruleTag += 1
        if allow_external:
            vcns_rules.append(
                {'action': "accept",
                 'enabled': True,
                 'destination': {'vnicGroupId': ["external"]},
                 'ruleTag': ruleTag})
        return {
            'featureType': "firewall_4.0",
            'globalConfig': {'tcpTimeoutEstablished': 7200},
            'firewallRules': {
                'firewallRules': vcns_rules}}

    def _restore_firewall(self, context, edge_id, response):
        res = {}
        res['firewall_rule_list'] = []
        for rule in response['firewallRules']['firewallRules']:
            rule_binding = (
                nsxv_db.get_nsxv_edge_firewallrule_binding_by_vseid(
                    context.session, edge_id, rule['ruleId']))
            if rule_binding is None:
                continue
            service = rule['application']['service'][0]
            src_port_range = self._get_port_range_from_min_max_ports(
                service['sourcePort'][0], service['sourcePort'][-1])
            dst_port_range = self._get_port_range_from_min_max_ports(
                service['port'][0], service['port'][-1])
            item = {
                'firewall_rule': {
                    'id': rule_binding['rule_id'],
                    'source_ip_address': rule['source']['ipAddress'],
                    'destination_ip_address': rule[
                        'destination']['ipAddress'],
                    'protocol': service['protocol'],
                    'destination_port': dst_port_range,
                    'source_port': src_port_range,
                    'action': self._restore_firewall_action(rule['action']),
                    'enabled': rule['enabled']}}
            if rule.get('name'):
                item['firewall_rule']['name'] = rule['name']
            if rule.get('description'):
                item['firewall_rule']['description'] = rule['description']
            res['firewall_rule_list'].append(item)
        return res

    def _create_rule_id_mapping(
        self, context, edge_id, firewall, vcns_fw):
        for rule in vcns_fw['firewallRules']['firewallRules']:
            index = rule['ruleTag'] - 1
            #TODO(linb):a simple filter of the retrived rules which may be
            #created by other operations unintentionally
            if index < len(firewall['firewall_rule_list']):
                rule_vseid = rule['ruleId']
                rule_id = firewall['firewall_rule_list'][index]['id']
                map_info = {
                    'rule_id': rule_id,
                    'rule_vseid': rule_vseid,
                    'edge_id': edge_id
                }
                nsxv_db.add_nsxv_edge_firewallrule_binding(
                    context.session, map_info)

    def _get_firewall(self, context, edge_id):
        try:
            return self.vcns.get_firewall(edge_id)[1]
        except vcns_exc.VcnsApiException as e:
            LOG.exception(_LE("Failed to get firewall with edge "
                              "id: %s"), edge_id)
            raise e

    def _get_firewall_rule_next(self, context, edge_id, rule_vseid):
        # Return the firewall rule below 'rule_vseid'
        fw_cfg = self._get_firewall(context, edge_id)
        for i in range(len(fw_cfg['firewallRules']['firewallRules'])):
            rule_cur = fw_cfg['firewallRules']['firewallRules'][i]
            if str(rule_cur['ruleId']) == rule_vseid:
                if (i + 1) == len(fw_cfg['firewallRules']['firewallRules']):
                    return None
                else:
                    return fw_cfg['firewallRules']['firewallRules'][i + 1]

    def get_firewall_rule(self, context, id, edge_id):
        rule_map = nsxv_db.get_nsxv_edge_firewallrule_binding(
            context.session, id, edge_id)
        if rule_map is None:
            msg = _("No rule id:%s found in the edge_firewall_binding") % id
            LOG.error(msg)
            raise vcns_exc.VcnsNotFound(
                resource='vcns_firewall_rule_bindings', msg=msg)
        vcns_rule_id = rule_map.rule_vseid
        try:
            response = self.vcns.get_firewall_rule(
                edge_id, vcns_rule_id)[1]
        except vcns_exc.VcnsApiException as e:
            LOG.exception(_LE("Failed to get firewall rule: %(rule_id)s "
                              "with edge_id: %(edge_id)s"), {
                                'rule_id': id,
                                'edge_id': edge_id})
            raise e
        return self._restore_firewall_rule(context, edge_id, response)

    def get_firewall(self, context, edge_id):
        response = self._get_firewall(context, edge_id)
        return self._restore_firewall(context, edge_id, response)

    def update_firewall(self, context, edge_id, firewall):
        fw_req = self._convert_firewall(context, firewall)
        try:
            self.vcns.update_firewall(edge_id, fw_req)
        except vcns_exc.VcnsApiException as e:
            LOG.exception(_LE("Failed to update firewall "
                              "with edge_id: %s"), edge_id)
            raise e
        fw_res = self._get_firewall(context, edge_id)
        nsxv_db.cleanup_nsxv_edge_firewallrule_binding(
            context.session, edge_id)
        self._create_rule_id_mapping(context, edge_id, firewall, fw_res)

    def delete_firewall(self, context, edge_id):
        try:
            self.vcns.delete_firewall(edge_id)
        except vcns_exc.VcnsApiException as e:
            LOG.exception(_LE("Failed to delete firewall "
                              "with edge_id:%s"), edge_id)
            raise e
        nsxv_db.cleanup_nsxv_edge_firewallrule_binding(
            context.session, edge_id)

    def update_firewall_rule(self, context, id, edge_id, firewall_rule):
        rule_map = nsxv_db.get_nsxv_edge_firewallrule_binding(
            context.session, id, edge_id)
        vcns_rule_id = rule_map.rule_vseid
        fwr_req = self._convert_firewall_rule(context, firewall_rule)
        try:
            self.vcns.update_firewall_rule(edge_id, vcns_rule_id, fwr_req)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update firewall rule: "
                                  "%(rule_id)s "
                                  "with edge_id: %(edge_id)s"),
                              {'rule_id': id,
                               'edge_id': edge_id})

    def delete_firewall_rule(self, context, id, edge_id):
        rule_map = nsxv_db.get_nsxv_edge_firewallrule_binding(
            context.session, id, edge_id)
        vcns_rule_id = rule_map.rule_vseid
        try:
            self.vcns.delete_firewall_rule(edge_id, vcns_rule_id)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to delete firewall rule: "
                                  "%(rule_id)s "
                                  "with edge_id: %(edge_id)s"),
                              {'rule_id': id,
                               'edge_id': edge_id})
        nsxv_db.delete_nsxv_edge_firewallrule_binding(
            context.session, id)

    def _add_rule_above(self, context, ref_rule_id, edge_id, firewall_rule):
        rule_map = nsxv_db.get_nsxv_edge_firewallrule_binding(
            context.session, ref_rule_id, edge_id)
        ref_vcns_rule_id = rule_map.rule_vseid
        fwr_req = self._convert_firewall_rule(context, firewall_rule)
        try:
            header = self.vcns.add_firewall_rule_above(
                edge_id, ref_vcns_rule_id, fwr_req)[0]
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to add firewall rule above: "
                                  "%(rule_id)s with edge_id: %(edge_id)s"),
                              {'rule_id': ref_vcns_rule_id,
                               'edge_id': edge_id})

        objuri = header['location']
        fwr_vseid = objuri[objuri.rfind("/") + 1:]
        map_info = {
            'rule_id': firewall_rule['id'],
            'rule_vseid': fwr_vseid,
            'edge_id': edge_id}
        nsxv_db.add_nsxv_edge_firewallrule_binding(
            context.session, map_info)

    def _add_rule_below(self, context, ref_rule_id, edge_id, firewall_rule):
        rule_map = nsxv_db.get_nsxv_edge_firewallrule_binding(
            context.session, ref_rule_id, edge_id)
        ref_vcns_rule_id = rule_map.rule_vseid
        fwr_vse_next = self._get_firewall_rule_next(
            context, edge_id, ref_vcns_rule_id)
        fwr_req = self._convert_firewall_rule(context, firewall_rule)
        if fwr_vse_next:
            ref_vcns_rule_id = fwr_vse_next['ruleId']
            try:
                header = self.vcns.add_firewall_rule_above(
                    edge_id, int(ref_vcns_rule_id), fwr_req)[0]
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Failed to add firewall rule above: "
                                      "%(rule_id)s with edge_id: %(edge_id)s"),
                                  {'rule_id': ref_vcns_rule_id,
                                   'edge_id': edge_id})
        else:
            # append the rule at the bottom
            try:
                header = self.vcns.add_firewall_rule(
                    edge_id, fwr_req)[0]
            except vcns_exc.VcnsApiException:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Failed to append a firewall rule"
                                      "with edge_id: %s"), edge_id)

        objuri = header['location']
        fwr_vseid = objuri[objuri.rfind("/") + 1:]
        map_info = {
            'rule_id': firewall_rule['id'],
            'rule_vseid': fwr_vseid,
            'edge_id': edge_id
        }
        nsxv_db.add_nsxv_edge_firewallrule_binding(
            context.session, map_info)

    def insert_rule(self, context, rule_info, edge_id, fwr):
        if rule_info.get('insert_before'):
            self._add_rule_above(
                context, rule_info['insert_before'], edge_id, fwr)
        elif rule_info.get('insert_after'):
            self._add_rule_below(
                context, rule_info['insert_after'], edge_id, fwr)
        else:
            msg = _("Can't execute insert rule operation "
                    "without reference rule_id")
            raise vcns_exc.VcnsBadRequest(resource='firewall_rule', msg=msg)

    def _asyn_update_firewall(self, task):
        edge_id = task.userdata['edge_id']
        config = task.userdata['config']
        context = task.userdata['jobdata']['context']
        try:
            self.vcns.update_firewall(edge_id, config)
        except vcns_exc.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update firewall "
                                  "with edge_id: %s"), edge_id)
        vcns_fw_config = self._get_firewall(context, edge_id)
        task.userdata['vcns_fw_config'] = vcns_fw_config
        return task_const.TaskStatus.COMPLETED

    def asyn_update_firewall(self, router_id, edge_id, firewall,
                             jobdata=None, allow_external=True):
        # TODO(berlin): Remove uncessary context input parameter.
        config = self._convert_firewall(None, firewall,
                                        allow_external=allow_external)
        userdata = {
            'edge_id': edge_id,
            'config': config,
            'fw_config': firewall,
            'jobdata': jobdata}
        task_name = "update-firewall-%s" % edge_id
        task = tasks.Task(task_name, router_id,
                          self._asyn_update_firewall, userdata=userdata)
        task.add_result_monitor(self.callbacks.firewall_update_result)
        self.task_manager.add(task)
        return task
