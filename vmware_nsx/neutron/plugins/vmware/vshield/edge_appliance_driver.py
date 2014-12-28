# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

import time

from oslo.config import cfg
from oslo.serialization import jsonutils
from oslo.utils import excutils

from neutron.i18n import _LE, _LI, _LW
from neutron.openstack.common import log as logging
from vmware_nsx.neutron.plugins.vmware.common import nsxv_constants
from vmware_nsx.neutron.plugins.vmware.common import utils
from vmware_nsx.neutron.plugins.vmware.vshield.common import constants
from vmware_nsx.neutron.plugins.vmware.vshield.common import exceptions
from vmware_nsx.neutron.plugins.vmware.vshield.tasks import (
    constants as task_constants)
from vmware_nsx.neutron.plugins.vmware.vshield.tasks import tasks

LOG = logging.getLogger(__name__)


class EdgeApplianceDriver(object):
    def __init__(self):
        # store the last task per edge that has the latest config
        self.updated_task = {
            'nat': {},
            'route': {},
        }

    def _assemble_edge(self, name, appliance_size="compact",
                       deployment_container_id=None, datacenter_moid=None,
                       enable_aesni=True, dist=False,
                       enable_fips=False, remote_access=False):
        edge = {
            'name': name,
            'fqdn': name,
            'enableAesni': enable_aesni,
            'enableFips': enable_fips,
            'cliSettings': {
                'remoteAccess': remote_access
            },
            'appliances': {
                'applianceSize': appliance_size
            },
        }
        if not dist:
            edge['type'] = "gatewayServices"
            edge['vnics'] = {'vnics': []}
        else:
            edge['type'] = "distributedRouter"
            edge['interfaces'] = {'interfaces': []}

        if deployment_container_id:
            edge['appliances']['deploymentContainerId'] = (
                deployment_container_id)
        if datacenter_moid:
            edge['datacenterMoid'] = datacenter_moid

        return edge

    def _assemble_edge_appliance(self, resource_pool_id, datastore_id):
        appliance = {}
        if resource_pool_id:
            appliance['resourcePoolId'] = resource_pool_id
        if datastore_id:
            appliance['datastoreId'] = datastore_id
        return appliance

    def _assemble_edge_vnic(self, name, index, portgroup_id, tunnel_index=-1,
                            primary_address=None, subnet_mask=None,
                            secondary=None,
                            type="internal",
                            enable_proxy_arp=False,
                            enable_send_redirects=True,
                            is_connected=True,
                            mtu=1500,
                            address_groups=None):
        vnic = {
            'index': index,
            'name': name,
            'type': type,
            'portgroupId': portgroup_id,
            'mtu': mtu,
            'enableProxyArp': enable_proxy_arp,
            'enableSendRedirects': enable_send_redirects,
            'isConnected': is_connected
        }
        if address_groups is None:
            address_groups = []
        if not address_groups:
            if primary_address and subnet_mask:
                address_group = {
                    'primaryAddress': primary_address,
                    'subnetMask': subnet_mask
                }
                if secondary:
                    address_group['secondaryAddresses'] = {
                        'ipAddress': secondary,
                        'type': 'secondary_addresses'
                    }

                vnic['addressGroups'] = {
                    'addressGroups': [address_group]
                }
            else:
                vnic['subInterfaces'] = {'subInterfaces': address_groups}
        else:
            if tunnel_index < 0:
                vnic['addressGroups'] = {'addressGroups': address_groups}
            else:
                vnic['subInterfaces'] = {'subInterfaces': address_groups}

        return vnic

    def _assemble_vdr_interface(self, portgroup_id,
                                primary_address=None, subnet_mask=None,
                                secondary=None,
                                type="internal",
                                is_connected=True,
                                mtu=1500,
                                address_groups=None):
        interface = {
            'type': type,
            'connectedToId': portgroup_id,
            'mtu': mtu,
            'isConnected': is_connected
        }
        if address_groups is None:
            address_groups = []
        if not address_groups:
            if primary_address and subnet_mask:
                address_group = {
                    'primaryAddress': primary_address,
                    'subnetMask': subnet_mask
                }
                if secondary:
                    address_group['secondaryAddresses'] = {
                        'ipAddress': secondary,
                        'type': 'secondary_addresses'
                    }

                interface['addressGroups'] = {
                    'addressGroups': [address_group]
                }
        else:
            interface['addressGroups'] = {'addressGroups': address_groups}
        interfaces = {'interfaces': [interface]}

        return interfaces

    def _edge_status_to_level(self, status):
        if status == 'GREEN':
            status_level = constants.RouterStatus.ROUTER_STATUS_ACTIVE
        elif status in ('GREY', 'YELLOW'):
            status_level = constants.RouterStatus.ROUTER_STATUS_DOWN
        else:
            status_level = constants.RouterStatus.ROUTER_STATUS_ERROR
        return status_level

    def _enable_loadbalancer(self, edge):
        if not edge.get('featureConfigs') or (
            not edge['featureConfigs'].get('features')):
            edge['featureConfigs'] = {'features': []}
        edge['featureConfigs']['features'].append(
            {'featureType': 'loadbalancer_4.0',
             'enabled': True})

    def get_edge_status(self, edge_id):
        try:
            response = self.vcns.get_edge_status(edge_id)[1]
            status_level = self._edge_status_to_level(
                response['edgeStatus'])
        except exceptions.VcnsApiException as e:
            LOG.exception(_LE("VCNS: Failed to get edge status:\n%s"),
                          e.response)
            status_level = constants.RouterStatus.ROUTER_STATUS_ERROR
            try:
                desc = jsonutils.loads(e.response)
                if desc.get('errorCode') == (
                    constants.VCNS_ERROR_CODE_EDGE_NOT_RUNNING):
                    status_level = constants.RouterStatus.ROUTER_STATUS_DOWN
            except ValueError:
                LOG.exception(e.response)

        return status_level

    def get_edges_statuses(self):
        edges_status_level = {}
        edges = self._get_edges()
        for edge in edges['edgePage'].get('data', []):
            edge_id = edge['id']
            status = edge['edgeStatus']
            edges_status_level[edge_id] = self._edge_status_to_level(status)

        return edges_status_level

    def get_interface(self, edge_id, vnic_index):
        self.check_edge_jobs(edge_id)
        # get vnic interface address groups
        try:
            return self.vcns.query_interface(edge_id, vnic_index)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("NSXv: Failed to query vnic %s"), vnic_index)

    def check_edge_jobs(self, edge_id):
        retries = max(cfg.CONF.nsxv.retries, 1)
        delay = 0.5
        for attempt in range(1, retries + 1):
            if attempt != 1:
                time.sleep(delay)
                delay = min(2 * delay, 60)
            h, jobs = self.vcns.get_edge_jobs(edge_id)
            if jobs['edgeJob'] == []:
                return
            LOG.warning(_LW('NSXv: jobs still running.'))
        LOG.error(_LE('NSXv: jobs are still runnings!'))

    def update_interface(self, router_id, edge_id, index, network,
                         tunnel_index=-1, address=None, netmask=None,
                         secondary=None, jobdata=None,
                         address_groups=None):
        LOG.debug("VCNS: update vnic %(index)d: %(addr)s %(netmask)s", {
            'index': index, 'addr': address, 'netmask': netmask})
        if index == constants.EXTERNAL_VNIC_INDEX:
            name = constants.EXTERNAL_VNIC_NAME
            intf_type = 'uplink'
        else:
            name = constants.INTERNAL_VNIC_NAME + str(index)
            if tunnel_index < 0:
                intf_type = 'internal'
            else:
                intf_type = 'trunk'

        config = self._assemble_edge_vnic(
            name, index, network, tunnel_index,
            address, netmask, secondary, type=intf_type,
            address_groups=address_groups)

        self.vcns.update_interface(edge_id, config)

    def add_vdr_internal_interface(self, edge_id,
                                   network, address=None, netmask=None,
                                   secondary=None, address_groups=None,
                                   type="internal"):
        LOG.debug("Add VDR interface on edge: %s", edge_id)
        if address_groups is None:
            address_groups = []
        interface_req = self._assemble_vdr_interface(
            network, address, netmask, secondary,
            address_groups=address_groups,
            type=type)
        self.vcns.add_vdr_internal_interface(edge_id, interface_req)
        header, response = self.vcns.get_edge_interfaces(edge_id)
        for interface in response['interfaces']:
            if interface['connectedToId'] == network:
                vnic_index = int(interface['index'])
                return vnic_index

    def update_vdr_internal_interface(self, edge_id, index, network,
                                      address=None, netmask=None,
                                      secondary=None, address_groups=None):
        if not address_groups:
            address_groups = []
        interface_req = self._assemble_vdr_interface(
            network, address, netmask, secondary,
            address_groups=address_groups)
        try:
            header, response = self.vcns.update_vdr_internal_interface(
                edge_id, index, interface_req)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to update vdr interface on edge: "
                                  "%s"), edge_id)

    def delete_vdr_internal_interface(self, edge_id, interface_index):
        LOG.debug("Delete VDR interface on edge: %s", edge_id)
        try:
            header, response = self.vcns.delete_vdr_internal_interface(
                edge_id, interface_index)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to delete vdr interface on edge: "
                                  "%s"),
                              edge_id)

    def _delete_interface(self, task):
        edge_id = task.userdata['edge_id']
        vnic_index = task.userdata['vnic_index']
        LOG.debug("start deleting vnic %s", vnic_index)
        try:
            self.vcns.delete_interface(edge_id, vnic_index)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to delete vnic %(vnic_index)s: "
                                  "on edge %(edge_id)s"),
                              {'vnic_index': vnic_index,
                               'edge_id': edge_id})
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to delete vnic %d"), vnic_index)

        return task_constants.TaskStatus.COMPLETED

    def delete_interface(self, router_id, edge_id, index, jobdata=None):
        task_name = "delete-interface-%s-%d" % (edge_id, index)
        userdata = {
            'router_id': router_id,
            'edge_id': edge_id,
            'vnic_index': index,
            'jobdata': jobdata
        }
        task = tasks.Task(task_name, router_id, self._delete_interface,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.interface_delete_result)
        self.task_manager.add(task)
        return task

    def _deploy_edge(self, task):
        userdata = task.userdata
        LOG.debug("NSXv: start deploying edge")
        request = userdata['request']
        try:
            header = self.vcns.deploy_edge(request)[0]
            objuri = header['location']
            job_id = objuri[objuri.rfind("/") + 1:]
            response = self.vcns.get_edge_id(job_id)[1]
            edge_id = response['edgeId']
            LOG.debug("VCNS: deploying edge %s", edge_id)
            userdata['edge_id'] = edge_id
            status = task_constants.TaskStatus.PENDING
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("NSXv: deploy edge failed."))

        return status

    def _status_edge(self, task):
        edge_id = task.userdata['edge_id']
        try:
            response = self.vcns.get_edge_deploy_status(edge_id)[1]
            task.userdata['retries'] = 0
            system_status = response.get('systemStatus', None)
            if system_status is None:
                status = task_constants.TaskStatus.PENDING
            elif system_status == 'good':
                status = task_constants.TaskStatus.COMPLETED
            else:
                status = task_constants.TaskStatus.ERROR
        except exceptions.VcnsApiException as e:
            LOG.exception(_LE("VCNS: Edge %s status query failed."), edge_id)
            raise e
        except Exception as e:
            retries = task.userdata.get('retries', 0) + 1
            if retries < 3:
                task.userdata['retries'] = retries
                LOG.exception(_LE("VCNS: Unable to retrieve edge %(edge_id)s "
                                  "status. Retry %(retries)d."),
                              {'edge_id': edge_id,
                               'retries': retries})
                status = task_constants.TaskStatus.PENDING
            else:
                LOG.exception(_LE("VCNS: Unable to retrieve edge %s status. "
                                  "Abort."), edge_id)
                status = task_constants.TaskStatus.ERROR
        LOG.debug("VCNS: Edge %s status", edge_id)
        return status

    def _result_edge(self, task):
        edge_id = task.userdata.get('edge_id')
        if task.status != task_constants.TaskStatus.COMPLETED:
            LOG.error(_LE("NSXv: Failed to deploy edge %(edge_id)s "
                          "status %(status)d"),
                      {'edge_id': edge_id,
                       'status': task.status})
        else:
            LOG.debug("NSXv: Edge %s is deployed", edge_id)

    def _update_edge(self, task):
        edge_id = task.userdata['edge_id']
        LOG.debug("start update edge %s", edge_id)
        request = task.userdata['request']
        try:
            self.vcns.update_edge(edge_id, request)
            status = task_constants.TaskStatus.COMPLETED
        except exceptions.VcnsApiException as e:
            LOG.error(_LE("Failed to update edge: %s"),
                      e.response)
            status = task_constants.TaskStatus.ERROR

        return status

    def _delete_edge(self, task):
        edge_id = task.userdata['edge_id']
        LOG.debug("VCNS: start destroying edge %s", edge_id)
        status = task_constants.TaskStatus.COMPLETED
        if edge_id:
            try:
                self.vcns.delete_edge(edge_id)
            except exceptions.ResourceNotFound:
                pass
            except exceptions.VcnsApiException as e:
                LOG.exception(_LE("VCNS: Failed to delete %(edge_id)s:\n"
                                  "%(response)s"),
                              {'edge_id': edge_id, 'response': e.response})
                status = task_constants.TaskStatus.ERROR
            except Exception:
                LOG.exception(_LE("VCNS: Failed to delete %s"), edge_id)
                status = task_constants.TaskStatus.ERROR

        return status

    def _get_edges(self):
        try:
            return self.vcns.get_edges()[1]
        except exceptions.VcnsApiException as e:
            LOG.exception(_LE("VCNS: Failed to get edges:\n%s"), e.response)
            raise e

    def deploy_edge(self, resource_id, name, internal_network, jobdata=None,
                    dist=False, wait_for_exec=False, loadbalancer_enable=True,
                    appliance_size=nsxv_constants.LARGE):
        task_name = 'deploying-%s' % name
        edge_name = name
        edge = self._assemble_edge(
            edge_name, datacenter_moid=self.datacenter_moid,
            deployment_container_id=self.deployment_container_id,
            appliance_size=appliance_size, remote_access=True, dist=dist)
        appliance = self._assemble_edge_appliance(self.resource_pool_id,
                                                  self.datastore_id)
        if appliance:
            edge['appliances']['appliances'] = [appliance]

        if not dist:
            vnic_external = self._assemble_edge_vnic(
                constants.EXTERNAL_VNIC_NAME, constants.EXTERNAL_VNIC_INDEX,
                self.external_network, type="uplink")
            edge['vnics']['vnics'].append(vnic_external)
        else:
            edge['mgmtInterface'] = {
                'connectedToId': self.external_network,
                'name': "mgmtInterface"}
        if internal_network:
            vnic_inside = self._assemble_edge_vnic(
                constants.INTERNAL_VNIC_NAME, constants.INTERNAL_VNIC_INDEX,
                internal_network,
                constants.INTEGRATION_EDGE_IPADDRESS,
                constants.INTEGRATION_SUBNET_NETMASK,
                type="internal")
            edge['vnics']['vnics'].append(vnic_inside)
        if not dist and loadbalancer_enable:
            self._enable_loadbalancer(edge)
        userdata = {
            'dist': dist,
            'request': edge,
            'router_name': name,
            'jobdata': jobdata
        }
        task = tasks.Task(task_name, resource_id,
                          self._deploy_edge,
                          status_callback=self._status_edge,
                          result_callback=self._result_edge,
                          userdata=userdata)
        task.add_executed_monitor(self.callbacks.edge_deploy_started)
        task.add_result_monitor(self.callbacks.edge_deploy_result)
        self.task_manager.add(task)

        if wait_for_exec:
            # waitl until the deploy task is executed so edge_id is available
            task.wait(task_constants.TaskState.EXECUTED)

        return task

    def update_edge(self, router_id, edge_id, name, internal_network,
                    jobdata=None, dist=False, loadbalancer_enable=True,
                    appliance_size=nsxv_constants.LARGE):
        """Update edge name."""
        task_name = 'update-%s' % name
        edge_name = name
        edge = self._assemble_edge(
            edge_name, datacenter_moid=self.datacenter_moid,
            deployment_container_id=self.deployment_container_id,
            appliance_size=appliance_size, remote_access=True, dist=dist)
        edge['id'] = edge_id
        appliance = self._assemble_edge_appliance(self.resource_pool_id,
                                                  self.datastore_id)
        if appliance:
            edge['appliances']['appliances'] = [appliance]

        if not dist:
            vnic_external = self._assemble_edge_vnic(
                constants.EXTERNAL_VNIC_NAME, constants.EXTERNAL_VNIC_INDEX,
                self.external_network, type="uplink")
            edge['vnics']['vnics'].append(vnic_external)
        else:
            edge['mgmtInterface'] = {
                'connectedToId': self.external_network,
                'name': "mgmtInterface"}

        if internal_network:
            internal_vnic = self._assemble_edge_vnic(
                constants.INTERNAL_VNIC_NAME, constants.INTERNAL_VNIC_INDEX,
                internal_network,
                constants.INTEGRATION_EDGE_IPADDRESS,
                constants.INTEGRATION_SUBNET_NETMASK,
                type="internal")
            edge['vnics']['vnics'].append(internal_vnic)
        if not dist and loadbalancer_enable:
            self._enable_loadbalancer(edge)
        userdata = {
            'edge_id': edge_id,
            'request': edge,
            'jobdata': jobdata
        }
        task = tasks.Task(task_name, router_id,
                          self._update_edge,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.edge_update_result)
        self.task_manager.add(task)
        return task

    def delete_edge(self, resource_id, edge_id, jobdata=None, dist=False):
        task_name = 'delete-%s' % edge_id
        userdata = {
            'router_id': resource_id,
            'dist': dist,
            'edge_id': edge_id,
            'jobdata': jobdata
        }
        task = tasks.Task(task_name, resource_id, self._delete_edge,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.edge_delete_result)
        self.task_manager.add(task)
        return task

    def _assemble_nat_rule(self, action, original_address,
                           translated_address,
                           vnic_index=constants.EXTERNAL_VNIC_INDEX,
                           enabled=True,
                           protocol='any',
                           original_port='any',
                           translated_port='any'):
        nat_rule = {}
        nat_rule['action'] = action
        nat_rule['vnic'] = vnic_index
        nat_rule['originalAddress'] = original_address
        nat_rule['translatedAddress'] = translated_address
        nat_rule['enabled'] = enabled
        nat_rule['protocol'] = protocol
        nat_rule['originalPort'] = original_port
        nat_rule['translatedPort'] = translated_port

        return nat_rule

    def get_nat_config(self, edge_id):
        try:
            return self.vcns.get_nat_config(edge_id)[1]
        except exceptions.VcnsApiException as e:
            LOG.exception(_LE("VCNS: Failed to get nat config:\n%s"),
                          e.response)
            raise e

    def _create_nat_rule(self, task):
        # TODO(fank): use POST for optimization
        #             return rule_id for future reference
        rule = task.userdata['rule']
        LOG.debug("VCNS: start creating nat rules: %s", rule)
        edge_id = task.userdata['edge_id']
        nat = self.get_nat_config(edge_id)
        location = task.userdata['location']

        del nat['version']

        if location is None or location == constants.APPEND:
            nat['rules']['natRulesDtos'].append(rule)
        else:
            nat['rules']['natRulesDtos'].insert(location, rule)

        try:
            self.vcns.update_nat_config(edge_id, nat)
            status = task_constants.TaskStatus.COMPLETED
        except exceptions.VcnsApiException as e:
            LOG.exception(_LE("VCNS: Failed to create snat rule:\n%s"),
                          e.response)
            status = task_constants.TaskStatus.ERROR

        return status

    def create_snat_rule(self, router_id, edge_id, src, translated,
                         jobdata=None, location=None):
        LOG.debug("VCNS: create snat rule %(src)s/%(translated)s", {
            'src': src, 'translated': translated})
        snat_rule = self._assemble_nat_rule("snat", src, translated)
        userdata = {
            'router_id': router_id,
            'edge_id': edge_id,
            'rule': snat_rule,
            'location': location,
            'jobdata': jobdata
        }
        task_name = "create-snat-%s-%s-%s" % (edge_id, src, translated)
        task = tasks.Task(task_name, router_id, self._create_nat_rule,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.snat_create_result)
        self.task_manager.add(task)
        return task

    def _delete_nat_rule(self, task):
        # TODO(fank): pass in rule_id for optimization
        #             handle routes update for optimization
        edge_id = task.userdata['edge_id']
        address = task.userdata['address']
        addrtype = task.userdata['addrtype']
        LOG.debug("VCNS: start deleting %(type)s rules: %(addr)s", {
            'type': addrtype, 'addr': address})
        nat = self.get_nat_config(edge_id)
        del nat['version']
        status = task_constants.TaskStatus.COMPLETED
        for nat_rule in nat['rules']['natRulesDtos']:
            if nat_rule[addrtype] == address:
                rule_id = nat_rule['ruleId']
                try:
                    self.vcns.delete_nat_rule(edge_id, rule_id)
                except exceptions.VcnsApiException as e:
                    LOG.exception(_LE("VCNS: Failed to delete snat rule:\n"
                                      "%s"), e.response)
                    status = task_constants.TaskStatus.ERROR

        return status

    def delete_snat_rule(self, router_id, edge_id, src, jobdata=None):
        LOG.debug("VCNS: delete snat rule %s", src)
        userdata = {
            'edge_id': edge_id,
            'address': src,
            'addrtype': 'originalAddress',
            'jobdata': jobdata
        }
        task_name = "delete-snat-%s-%s" % (edge_id, src)
        task = tasks.Task(task_name, router_id, self._delete_nat_rule,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.snat_delete_result)
        self.task_manager.add(task)
        return task

    def create_dnat_rule(self, router_id, edge_id, dst, translated,
                         jobdata=None, location=None):
        # TODO(fank): use POST for optimization
        #             return rule_id for future reference
        LOG.debug("VCNS: create dnat rule %(dst)s/%(translated)s", {
            'dst': dst, 'translated': translated})
        dnat_rule = self._assemble_nat_rule(
            "dnat", dst, translated)
        userdata = {
            'router_id': router_id,
            'edge_id': edge_id,
            'rule': dnat_rule,
            'location': location,
            'jobdata': jobdata
        }
        task_name = "create-dnat-%s-%s-%s" % (edge_id, dst, translated)
        task = tasks.Task(task_name, router_id, self._create_nat_rule,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.dnat_create_result)
        self.task_manager.add(task)
        return task

    def delete_dnat_rule(self, router_id, edge_id, translated,
                         jobdata=None):
        # TODO(fank): pass in rule_id for optimization
        LOG.debug("VCNS: delete dnat rule %s", translated)
        userdata = {
            'edge_id': edge_id,
            'address': translated,
            'addrtype': 'translatedAddress',
            'jobdata': jobdata
        }
        task_name = "delete-dnat-%s-%s" % (edge_id, translated)
        task = tasks.Task(task_name, router_id, self._delete_nat_rule,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.dnat_delete_result)
        self.task_manager.add(task)
        return task

    def _update_nat_rule(self, task):
        # TODO(fank): use POST for optimization
        #             return rule_id for future reference
        edge_id = task.userdata['edge_id']
        if task != self.updated_task['nat'][edge_id]:
            # this task does not have the latest config, abort now
            # for speedup
            return task_constants.TaskStatus.ABORT

        rules = task.userdata['rules']
        LOG.debug("VCNS: start updating nat rules: %s", rules)

        nat = {
            'featureType': 'nat',
            'rules': {
                'natRulesDtos': rules
            }
        }

        try:
            self.vcns.update_nat_config(edge_id, nat)
            status = task_constants.TaskStatus.COMPLETED
        except exceptions.VcnsApiException as e:
            LOG.exception(_LE("VCNS: Failed to create snat rule:\n%s"),
                          e.response)
            status = task_constants.TaskStatus.ERROR

        return status

    def update_nat_rules(self, router_id, edge_id, snats, dnats,
                         jobdata=None):
        LOG.debug("VCNS: update nat rule\n"
                  "SNAT:%(snat)s\n"
                  "DNAT:%(dnat)s\n", {
                        'snat': snats, 'dnat': dnats})
        nat_rules = []

        for dnat in dnats:
            nat_rules.append(self._assemble_nat_rule(
                'dnat', dnat['dst'], dnat['translated']))
            nat_rules.append(self._assemble_nat_rule(
                'snat', dnat['translated'], dnat['dst']))

        for snat in snats:
            nat_rules.append(self._assemble_nat_rule(
                'snat', snat['src'], snat['translated']))

        userdata = {
            'edge_id': edge_id,
            'rules': nat_rules,
            'jobdata': jobdata,
        }
        task_name = "update-nat-%s" % edge_id
        task = tasks.Task(task_name, router_id, self._update_nat_rule,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.nat_update_result)
        self.updated_task['nat'][edge_id] = task
        self.task_manager.add(task)
        return task

    def update_dnat_rules(self, edge_id, dnat_rules):
        edge_nat_rules = []
        for rule in dnat_rules:
            edge_nat_rules.append(
                self._assemble_nat_rule(
                    'dnat',
                    rule['dst'],
                    rule['translated'],
                    vnic_index=rule['vnic_index'],
                    enabled=True,
                    protocol=rule['protocol'],
                    original_port=rule['original_port'],
                    translated_port=rule['translated_port']))

        nat = {
            'featureType': 'nat',
            'rules': {
                'natRulesDtos': edge_nat_rules
            }
        }

        self.vcns.update_nat_config(edge_id, nat)

    def _update_routes(self, task):
        edge_id = task.userdata['edge_id']
        if (task != self.updated_task['route'][edge_id] and
            task.userdata.get('skippable', True)):
            # this task does not have the latest config, abort now
            # for speedup
            return task_constants.TaskStatus.ABORT
        gateway = task.userdata['gateway']
        gateway_vnic_index = task.userdata['gateway_vnic_index']
        routes = task.userdata['routes']
        LOG.debug("VCNS: start updating routes for %s", edge_id)
        static_routes = []
        for route in routes:
            if route.get('vnic_index') is None:
                static_routes.append({
                    "description": "",
                    "vnic": constants.INTERNAL_VNIC_INDEX,
                    "network": route['cidr'],
                    "nextHop": route['nexthop']
                })
            else:
                static_routes.append({
                    "description": "",
                    "vnic": route['vnic_index'],
                    "network": route['cidr'],
                    "nextHop": route['nexthop']
                })
        request = {
            "staticRoutes": {
                "staticRoutes": static_routes
            }
        }
        if gateway:
            request["defaultRoute"] = {
                "description": "default-gateway",
                "gatewayAddress": gateway,
                "vnic": gateway_vnic_index
            }
        try:
            self.vcns.update_routes(edge_id, request)
            status = task_constants.TaskStatus.COMPLETED
        except exceptions.VcnsApiException as e:
            LOG.exception(_LE("VCNS: Failed to update routes:\n%s"),
                          e.response)
            status = task_constants.TaskStatus.ERROR

        return status

    def update_routes(self, router_id, edge_id, gateway, routes,
                      skippable=True, jobdata=None,
                      gateway_vnic_index=constants.EXTERNAL_VNIC_INDEX):
        if gateway:
            gateway = gateway.split('/')[0]

        userdata = {
            'edge_id': edge_id,
            'gateway': gateway,
            'gateway_vnic_index': gateway_vnic_index,
            'routes': routes,
            'skippable': skippable,
            'jobdata': jobdata
        }
        task_name = "update-routes-%s" % (edge_id)
        task = tasks.Task(task_name, router_id, self._update_routes,
                          userdata=userdata)
        task.add_result_monitor(self.callbacks.routes_update_result)
        self.updated_task['route'][edge_id] = task
        self.task_manager.add(task)
        return task

    def create_lswitch(self, name, tz_config, tags=None,
                       port_isolation=False, replication_mode="service"):
        lsconfig = {
            'display_name': utils.check_and_truncate(name),
            "tags": tags or [],
            "type": "LogicalSwitchConfig",
            "_schema": "/ws.v1/schema/LogicalSwitchConfig",
            "transport_zones": tz_config
        }
        if port_isolation is bool:
            lsconfig["port_isolation_enabled"] = port_isolation
        if replication_mode:
            lsconfig["replication_mode"] = replication_mode

        response = self.vcns.create_lswitch(lsconfig)[1]
        return response

    def delete_lswitch(self, lswitch_id):
        self.vcns.delete_lswitch(lswitch_id)

    def get_loadbalancer_config(self, edge_id):
        try:
            header, response = self.vcns.get_loadbalancer_config(
                edge_id)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to get service config"))
        return response

    def enable_service_loadbalancer(self, edge_id):
        config = self.get_loadbalancer_config(
            edge_id)
        if not config['enabled']:
            config['enabled'] = True
        try:
            self.vcns.enable_service_loadbalancer(edge_id, config)
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Failed to enable loadbalancer "
                                  "service config"))

    def _delete_port_group(self, task):
        try:
            header, response = self.vcns.get_edge_id(task.userdata['job_id'])
        except exceptions.VcnsApiException:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("NSXv: Failed to get job for %s"),
                          task.userdata)
        status = response['status']
        if status != 'COMPLETED':
            if (status == 'QUEUED' or status == 'RUNNING' or
                status == 'ROLLBACK'):
                LOG.debug("NSXv: job is still pending for %s", task.userdata)
                return task_constants.TaskStatus.PENDING
        try:
            self.vcns.delete_port_group(
                task.userdata['dvs_id'],
                task.userdata['port_group_id'])
        except Exception as e:
            LOG.error(_LE('Unable to delete %(pg)s (job status %(state)s) '
                          'exception %(ex)s'),
                      {'pg': task.userdata['port_group_id'],
                       'state': status,
                       'ex': e})
        if status == 'FAILED':
            return task_constants.TaskStatus.ERROR
        return task_constants.TaskStatus.COMPLETED

    def delete_portgroup(self, dvs_id, port_group_id, job_id):
        task_name = "delete-port-group-%s" % port_group_id
        userdata = {'dvs_id': dvs_id,
                    'port_group_id': port_group_id,
                    'job_id': job_id}
        task = tasks.Task(task_name, port_group_id,
                          self._delete_port_group,
                          status_callback=self._delete_port_group,
                          userdata=userdata)
        self.task_manager.add(task)

    def _retry_task(self, task):
        delay = 0.5
        max_retries = max(cfg.CONF.nsxv.retries, 1)
        args = task.userdata.get('args', [])
        kwargs = task.userdata.get('kwargs', {})
        retry_number = task.userdata['retry_number']
        retry_command = task.userdata['retry_command']
        try:
            retry_command(*args, **kwargs)
        except Exception as exc:
            LOG.debug("Task %(name)s retry %(retry)s failed %(exc)s",
                      {'name': task.name,
                       'exc': exc,
                       'retry': retry_number})
            retry_number += 1
            if retry_number > max_retries:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Failed to %s"), task.name)
            else:
                task.userdata['retry_number'] = retry_number
                # Sleep twice as long as the previous retry
                tts = (2 ** (retry_number - 1)) * delay
                time.sleep(min(tts, 60))
                return task_constants.TaskStatus.PENDING
        LOG.info(_LI("Task %(name)s completed."), {'name': task.name})
        return task_constants.TaskStatus.COMPLETED

    def delete_port_group(self, dvs_id, port_group_id):
        task_name = 'delete-port-group-%s-%s' % (port_group_id, dvs_id)
        userdata = {'retry_number': 1,
                    'retry_command': self.vcns.delete_port_group,
                    'args': [dvs_id, port_group_id]}
        task = tasks.Task(task_name, port_group_id,
                          self._retry_task,
                          status_callback=self._retry_task,
                          userdata=userdata)
        self.task_manager.add(task)

    def delete_virtual_wire(self, vw_id):
        task_name = 'delete-virtualwire-%s' % vw_id
        userdata = {'retry_number': 1,
                    'retry_command': self.vcns.delete_virtual_wire,
                    'args': [vw_id]}
        task = tasks.Task(task_name, vw_id,
                          self._retry_task,
                          status_callback=self._retry_task,
                          userdata=userdata)
        self.task_manager.add(task)
