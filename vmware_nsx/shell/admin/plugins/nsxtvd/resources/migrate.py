# Copyright 2017 VMware, Inc.  All rights reserved.
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

import sys

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron.extensions import securitygroup as ext_sg
from neutron_lib.callbacks import registry
from neutron_lib import context as n_context
from neutron_lib import exceptions

from vmware_nsx.api_replay import utils as replay_utils
from vmware_nsx.db import db
from vmware_nsx.extensions import projectpluginmap
from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
from vmware_nsx.shell.admin.plugins.nsxv.resources import utils as v_utils
from vmware_nsx.shell.admin.plugins.nsxv3.resources import utils as v3_utils
from vmware_nsx.shell import resources as shell

LOG = logging.getLogger(__name__)
# list of supported objects to migrate in order of deletion (creation will be
# in the opposite order)
migrated_resources = ["floatingip", "router", "port", "subnet",
                      "network", "security_group"]
#TODO(asarfaty): add other resources of different service plugins like
#vpnaas, fwaas, lbaas, qos, subnetpool, etc


@admin_utils.output_header
def import_projects(resource, event, trigger, **kwargs):
    """Import existing openstack projects to the current plugin"""
    # TODO(asarfaty): get the projects list from keystone

    # get the plugin name from the user
    if not kwargs.get('property'):
        LOG.error("Need to specify plugin and project parameters")
        return
    else:
        properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
        plugin = properties.get('plugin')
        project = properties.get('project')
        if not plugin or not project:
            LOG.error("Need to specify plugin and project parameters")
            return
    if plugin not in projectpluginmap.VALID_TYPES:
        LOG.error("The supported plugins are %s", projectpluginmap.VALID_TYPES)
        return

    ctx = n_context.get_admin_context()
    if not db.get_project_plugin_mapping(ctx.session, project):
        db.add_project_plugin_mapping(ctx.session, project, plugin)


def get_resource_file_name(project_id, resource):
    return "%s_nsxv_%ss" % (project_id, resource)

def read_v_resources_to_files(context, project_id):
    """Read all relevant NSX-V resources from a specific project

    and write them into a json file
    """
    results = {}
    with v_utils.NsxVPluginWrapper() as plugin:
        filters = {'project_id': [project_id]}
        for resource in migrated_resources:
            filename = get_resource_file_name(project_id, resource)
            file = open(filename, 'w')
            get_objects = getattr(plugin, "get_%ss" % resource)
            objects = get_objects(context, filters=filters)
            file.write(jsonutils.dumps(objects, sort_keys=True, indent=4))
            file.close()
            results[resource] = objects
    return results


def read_v_resources_from_files(project_id):
    """Read all relevant NSX-V resources from a json file"""
    results = {}
    for resource in migrated_resources:
        filename = get_resource_file_name(project_id, resource)
        file = open(filename, 'r')
        results[resource] = jsonutils.loads(file.read())
        file.close()
    return results


def delete_router_interfaces(context, plugin, router):
    #TODO(asarfaty) consider delete this when coming across the port,
    # before the router deletion
    interfaces = plugin._get_router_interfaces(context, router['id'])
    for port in interfaces:
        plugin.remove_router_interface(context, router['id'],
                                       {'port_id': port['id']})


def delete_v_resources(context, objects):
    """Delete a list of objects from the V plugin"""
    LOG.info("Deleting all remaining NSX-V objects of the project.")
    with v_utils.NsxVPluginWrapper() as plugin:
        for resource in migrated_resources:
            del_object = getattr(plugin, "delete_%s" % resource)
            for obj in objects[resource]:
                try:
                    if resource == 'router':
                        delete_router_interfaces(context, plugin, obj)
                    if resource == 'port':
                        if obj['device_owner'] == 'network:dhcp':
                            continue

                    del_object(context, obj['id'])
                    LOG.info(">>Deleted %(resource)s %(name)s",
                             {'resource': resource,
                              'name': obj.get('name') or obj['id']})
                except exceptions.NotFound:
                    # prevent logger from logging this exception
                    sys.exc_clear()
                except Exception as e:
                    LOG.warning(">>Failed to delete %(resource)s %(name)s: "
                                "%(e)s",
                                {'resource': resource,
                                 'name': obj.get('name') or obj['id'], 'e': e})
    LOG.info("Done deleting all NSX-V objects.")


def create_t_resources(context, objects, ext_net):
    """Create a list of objects in the T plugin"""
    LOG.info("Creating all projects objects in NSX-T.")
    prepare = replay_utils.PrepareObjectForMigration()
    with v3_utils.NsxV3PluginWrapper() as plugin:
        # create the resource in the order opposite to the deletion
        # (but start with routers)
        ordered_resources = migrated_resources[::-1]
        ordered_resources.remove('router')
        ordered_resources = ['router'] + ordered_resources
        for resource in ordered_resources:
            total_num = len(objects[resource])
            LOG.info(">>>Creating %s %ss", total_num, resource)
            get_object = getattr(plugin, "get_%s" % resource)
            create_object = getattr(plugin, "create_%s" % resource)
            dhcp_subnets = []
            # go over the objects of this resource
            for count, obj in enumerate(objects[resource], 1):
                # check if this object already exists
                try:
                    get_object(context, obj['id'])
                except exceptions.NotFound:
                    # prevent logger from logging this exception
                    sys.exc_clear()
                else:
                    # already exists (this will happen if we rerun from files,
                    # or if the deletion failed)
                    LOG.info(">>Skipping %(resource)s %(name)s %(count)s/"
                             "%(total)s as it "
                             "is already created.",
                             {'resource': resource,
                              'name': obj.get('name') or obj['id'],
                              'count': count,
                              'total': total_num})
                    continue

                # fix object before creation using the api replay code
                orig_id = obj['id']
                prepare_object = getattr(prepare, "prepare_%s" % resource)
                obj_data = prepare_object(obj)

                # special cases for different objects before create:
                if resource == 'subnet':
                    if obj_data['enable_dhcp']:
                        # disable dhcp for now, to avoid ip collisions
                        obj_data['enable_dhcp'] = False
                        dhcp_subnets.append(obj_data['id'])
                if resource == 'security_group':
                    # security group rules should be added separately
                    sg_rules = obj_data.pop('security_group_rules')
                if resource == 'port':
                    if obj_data['device_owner'] == 'network:dhcp':
                        continue
                    if obj_data['device_owner'] == 'network:floatingip':
                        continue
                    if obj_data['device_owner'] == 'network:router_gateway':
                        # add a gateway on the new ext network for this router
                        router_id = obj_data['device_id']
                        router_data = objects['rotuers'][router_id]
                        enable_snat = router_data['external_gateway_info'].get(
                                'enable_snat', True)
                        rtr_body = {
                            "external_gateway_info":
                                {"network_id": ext_net,
                                 "enable_snat": enable_snat}}
                        try:
                            plugin.update_router(
                                context, router_id, {'router': rtr_body})
                            LOG.info(">>Uplinked router %(rtr)s to new "
                                     "external network %(net)s",
                                     {'rtr': router_id,
                                      'net': ext_net})

                        except Exception as e:
                            LOG.error(">>Failed to add router %(rtr)s "
                                      "gateway: %(e)s",
                                      {'rtr': router_id, 'e': e})
                        continue
                    if obj_data['device_owner'] == 'network:router_interface':
                        try:
                            # uplink router_interface ports by creating the
                            # port, and attaching it to the router
                            router_id = obj_data['device_id']
                            del obj_data['device_owner']
                            del obj_data['device_id']
                            created_port = plugin.create_port(
                                context,
                                {'port': obj_data})['port']
                            LOG.info(">>Created interface port %(port)s, ip "
                                     "%(ip)s, mac %(mac)s)",
                                     {'port': created_port['id'],
                                      'ip': created_port['fixed_ips'][0][
                                            'ip_address'],
                                      'mac': created_port['mac_address']})
                            plugin.add_interface_router(
                                router_id,
                                {'port_id': created_port['id']})
                            LOG.info(">>Uplinked router %(rtr)s to network "
                                     "%(net)s",
                                     {'rtr': router_id,
                                      'net': obj_data['network_id']})
                        except Exception as e:
                            LOG.error(">>Failed to add router %(rtr)s "
                                      "interface port: %(e)s",
                                      {'rtr': router_id, 'e': e})
                        continue
                    # remove the old subnet id field from ports fixed_ips dict
                    for fixed_ips in obj_data['fixed_ips']:
                        del fixed_ips['subnet_id']

                # create the object on the NSX-T plugin
                try:
                    create_object(context, {resource: obj_data})
                    LOG.info(">>Created %(resource)s %(name)s %(count)s/"
                             "%(total)s",
                             {'resource': resource, 'count': count,
                              'name': obj_data.get('name') or orig_id,
                              'total': total_num})
                except Exception as e:
                    LOG.error(">>Failed to create %(resource)s %(name)s: "
                              "%(e)s",
                              {'resource': resource,
                               'name': obj_data.get('name') or orig_id,
                               'e': e})

                # special cases for different objects after create:
                if resource == 'security_group':
                    sg_id = obj_data.get('name') or obj_data['id']
                    for rule in sg_rules:
                        rule_data = prepare.prepare_security_group_rule(rule)
                        try:
                            plugin.create_security_group_rule(
                                context, {'security_group_rule': rule_data})
                        except ext_sg.SecurityGroupRuleExists:
                            # default rules were already created.
                            # prevent logger from logging this exception
                            sys.exc_clear()
                        except Exception as e:
                            LOG.error(
                                ">>Failed to create security group %(name)s "
                                "rules: %(e)s",
                                {'name': sg_id, 'e': e})

            # Enable dhcp on the relevant subnets:
            if resource == 'subnet' and dhcp_subnets:
                for subnet_id in dhcp_subnets:
                    try:
                        plugin.update_subnet(
                            context, subnet_id,
                            {'subnet': {'enable_dhcp': True}})
                    except Exception as e:
                        LOG.error("Failed to enable DHCP on subnet %(subnet)s:"
                                  " %(e)s",
                                  {'subnet': subnet_id, 'e': e})


@admin_utils.output_header
def migrate_v_project_to_t(resource, event, trigger, **kwargs):
    """Migrate 1 project from v to t with all its resources"""
    # get the configuration: tenant + public network + from file flag
    usage = ("Usage: nsxadmin -r projects -o %s --property project-id=<> "
             "--property external-net=<NSX-T external network to be used> "
             "<--property from-file=True>" %
             shell.Operations.NSX_MIGRATE_V_V3.value)
    if not kwargs.get('property'):
        LOG.error("Missing parameters: %s", usage)
        return
    properties = admin_utils.parse_multi_keyval_opt(kwargs['property'])
    project = properties.get('project-id')
    ext_net_id = properties.get('external-net')
    from_file = properties.get('from-file', 'false').lower() == "true" 
    # TODO(asarfaty): get files path
    if not project:
        LOG.error("Missing project-id parameter: %s", usage)
        return
    if not ext_net_id:
        LOG.error("Missing external-net parameter: %s", usage)
        return
    if not from_file:
        # check if files exist in the current directory
        filename = get_resource_file_name(project, 'network')
        try:
            file = open(filename, 'r')
            if file.read():
                from_file = admin_utils.query_yes_no(
                    "Use existing resources files for this project?",
                    default="yes")
            file.close()
        except Exception as e:
            sys.exc_clear()


    # validate tenant id and public network
    ctx = n_context.get_admin_context()
    mapping = db.get_project_plugin_mapping(ctx.session, project)
    if not mapping:
        LOG.error("Project %s is unknown", project)
        return
    if not from_file and mapping.plugin != projectpluginmap.NsxPlugins.NSX_V:
        LOG.error("Project %s belongs to plugin %s.", project, mapping.plugin)
        return

    with v3_utils.NsxV3PluginWrapper() as plugin:
        try:
            plugin.get_network(ctx, ext_net_id)
        except exceptions.NetworkNotFound:
            LOG.error("Network %s was not found", ext_net_id)
            return
        if not plugin._network_is_external(ctx, ext_net_id):
            LOG.error("Network %s is not external", ext_net_id)
            return

    if from_file:
        # read resources from files
        objects = read_v_resources_from_files(project)
    else:
        # read all V resources and dump to a file
        objects = read_v_resources_to_files(ctx, project)

    # delete all the V resources (reading it from the files)
    delete_v_resources(ctx, objects)

    # change the mapping of this tenant to T
    db.update_project_plugin_mapping(ctx.session, project,
                                     projectpluginmap.NsxPlugins.NSX_T)

    # use api replay flag to allow keeping the IDs
    cfg.CONF.set_override('api_replay_mode', True)

    # add resources 1 by one after adapting them to T (api-replay code)
    create_t_resources(ctx, objects, ext_net_id)

    # reset api replay flag to allow keeping the IDs
    cfg.CONF.set_override('api_replay_mode', False)


registry.subscribe(import_projects,
                   constants.PROJECTS,
                   shell.Operations.IMPORT.value)

registry.subscribe(migrate_v_project_to_t,
                   constants.PROJECTS,
                   shell.Operations.NSX_MIGRATE_V_V3.value)
