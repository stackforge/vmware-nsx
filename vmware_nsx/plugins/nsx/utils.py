# Copyright 2014 VMware, Inc.
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

from oslo_config import cfg

from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from vmware_nsx.db import db as nsx_db


def is_tvd_core_plugin():
    core_plugin = cfg.CONF.core_plugin
    if (core_plugin.endswith('NsxTVDPlugin') or
        core_plugin.endswith('vmware_nsxtvd')):
        return True
    return False


def get_plugin_type_for_project(context, project_id):
    """Get the plugin type used by a project

    Raise an exception if not found or the plugin is not in use
    """
    mapping = nsx_db.get_project_plugin_mapping(
        context.session, project_id)
    if mapping:
        plugin_type = mapping['plugin']
    else:
        msg = (_("Couldn't find the plugin project %s is using") % project_id)
        raise n_exc.InvalidInput(error_message=msg)

    # make sure the core plugin is supported
    core_plugin = directory.get_plugin()
    if not core_plugin.get_plugin_by_type(plugin_type):
        msg = (_("Plugin %(plugin)s for project %(project)s is not "
                 "supported by the TVD core plugin") % {
                'project': project_id,
                'plugin': plugin_type})
        raise n_exc.InvalidInput(error_message=msg)

    return plugin_type
