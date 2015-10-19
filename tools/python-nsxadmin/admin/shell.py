# Copyright 2015 VMware, Inc.  All rights reserved.
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

"""
Purpose of this script is to build a framework which can be leveraged
to build utilities to help the on-field ops in system debugging.


TODO: Use Cliff https://pypi.python.org/pypi/cliff
TODO: Define commands instead of -r -o like get-security-groups,
delete-security-groups, nsx neutron nsxv3 can be options
TODO: Add support for other resources, ports, logical switches etc.
TODO: Autocomplete command line args
TODO: Error handling, print only options which are supported
"""

from enum import Enum

import glob
import importlib
import logging
import os
from os.path import basename
import requests
import sys

from neutron.callbacks import registry
from neutron.common import config as neutron_config

from vmware_nsx.common import config  # noqa

from oslo_config import cfg
from oslo_log import _options

from admin.plugins.common import constants

from admin import version

# Suppress the Insecure request warning
requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)


class Operations(Enum):
    LIST = 'list'
    CLEAN = 'clean'

    NEUTRON_LIST = 'neutron_list'
    NEUTRON_CLEAN = 'neutron_clean'

    NSX_LIST = 'nsx_list'
    NSX_CLEAN = 'nsx_clean'


class Resources(Enum):
    SECURITY_GROUPS = 'security-groups'
    EDGES = "edges"

def get_plugin():
    plugin = cfg.CONF.core_plugin
    plugin_name = ''
    if plugin == constants.NSXV3_PLUGIN:
        plugin_name = 'nsxv3'
    elif plugin == constants.NSXV_PLUGIN:
        plugin_name = 'nsxv'
    return plugin_name


def get_plugin_dir():
    return 'admin/plugins/{}/resources'.format(get_plugin())


def get_resources():
    modules = glob.glob(get_plugin_dir() + "/*.py")
    return map(lambda module: os.path.splitext(basename(module))[0], modules)


resources = [resource.value for resource in Resources]
ops = [op.value for op in Operations]


cli_opts = [cfg.StrOpt('neutron-conf',
                       default='/etc/neutron/neutron.conf',
                       help='Neutron configuration file'),
            cfg.StrOpt('nsx-conf',
                       default='/etc/neutron/plugins/vmware/nsx.ini',
                       help='NSX configuration file'),
            cfg.StrOpt('fmt',
                       short='f',
                       default='psql',
                       choices=['psql', 'json'],
                       help='Supported output formats: json, psql'),
            cfg.StrOpt('resource',
                       short='r',
                       choices=resources,
                       help='Supported list of resources: {}'
                             .format(', '.join(resources))),
            cfg.StrOpt('operation',
                       short='o',
                       choices=ops,
                       help='Supported list of operations: {}'
                             .format(', '.join(ops))),
            ]


def init_plugin():
    resources = get_resources()
    for resource in resources:
        if resource != '__init__':
            importlib.import_module("." + resource,
                                    get_plugin_dir().replace("/", "."))


def init_cfg():
    cfg.CONF.register_cli_opts(cli_opts)

    # NOTE(gangila): neutron.common.config registers some options by default
    # which are then shown in the help message. We don't need them
    # so we unregister these options
    cfg.CONF.unregister_opts(_options.common_cli_opts)
    cfg.CONF.unregister_opts(_options.logging_cli_opts)
    cfg.CONF.unregister_opts(neutron_config.core_cli_opts)

    cfg.CONF(args=sys.argv[1:], project='NSX',
             prog='Admin Utility',
             version=version.__version__,
             usage='nsxadmin -r <resources> -o <operation>',
             default_config_files=[cfg.CONF.neutron_conf,
                                   cfg.CONF.nsx_conf])


def main(argv=sys.argv[1:]):
    init_cfg()
    init_plugin()
    LOG.info('NSX Plugin in use: {}'.format(get_plugin()))
    registry.notify(cfg.CONF.resource, cfg.CONF.operation, "admin")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
