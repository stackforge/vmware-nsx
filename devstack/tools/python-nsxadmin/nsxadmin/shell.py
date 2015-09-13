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
TODO: Write formatters wrapper
TODO: Add support for other resources, ports, logical switches etc.
TODO: Autocomplete command line args
TODO: Error when unsupported operations are called for.
"""

import requests
import sys

from neutron.callbacks import registry
from neutron.common import config as neutron_config

from oslo_config import cfg
from oslo_log import _options

# from oslo_db import options as db_options

from vmware_nsx.common import config as nsx_config

from nsxadmin.nsx_plugins.common import nsxadmin_logging as logging
from nsxadmin.nsx_plugins.nsxv3.resources import securitygroups as sg
from nsxadmin import version

# Suppress the Insecure request warning
requests.packages.urllib3.disable_warnings()


LOG = logging.getLogger(__name__)

# conf = cfg.ConfigOpts()

cli_opts = [cfg.StrOpt('neutron_conf',
                       default='/etc/neutron/neutron.conf',
                       help='Neutron configuration file'),
            cfg.StrOpt('nsx_conf',
                       default='/etc/neutron/plugins/vmware/nsx.ini',
                       help='NSX configuration file'),
            cfg.StrOpt('resource',
                       short='r',
                       help='Supported list of resources: '
                            'security-groups'),
            cfg.StrOpt('operation',
                       short='o',
                       help='Supported list of operations: '
                       'list, clean, nsx_list, nsx_clean, '
                       'neutron_list, neutron_clean')
            ]


class Constants(object):
    PROJECT = 'NSX'
    PROGRAM = 'Admin Utility'
    USAGE = 'nsxadmin -r <resource_name> -o <operation>'


class Operations(object):
    LIST = 'list'
    CLEAN = 'clean'

    NEUTRON_LIST = 'neutron_list'
    NEUTRON_CLEAN = 'neutron_clean'

    NSX_LIST = 'nsx_list'
    NSX_CLEAN = 'nsx_clean'


class Resources(object):
    SECURITY_GROUPS = 'security-groups'


def init_cfg():
    cfg.CONF.register_cli_opts(cli_opts)
    
    # NOTE: neutron.common.config registers some options by default
    # which are then shown in the help message. We don't need them
    # so we unregister these options
    cfg.CONF.unregister_opts(_options.common_cli_opts)
    cfg.CONF.unregister_opts(_options.logging_cli_opts)
    cfg.CONF.unregister_opts(neutron_config.core_cli_opts)

    cfg.CONF(args=sys.argv[1:], project=Constants.PROJECT,
             prog=Constants.PROGRAM,
             version=version.__version__,
             usage=Constants.USAGE,
             default_config_files=[cfg.CONF.neutron_conf,
                                   cfg.CONF.nsx_conf])


def init_registry():
    registry.subscribe(sg.neutron_clean_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.NEUTRON_CLEAN)
    registry.subscribe(sg.neutron_list_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.NEUTRON_LIST)
    registry.subscribe(sg.nsx_list_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.NSX_LIST)
    registry.subscribe(sg.nsx_clean_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.NSX_CLEAN)
    registry.subscribe(sg.neutron_list_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.LIST)
    registry.subscribe(sg.nsx_list_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.LIST)
    registry.subscribe(sg.neutron_clean_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.CLEAN)
    registry.subscribe(sg.nsx_clean_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.CLEAN)


def main(argv=sys.argv[1:]):
    init_cfg()
    init_registry()
    registry.notify(cfg.CONF.resource, cfg.CONF.operation, "admin")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
