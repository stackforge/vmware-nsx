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

We support the following functions for now:
* Be able to read the database and configuration files.
* Be able to access the backend via API
* Compare data from different sources and decide next course of
  action.

TODO: Use cliff
TODO: Define commands instead of -r -o like get-security-groups,
delete-security-groups, nsx neutron nsxv3 can be options
TODO: Write formatters wrapper
TODO: Support ports, logical switches
TODO: Autocomplete command line args
TODO: Error when unsupported operations are called for.
"""

import requests
import sys

from neutron.callbacks import registry
from neutron.common import config as neutron_config

from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import config as nsx_config

from nsxadmin.nsx_plugins.nsxv3.resources import securitygroups as sg

# Suppress the Insecure request warning
requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)

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
    VERSION = '0.1'
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


def register_nsx_opts():
    cfg.CONF.register_opts(nsx_config.connection_opts)
    cfg.CONF.register_opts(nsx_config.cluster_opts)
    cfg.CONF.register_opts(nsx_config.nsx_v3_opts, group="nsx_v3")
    cfg.CONF.register_opts(nsx_config.nsxv_opts, group="nsxv")
    cfg.CONF.register_opts(nsx_config.base_opts, group="NSX")
    cfg.CONF.register_opts(nsx_config.sync_opts, group="NSX_SYNC")


def register_neutron_opts():
    cfg.CONF.register_opts(neutron_config.core_opts)
    cfg.CONF.register_opts(neutron_config.core_cli_opts)


def init_cfg():
    register_nsx_opts()
    register_neutron_opts()
    cfg.CONF.register_cli_opts(cli_opts)
    cfg.CONF(args=sys.argv[1:],
             project=Constants.PROJECT,
             prog=Constants.PROGRAM,
             version=Constants.VERSION,
             usage=Constants.USAGE,
             default_config_files=[cfg.CONF.neutron_conf,
                                   cfg.CONF.nsx_conf])

    LOG.info("Config initialized")


def init_logging():
    logging.register_options(cfg.CONF)
    logging.set_defaults()
    logging.setup(cfg.CONF, Constants.PROGRAM, Constants.VERSION)


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
    LOG.info("Callbacks Subscribed")


def main(argv=sys.argv[1:]):
    init_logging()
    init_cfg()
    init_registry()
    registry.notify(cfg.CONF.resource, cfg.CONF.operation, "admin")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
