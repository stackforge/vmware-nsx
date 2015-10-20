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

from enum import Enum

import requests
import sys

from neutron.callbacks import registry
from neutron.common import config as neutron_config

from vmware_nsx.common import config  # noqa

from oslo_config import cfg
from oslo_log import _options

from admin.plugins.nsxv3.resources import securitygroups as sg
from admin.plugins.nsxv.resources import edges
from admin.plugins.nsxv.resources import spoofguard_policy as sgp
from admin import version


# Suppress the Insecure request warning
requests.packages.urllib3.disable_warnings()

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
    SPOOFGUARD_POLICIES = "spoofguard-policies"

cli_opts = [cfg.StrOpt('neutron_conf',
                       default='/etc/neutron/neutron.conf',
                       help='Neutron configuration file'),
            cfg.StrOpt('nsx_conf',
                       default='/etc/neutron/plugins/vmware/nsx.ini',
                       help='NSX configuration file'),
            cfg.StrOpt('resource',
                       short='r',
                       help='Supported list of resources: {}'
                       .format([resource.value for resource in Resources])),
            cfg.StrOpt('operation',
                       short='o',
                       help='Supported list of operations: {}'
                       .format([op.value for op in Operations])),
            cfg.StrOpt('fmt',
                       short='f',
                       default='psql',
                       choices=['psql', 'json'],
                       help='Supported output formats: json, psql')
            ]


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


def init_registry():
    registry.subscribe(sg.neutron_clean_security_groups,
                       Resources.SECURITY_GROUPS.value,
                       Operations.NEUTRON_CLEAN.value)
    registry.subscribe(sg.neutron_list_security_groups,
                       Resources.SECURITY_GROUPS.value,
                       Operations.NEUTRON_LIST.value)
    registry.subscribe(sg.nsx_list_security_groups,
                       Resources.SECURITY_GROUPS.value,
                       Operations.NSX_LIST.value)
    registry.subscribe(sg.nsx_clean_security_groups,
                       Resources.SECURITY_GROUPS.value,
                       Operations.NSX_CLEAN.value)
    registry.subscribe(sg.neutron_list_security_groups,
                       Resources.SECURITY_GROUPS.value,
                       Operations.LIST.value)
    registry.subscribe(sg.nsx_list_security_groups,
                       Resources.SECURITY_GROUPS.value,
                       Operations.LIST.value)
    registry.subscribe(sg.neutron_clean_security_groups,
                       Resources.SECURITY_GROUPS.value,
                       Operations.CLEAN.value)
    registry.subscribe(sg.nsx_clean_security_groups,
                       Resources.SECURITY_GROUPS.value,
                       Operations.CLEAN.value)
    registry.subscribe(edges.nsx_list_edges,
                       Resources.EDGES.value,
                       Operations.LIST.value)
    registry.subscribe(edges.neutron_list_router_edge_bindings,
                       Resources.EDGES.value,
                       Operations.LIST.value)
    registry.subscribe(edges.nsx_list_orphaned_edges,
                       Resources.EDGES.value,
                       Operations.LIST.value)
    registry.subscribe(edges.nsx_delete_orphaned_edges,
                       Resources.EDGES.value,
                       Operations.CLEAN.value)
    registry.subscribe(sgp.nsx_list_spoofguard_policies,
                       Resources.SPOOFGUARD_POLICIES.value,
                       Operations.LIST.value)
    registry.subscribe(sgp.neutron_list_spoofguard_policy_mappings,
                       Resources.SPOOFGUARD_POLICIES.value,
                       Operations.LIST.value)


def main(argv=sys.argv[1:]):
    init_cfg()
    init_registry()
    registry.notify(cfg.CONF.resource, cfg.CONF.operation, "admin")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
