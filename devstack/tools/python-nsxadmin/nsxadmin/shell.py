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
#     under the License.


from cliff import app
from cliff import commandmanager

import argparse
import sys
import requests

from neutron.callbacks import registry
from neutron.common import config as neutron_config

from oslo_config import cfg
from oslo_log import log as logging

from vmware_nsx.common import config as nsx_config

from nsxadmin.nsx_plugins.nsxv3.resources import securitygroups as sg

# Suppress the Insecure request warning
requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)
PROGRAM = 'Command-line interface to administrate VMware-NSX deployments.'
VERSION = '0.1'

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
                       'list, delete, nsx_list, nsx_delete, '
                       'neutron_list, neutron_delete')
            ]


class Operations(object):
    LIST = 'list'
    SYNC = 'sync'
    CLEAN = 'delete'

    NEUTRON_LIST = 'neutron_list'
    NEUTRON_CLEAN = 'neutron_delete'

    NSX_LIST = 'nsx_list'
    NSX_CLEAN = 'nsx_delete'


class Resources(object):
    EDGES = 'edges'
    PORTS = 'ports'
    LSWITCHES = 'logical-switches'
    SECURITY_GROUPS = 'security-groups'


COMMANDS_V1 = {
    'security-groups-list': sg.ListSecurityGroups,
    'security-groups-delete': sg.DeleteSecurityGroups,
}

COMMANDS = {VERSION: COMMANDS_V1}
apiversion = VERSION


class HelpAction(argparse.Action):
    """Provide a custom action so the -h and --help options
    to the main app will print a list of the commands.
    The commands are determined by checking the CommandManager
    instance, passed in as the "default" value for the action.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        outputs = []
        max_len = 0
        app = self.default
        parser.print_help(app.stdout)
        app.stdout.write(_('\nCommands for API v%s:\n') % app.api_version)
        command_manager = app.command_manager
        for name, ep in sorted(command_manager):
            factory = ep.load()
            cmd = factory(self, None)
            one_liner = cmd.get_description().split('\n')[0]
            outputs.append((name, one_liner))
            max_len = max(len(name), max_len)
        for (name, one_liner) in outputs:
            app.stdout.write('  %s  %s\n' % (name.ljust(max_len), one_liner))
        sys.exit(0)


class NSXAdminShell(app.App):
    def __init__(self):
        super(NSXAdminShell, self).__init__(
            description='Command-line interface to'
                        ' manage VMware-NSX deployments',
            version=VERSION,
            command_manager=commandmanager.CommandManager('nsxadmin.cli')
            )
        self.commands = COMMANDS
        for k, v in self.commands[apiversion].items():
            self.command_manager.add_command(k, v)

        # Pop the 'complete' to correct the outputs of 'neutron help'.
        self.command_manager.commands.pop('complete')

    def initialize_app(self, argv):
        LOG.debug('initialize_app')
        init_logging()
        init_cfg()
        init_registry()

    def prepare_to_run_command(self, cmd):
        self.LOG.debug('prepare_to_run_command %s', cmd.__class__.__name__)
        registry.notify(cfg.CONF.resource, cfg.CONF.operation, "admin")

#    def build_option_parser(self, description, version):
#        return cfg.CONF._oparser

    def delete_up(self, cmd, result, err):
        self.LOG.debug('delete_up %s', cmd.__class__.__name__)
        if err:
            self.LOG.debug('got an error: %s', err)


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
    cfg.CONF.register_cli_opts(cli_opts)
    register_nsx_opts()
    register_neutron_opts()
    cfg.CONF(args=sys.argv[1:],
             default_config_files=[cfg.CONF.neutron_conf,
                                   cfg.CONF.nsx_conf])

    LOG.info("Config initialized")


def init_logging():
    logging.register_options(cfg.CONF)
    logging.set_defaults()
    logging.setup(cfg.CONF, PROGRAM, VERSION)


def init_registry():
    registry.subscribe(sg.neutron_delete_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.NEUTRON_CLEAN)
    registry.subscribe(sg.neutron_list_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.NEUTRON_LIST)
    registry.subscribe(sg.nsx_list_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.NSX_LIST)
    registry.subscribe(sg.nsx_delete_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.NSX_CLEAN)
    registry.subscribe(sg.neutron_list_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.LIST)
    registry.subscribe(sg.nsx_list_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.LIST)
    registry.subscribe(sg.neutron_delete_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.CLEAN)
    registry.subscribe(sg.nsx_delete_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.CLEAN)
    LOG.info("Callbacks Subscribed")


def main(argv=sys.argv[1:]):
    nsxadmin = NSXAdminShell()
    return nsxadmin.run(argv)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
