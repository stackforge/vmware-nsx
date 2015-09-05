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

"""
Purpose of this script is to build a framework which can be leveraged
to build utilities to help the on-field ops in system debugging.

We support the following functions for now:
* Be able to read the database and configuration files.
* Be able to access the backend via API
* Compare data from different sources and decide next course of
  action.

TODO: Write formatters wrapper
TODO: Ports/Switches NSX
TODO: Add neutron callbacks too
"""

import sys
import requests

from oslo_config import cfg
from oslo_log import log as logging

from neutron.callbacks import registry

from vmware_nsx.common import config as nsx_config
from neutron.common import config as neutron_config

from vmware_nsx.nsxlib.v3 import dfw_api as firewall

from neutron.db import api as db_api
from neutron.db import securitygroups_db as sg_db


requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)

cli_opts = [
            cfg.StrOpt('neutron_conf',
                       default='/etc/neutron/neutron.conf',
                       help='Neutron configuration file'),
            cfg.StrOpt('nsx_conf',
                       default='/etc/neutron/plugins/vmware/nsx.ini',
                       help='NSX configuration file'),
            cfg.StrOpt('resource',
                       help='Network resource to manage'),
            cfg.StrOpt('operation',
                       help='Operation to perform')
]


class Constants(object):
    PROJECT = 'NSX'
    PROGRAM = 'Admin Utility'
    VERSION = '0.1'
    USAGE = 'Admin Utility to manage NSX deployments.'


class Operations(object):
    LIST = 'list'
    SYNC = 'sync'
    CLEAN = 'clean'


class Resources(object):
    EDGES = 'edges'
    PORTS = 'ports'
    LSWITCHES = 'logical-switches'
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


def init():
    init_logging()
    init_cfg()
    init_registry()


def get_resource(resource, event, trigger, **kwargs):
    print('Get %s called by trigger: %s %s' (resource, trigger, event))


def cleanup_security_groups(resource, event, trigger, **kwargs):
    LOG.info('Cleaning up security groups')
    sections = firewall.list_sections()
    for section in sections[:-1]:
        LOG.info(("Deleting firewall section %(display_name)s, "
            "section id %(id)s"), {'display_name': section['display_name'],
                'id': section['id']})
        firewall.delete_section(section['id'])

    nsgroups = firewall.list_nsgroups()
    for nsgroup in nsgroups:
        LOG.info(("Deleting ns-group %(display_name)s, "
                "ns-group id %(id)s"),
                {'display_name': nsgroup['display_name'], 'id': nsgroup['id']})
        firewall.delete_nsgroup(nsgroup['id'])


def neutron_get_security_groups(resource, event, trigger, **kwargs):
    session = db_api.get_session()
    with session.begin():
        query = session.query(sg_db.SecurityGroup)
        for item in query:
            LOG.info(("Security group name: %(name)s id: %(id)s"),
                    {'name': item['name'], 'id': item['id']})


def neutron_delete_security_groups(resource, event, trigger, **kwargs):
    session = db_api.get_session()
    with session.begin():
        query = session.query(sg_db.SecurityGroup)
        for item in query:
            LOG.info(("Delete security group name: %(name)s id: %(id)s"),
                    {'name': item['name'], 'id': item['id']})
            session.delete(item)


def list_security_groups(resource, event, trigger, **kwargs):
    LOG.info('List security groups')
    sections = firewall.list_sections()
    for section in sections:
        LOG.info(("Firewall section: %(display_name)s, ID: %(id)s"),
                 {'display_name': section['display_name'],
                  'id': section['id']})

    nsgroups = firewall.list_nsgroups()
    for nsgroup in nsgroups:
        LOG.info(("ns-group: %(display_name)s, "
                  "ns-group id: %(id)s"),
                {'display_name': nsgroup['display_name'], 'id': nsgroup['id']})


def init_registry():
    registry.subscribe(neutron_delete_security_groups,
                       Resources.SECURITY_GROUPS,
                       Operations.CLEAN)
    registry.subscribe(neutron_get_security_groups, Resources.SECURITY_GROUPS,
                       Operations.LIST)
    LOG.info("Callbacks Subscribed")


if __name__ == "__main__":
    init()
    registry.notify(cfg.CONF.resource, cfg.CONF.operation, "admin")
