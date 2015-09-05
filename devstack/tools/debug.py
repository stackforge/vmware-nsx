#!/usr/bin/env python

"""
Purpose of this script is to build a framework which can be leveraged
to build utilities to help the on-field ops in system debugging.

We support the following functions for now:
* Be able to read the database and configuration files.
* Be able to access the backend via API
* Compare data from different sources and decide next course of
  action.
"""

import sys

from oslo_config import cfg
from oslo_log import log as logging

from neutron.callbacks import registry

from vmware_nsx.neutron.plugins.vmware.common import config as nsx_config
from neutron.common import config as neutron_config


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
    INFO = 'info'
    SYNC = 'sync'


class Resources(object):
    EDGES = 'edges'
    PORTS = 'ports'


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


def callback1(resource, event, trigger, **kwargs):
    print('Callback1 called by trigger: ', trigger)
    print('kwargs: ', kwargs)


def callback2(resource, event, trigger, **kwargs):
    print('Callback2 called by trigger: ', trigger)
    print('kwargs: ', kwargs)


def init_registry():
    registry.subscribe(callback1, Resources.PORTS, Operations.INFO)
    registry.subscribe(callback2, Resources.PORTS, Operations.INFO)
    LOG.info("Callbacks Subscribed")


if __name__ == "__main__":
    init()
    registry.notify(cfg.CONF.resource, cfg.CONF.operation, "admin")
