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


import logging

from admin.shell import Operations
from admin.plugins.common import constants
from admin.plugins.common import formatters
from admin.plugins.common.utils import output_header

from oslo_config import cfg

from neutron import context as neutron_context
from neutron.callbacks import registry
from neutron.db import common_db_mixin as common_db
from vmware_nsx.db import nsxv_db
from vmware_nsx.plugins.nsx_v.vshield import vcns

LOG = logging.getLogger(__name__)

class EdgeApi(common_db.CommonDbMixin):
    def __init__(self):
        super(EdgeApi, self)
        self.context = neutron_context.get_admin_context()


def init_nsxv_client():
    return vcns.Vcns(
        address=cfg.CONF.nsxv.manager_uri,
        user=cfg.CONF.nsxv.user,
        password=cfg.CONF.nsxv.password,
        ca_file=cfg.CONF.nsxv.ca_file,
        insecure=cfg.CONF.nsxv.insecure)


def get_nsxv_edges():
    nsxv = init_nsxv_client()
    edges = nsxv.get_edges()[1]
    return edges['edgePage'].get('data', [])


@output_header
def nsx_list_edges(resource, event, trigger, **kwargs):
    """ List edges from NSXv backend """
    edges = get_nsxv_edges()
    LOG.info(formatters.output_formatter(
                 constants.EDGES, edges,
                 ['id']))


def get_router_edge_bindings():
    edgeapi = EdgeApi()
    return nsxv_db.get_nsxv_router_bindings(edgeapi.context)


@output_header
def neutron_list_router_edge_bindings(resource, event, trigger, **kwargs):
    """ List NSXv edges from Neutron DB """
    edges = get_router_edge_bindings()
    LOG.info(formatters.output_formatter(
                 constants.EDGES, edges, ['edge_id', 'router_id']))


def get_orphaned_edges():
    nsxv_edge_ids = set()
    for edge in get_nsxv_edges():
        nsxv_edge_ids.add(edge.get('id'))

    neutron_edge_bindings = set()
    for binding in get_router_edge_bindings():
        neutron_edge_bindings.add(binding.edge_id)

    return nsxv_edge_ids - neutron_edge_bindings


@output_header
def nsx_list_orphaned_edges(resource, event, trigger, **kwargs):
    """
    List orphaned Edges on NSXv. Orphaned edges are NSXv edges that exist
    on NSXv backend but don't have a corresponding binding in Neutron DB
    """
    orphaned_edges = get_orphaned_edges()
    LOG.info(orphaned_edges)


registry.subscribe(nsx_list_edges,
                   constants.EDGES,
                   Operations.LIST.value)
registry.subscribe(neutron_list_router_edge_bindings,
                   constants.EDGES,
                   Operations.LIST.value)
registry.subscribe(nsx_list_orphaned_edges,
                   constants.EDGES,
                   Operations.LIST.value)
