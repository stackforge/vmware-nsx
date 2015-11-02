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

from admin.plugins.common import constants
from admin.plugins.common import formatters
from admin.plugins.common.utils import output_header
from admin.plugins.common.utils import query_yes_no
import admin.plugins.nsxv.resources.utils as utils
from admin.shell import Operations

from neutron.callbacks import registry
from neutron.i18n import _LI

from vmware_nsx.db import nsxv_db

LOG = logging.getLogger(__name__)


def get_nsxv_edges():
    nsxv = utils.get_nsxv_client()
    edges = nsxv.get_edges()[1]
    return edges['edgePage'].get('data', [])


@output_header
def nsx_list_edges(resource, event, trigger, **kwargs):
    """List edges from NSXv backend"""
    edges = get_nsxv_edges()
    LOG.info(formatters.output_formatter(constants.EDGES, edges,
                                         ['id']))


def get_router_edge_bindings():
    edgeapi = utils.NeutronDbClient()
    return nsxv_db.get_nsxv_router_bindings(edgeapi.context)


@output_header
def neutron_list_router_edge_bindings(resource, event, trigger, **kwargs):
    """List NSXv edges from Neutron DB"""
    edges = get_router_edge_bindings()
    LOG.info(formatters.output_formatter(constants.EDGES, edges,
                                         ['edge_id', 'router_id']))


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
    """List orphaned Edges on NSXv.

    Orphaned edges are NSXv edges that exist on NSXv backend but
    don't have a corresponding binding in Neutron DB
    """
    orphaned_edges = get_orphaned_edges()
    LOG.info(orphaned_edges)


@output_header
def nsx_delete_orphaned_edges(resource, event, trigger, **kwargs):
    """Delete orphaned edges from NSXv backend"""
    orphaned_edges = get_orphaned_edges()
    LOG.info(_LI("Before delete; Orphaned Edges: %s"), orphaned_edges)

    if not kwargs['force']:
        if len(orphaned_edges):
            user_confirm = query_yes_no("Do you want to delete "
                                        "orphaned edges", default="no")
            if not user_confirm:
                LOG.info(_LI("NSXv Edge deletion aborted by user"))
                return

    nsxv = utils.get_nsxv_client()
    for edge in orphaned_edges:
        LOG.info(_LI("Deleting edge: %s"), edge)
        nsxv.delete_edge(edge)

    LOG.info(_LI("After delete; Orphaned Edges: %s"), get_orphaned_edges())


registry.subscribe(nsx_list_edges,
                   constants.EDGES,
                   Operations.LIST.value)
registry.subscribe(neutron_list_router_edge_bindings,
                   constants.EDGES,
                   Operations.LIST.value)
registry.subscribe(nsx_list_orphaned_edges,
                   constants.EDGES,
                   Operations.LIST.value)
registry.subscribe(nsx_delete_orphaned_edges,
                   constants.EDGES,
                   Operations.CLEAN.value)
