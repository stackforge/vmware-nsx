# Copyright 2016 VMware, Inc.
#
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
from oslo_log import log as logging

from neutron.extensions import portbindings
from neutron.services.trunk import constants as trunk_consts
from neutron.services.trunk.drivers import base

LOG = logging.getLogger(__name__)

NAME = 'vmware_nsx.plugin.NsxV3Plugin'
SUPPORTED_INTERFACES = (
    portbindings.VIF_TYPE_OVS,
)
SUPPORTED_SEGMENTATION_TYPES = (
    trunk_consts.VLAN,
)


class NsxV3TrunkDriver(base.DriverBase):
    """Driver to implement neutron's trunk extensions."""

    @property
    def is_loaded(self):
        return NAME == cfg.CONF.core_plugin

    @classmethod
    def create(cls):
        return cls(NAME, SUPPORTED_INTERFACES, SUPPORTED_SEGMENTATION_TYPES,
                   agent_type=None, can_trunk_bound_port=False)


def register():
    NsxV3TrunkDriver.create()
    LOG.debug("VMware NSXv3 trunk driver initialized.")
