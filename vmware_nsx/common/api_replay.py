# All Rights Reserved.
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


from neutron.api.v2 import attributes

from oslo_config import cfg
from oslo_log import log

from vmware_nsx._i18n import _LW

LOG = log.getLogger(__name__)


class ApiReplay(object):

    def __init__(self):
        self._configure_api_replay_mode()

    def _configure_api_replay_mode(self):
        """
            Setups server to be in replay mode which allows the caller to
            specifiy the id for specific resouces.
        """
        LOG.warning(_LW("In api_replay_mode! This should only be enabled "
                        "if you are performing a migration!"))

        # allows the caller to specify the id for port resources
        attributes.RESOURCE_ATTRIBUTE_MAP['ports']['id']['allow_post'] = True
