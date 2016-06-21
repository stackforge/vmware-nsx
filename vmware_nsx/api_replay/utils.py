# Copyright 2016 VMware, Inc.
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


from neutron.plugins.common import utils
from oslo_config import cfg
from oslo_utils import uuidutils


def _fixup_res_dict(context, attr_name, res_dict, check_allow_post=True):
    # This method is called before the neutron implementaion of it and
    # is only done to insert a uuid into the id field if one is not
    # found ONLY if running in api_replay_mode.
    if cfg.CONF.api_replay_mode and 'id' not in res_dict:
        res_dict['id'] = uuidutils.generate_uuid()
    return utils._fixup_res_dict(context, attr_name, res_dict,
                                 check_allow_post)
