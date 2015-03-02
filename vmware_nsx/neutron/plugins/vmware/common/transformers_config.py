# Copyright 2015 OpenStack Foundation
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


transformer_opts = [
    cfg.StrOpt('nsx_user',
               default='admin',
               deprecated_name='nvp_user',
               help=_('User name for NSX controllers in this cluster')),
    cfg.StrOpt('nsx_password',
               default='default',
               secret=True,
               help=_('Password for NSX controllers in this cluster')),
    cfg.ListOpt('nsx_controllers',
                help=_("Lists the NSX controllers in this cluster")),
    cfg.StrOpt('default_transport_zone_uuid',
               help=_("The default transport_zone_uuid to use ."))]

cfg.CONF.register_opts(transformer_opts, group="transformers")
