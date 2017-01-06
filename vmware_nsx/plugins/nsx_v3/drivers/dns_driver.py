# Copyright 2017 VMware, Inc.
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

from neutron.plugins.ml2.extensions import dns_integration as ml2_dns

LOG = logging.getLogger(__name__)


class DNSExtensionDriverNSXv3(ml2_dns.DNSExtensionDriver):

    def _get_dns_domain(self):
        if cfg.CONF.nsx_v3.dns_domain:
            dns_domain = cfg.CONF.nsx_v3.dns_domain
        elif cfg.CONF.dns_domain:
            dns_domain = cfg.CONF.dns_domain
        else:
            return ''
        if dns_domain.endswith('.'):
            return dns_domain
        return '%s.' % dns_domain
