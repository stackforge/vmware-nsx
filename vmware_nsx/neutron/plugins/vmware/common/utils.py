# Copyright 2013 VMware, Inc.
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

import hashlib

from neutron.api.v2 import attributes
from neutron import version
from oslo_config import cfg
from oslo_log import log
import retrying
import six

LOG = log.getLogger(__name__)
MAX_DISPLAY_NAME_LEN = 40
NEUTRON_VERSION = version.version_info.release_string()


# Allowed network types for the NSX Plugin
class NetworkTypes:
    """Allowed provider network types for the NSX Plugin."""
    L3_EXT = 'l3_ext'
    STT = 'stt'
    GRE = 'gre'
    FLAT = 'flat'
    VLAN = 'vlan'
    BRIDGE = 'bridge'


# Allowed network types for the NSX-v Plugin
class NsxVNetworkTypes:
    """Allowed provider network types for the NSX-v Plugin."""
    FLAT = 'flat'
    VLAN = 'vlan'
    VXLAN = 'vxlan'
    PORTGROUP = 'portgroup'


# Allowed network types for the NSXv3 Plugin
class NsxV3NetworkTypes:
    """Allowed provider network types for the NSXv3 Plugin."""
    FLAT = 'flat'
    VLAN = 'vlan'
    VXLAN = 'vxlan'


def get_tags(**kwargs):
    tags = ([dict(tag=value, scope=key)
            for key, value in six.iteritems(kwargs)])
    tags.append({"tag": NEUTRON_VERSION, "scope": "quantum"})
    return sorted(tags, key=lambda x: x['tag'])


def device_id_to_vm_id(device_id, obfuscate=False):
    # device_id can be longer than 40 characters, for example
    # a device_id for a dhcp port is like the following:
    #
    # dhcp83b5fdeb-e3b4-5e18-ac5f-55161...80747326-47d7-46c2-a87a-cf6d5194877c
    #
    # To fit it into an NSX tag we need to hash it, however device_id
    # used for ports associated to VM's are small enough so let's skip the
    # hashing
    if len(device_id) > MAX_DISPLAY_NAME_LEN or obfuscate:
        return hashlib.sha1(device_id.encode()).hexdigest()
    else:
        return device_id or "N/A"


def check_and_truncate(display_name):
    if (attributes.is_attr_set(display_name) and
            len(display_name) > MAX_DISPLAY_NAME_LEN):
        LOG.debug("Specified name:'%s' exceeds maximum length. "
                  "It will be truncated on NSX", display_name)
        return display_name[:MAX_DISPLAY_NAME_LEN]
    return display_name or ''


def build_v3_tags_payload(logical_entity):
    """
    Construct the tags payload that will be pushed to NSX-v3
    Add os-tid:<tenant-id>, os-api-version:<neutron-api-version>,
        neutron-id:<resource-id>
    """
    return [{"scope": "neutron-id",
             "tag": logical_entity.get("id")},
            {"scope": "os-tid",
             "tag": logical_entity.get("tenant_id")},
            {"scope": "os-api-version",
             "tag": version.version_info.release_string()}]


def retry_upon_exception_nsxv3(exc, delay=500, max_delay=2000,
                               max_attempts=cfg.CONF.nsx_v3.retries):
    return retrying.retry(retry_on_exception=lambda e: isinstance(e, exc),
                          wait_exponential_multiplier=delay,
                          wait_exponential_max=max_delay,
                          stop_max_attempt_number=max_attempts)
