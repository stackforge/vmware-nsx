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

# Default conf file locations
NEUTRON_CONF = '/etc/neutron/neutron.conf'
NSX_INI = '/etc/neutron/plugins/vmware/nsx.ini'

# NSX Plugin Constants
NSXV3_PLUGIN = 'vmware_nsx.plugin.NsxV3Plugin'
NSXV_PLUGIN = 'vmware_nsx.plugin.NsxVPlugin'

# Common Resource Constants
NETWORKS = 'networks'
ROUTERS = 'routers'
DHCP_BINDING = 'dhcp-binding'

# NSXV3 Resource Constants
FIREWALL_SECTIONS = 'firewall-sections'
FIREWALL_NSX_GROUPS = 'nsx-security-groups'
SECURITY_GROUPS = 'security-groups'
PORTS = 'ports'
METADATA_PROXY = 'metadata-proxy'
ORPHANED_DHCP_SERVERS = 'orphaned-dhcp-servers'
CERTIFICATE = 'certificate'

# NSXV Resource Constants
EDGES = 'edges'
SPOOFGUARD_POLICY = 'spoofguard-policy'
BACKUP_EDGES = 'backup-edges'
ORPHANED_EDGES = 'orphaned-edges'
ORPHANED_BINDINGS = 'orphaned-bindings'
MISSING_EDGES = 'missing-edges'
METADATA = 'metadata'
MISSING_NETWORKS = 'missing-networks'
ORPHANED_NETWORKS = 'orphaned-networks'
LBAAS = 'lbaas'
