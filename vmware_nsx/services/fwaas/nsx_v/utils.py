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

from oslo_log import log as logging

from neutron_fwaas.db.firewall import firewall_db  # noqa
from neutron_fwaas.db.firewall import firewall_router_insertion_db \
    as fw_r_ins_db

from vmware_nsx._i18n import _LE

LOG = logging.getLogger(__name__)


# TODO(asarfaty) add this api to fwaas firewall-router-insertion-db
def get_router_firewall_id(session, router_id):
    LOG.error(_LE("DEBUG ADIT get_router_firewall_id router %s"), router_id)
    entry = session.query(fw_r_ins_db.FirewallRouterAssociation).filter_by(
        router_id=router_id).first()
    if entry:
        LOG.error(_LE("DEBUG ADIT fw %s"), entry.fw_id)
        return entry.fw_id


def get_fw_rules(context, fw_id):
    # DEBUG ADIT - not yet...
    LOG.error(_LE("DEBUG ADIT get_fw_rules fw %s"), fw_id)
    return []
