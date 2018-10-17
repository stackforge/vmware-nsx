# Copyright 2018 VMware, Inc.  All rights reserved.
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

from neutron.db import models_v2
from neutron_lib.callbacks import registry
from neutron_lib import context

from vmware_nsx.shell.admin.plugins.common import constants
from vmware_nsx.shell.admin.plugins.common import utils as admin_utils
import vmware_nsx.shell.resources as shell

#TODO(asarfaty): once firewall_db_v1 is deleted, use those local copies of the
# DB structures below
from neutron_fwaas.db.firewall import firewall_db as firewall_db_v1
from neutron_fwaas.db.firewall import firewall_router_insertion_db as rtr_v1

LOG = logging.getLogger(__name__)

# The FWaaS v1 DB models are copied here, as they are deleted from the
# neutron-fwaas project
# import sqlalchemy as sa
# from neutron_lib.db import model_base
# class FirewallRule(model_base.BASEV2, model_base.HasId,
#                    model_base.HasProject):
#     __tablename__ = 'firewall_rules'
#     __table_args__ = ({'mysql_collate': 'utf8_bin'})
#     name = sa.Column(sa.String(255))
#     description = sa.Column(sa.String(1024))
#     firewall_policy_id = sa.Column(sa.String(36),
#                                    sa.ForeignKey('firewall_policies.id'),
#                                    nullable=True)
#     shared = sa.Column(sa.Boolean)
#     protocol = sa.Column(sa.String(40))
#     ip_version = sa.Column(sa.Integer, nullable=False)
#     source_ip_address = sa.Column(sa.String(46))
#     destination_ip_address = sa.Column(sa.String(46))
#     source_port_range_min = sa.Column(sa.Integer)
#     source_port_range_max = sa.Column(sa.Integer)
#     destination_port_range_min = sa.Column(sa.Integer)
#     destination_port_range_max = sa.Column(sa.Integer)
#     action = sa.Column(sa.Enum('allow', 'deny', 'reject',
#                                name='firewallrules_action'))
#     enabled = sa.Column(sa.Boolean)
#     position = sa.Column(sa.Integer)


# class Firewall(model_base.BASEV2, model_base.HasId, model_base.HasProject):
#     __tablename__ = 'firewalls'
#     __table_args__ = ({'mysql_collate': 'utf8_bin'})
#     name = sa.Column(sa.String(255))
#     description = sa.Column(sa.String(1024))
#     shared = sa.Column(sa.Boolean)
#     admin_state_up = sa.Column(sa.Boolean)
#     status = sa.Column(sa.String(16))
#     firewall_policy_id = sa.Column(sa.String(36),
#                                    sa.ForeignKey('firewall_policies.id'),
#                                    nullable=True)


# class FirewallPolicy(model_base.BASEV2, model_base.HasId,
#                      model_base.HasProject):
#     __tablename__ = 'firewall_policies'
#     __table_args__ = ({'mysql_collate': 'utf8_bin'})
#     name = sa.Column(sa.String(255))
#     description = sa.Column(sa.String(1024))
#     shared = sa.Column(sa.Boolean)
#     audited = sa.Column(sa.Boolean)


# class FirewallRouterAssociation(model_base.BASEV2):
#     __tablename__ = 'firewall_router_associations'
#     fw_id = sa.Column(sa.String(36),
#         sa.ForeignKey('firewalls.id', ondelete="CASCADE"),
#         primary_key=True)
#     router_id = sa.Column(sa.String(36),
#         sa.ForeignKey('routers.id', ondelete="CASCADE"),
#         primary_key=True)


@admin_utils.output_header
def migrate_fwaas_v1_to_v2(resource, event, trigger, **kwargs):
    try:
        from neutron_fwaas.db.firewall.v2 import firewall_db_v2
    except ImportError:
        # FWaaS project not found - migration not supported
        LOG.error("neutron-fwaas was not found")
        return

    db_session = context.get_admin_context().session
    # the entire migration process will be done under the same transaction to
    # allow full rollback in case of error
    with db_session.begin(subtransactions=True):
        # Read all V1 policies
        v1_policies = db_session.query(firewall_db_v1.FirewallPolicy).all()

        for v1_pol in v1_policies:
            LOG.info("Migrating FWaaS V1 policy %s", v1_pol.id)
            # read the rules of this policy
            v1_rules = db_session.query(firewall_db_v1.FirewallRule).filter_by(
                firewall_policy_id=v1_pol.id).all()
            # Create the V2 policy
            v2_pol = firewall_db_v2.FirewallPolicy(
                id=v1_pol.id,
                tenant_id=v1_pol.tenant_id,
                name=v1_pol.name,
                description=v1_pol.description,
                shared=v1_pol.shared,
                audited=v1_pol.audited,
                rule_count=len(v1_rules))
            db_session.add(v2_pol)

            # Add the rules and associate them with the policy
            for v1_rule in v1_rules:
                LOG.info("Migrating FWaaS V1 rule %s", v1_rule.id)
                v2_rule = firewall_db_v2.FirewallRuleV2(
                    id=v1_rule.id,
                    name=v1_rule.name,
                    description=v1_rule.description,
                    tenant_id=v1_rule.tenant_id,
                    shared=v1_rule.shared,
                    protocol=v1_rule.protocol,
                    ip_version=v1_rule.ip_version,
                    source_ip_address=v1_rule.source_ip_address,
                    destination_ip_address=v1_rule.destination_ip_address,
                    source_port_range_min=v1_rule.source_port_range_min,
                    source_port_range_max=v1_rule.source_port_range_max,
                    destination_port_range_min=(
                        v1_rule.destination_port_range_min),
                    destination_port_range_max=(
                        v1_rule.destination_port_range_max),
                    action=v1_rule.action,
                    enabled=v1_rule.enabled)
                db_session.add(v2_rule)
                v2_link = firewall_db_v2.FirewallPolicyRuleAssociation(
                    firewall_policy_id=v1_pol.id,
                    firewall_rule_id=v1_rule.id,
                    position=v1_rule.position)
                db_session.add(v2_link)

        # Read all V1 firewalls
        v1_fws = db_session.query(firewall_db_v1.Firewall).all()
        for v1_fw in v1_fws:
            LOG.info("Migrating FWaaS V1 firewall %s", v1_fw.id)
            # create the V2 firewall group
            v2_fw_group = firewall_db_v2.FirewallGroup(
                id=v1_fw.id,
                name=v1_fw.name,
                description=v1_fw.description,
                tenant_id=v1_fw.tenant_id,
                shared=v1_fw.shared,
                admin_state_up=v1_fw.admin_state_up,
                status=v1_fw.status,
                ingress_firewall_policy_id=v1_fw.firewall_policy_id,
                egress_firewall_policy_id=v1_fw.firewall_policy_id)
            db_session.add(v2_fw_group)

            # for every router in the V1 Firewall router association, add all
            # its interface ports to the V2 FirewallGroupPortAssociation
            v1_routers = db_session.query(
                rtr_v1.FirewallRouterAssociation).filter_by(
                fw_id=v1_fw.id).all()
            for v1_router in v1_routers:
                rtr_id = v1_router.router_id
                LOG.info("Migrating FWaaS V1 %s router %s", v1_fw.id, rtr_id)
                if_ports = db_session.query(models_v2.Port).filter_by(
                    device_id=rtr_id,
                    device_owner="network:router_interface").all()
                for port in if_ports:
                    fw_port = firewall_db_v2.FirewallGroupPortAssociation(
                        firewall_group_id=v2_fw_group.id,
                        port_id=port.id)
                    db_session.add(fw_port)


registry.subscribe(migrate_fwaas_v1_to_v2,
                   constants.FWAAS,
                   shell.Operations.MIGRATE_V1_TO_V2.value)
