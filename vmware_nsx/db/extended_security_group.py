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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.common import utils as n_utils
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.api import validators

from vmware_nsx.extensions import providersecuritygroup as provider_sg
from vmware_nsx.extensions import securitygrouplogging as sg_logging


class NsxExtendedSecurityGroupProperties(model_base.BASEV2):
    __tablename__ = 'nsx_extended_security_group_properties'

    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('securitygroups.id',
                                                ondelete="CASCADE"),
                                  primary_key=True)
    logging = sa.Column(sa.Boolean, default=False, nullable=False)
    provider = sa.Column(sa.Boolean, default=False, nullable=False)
    security_group = orm.relationship(
        securitygroups_db.SecurityGroup,
        backref=orm.backref('ext_properties', lazy='joined',
                            uselist=False, cascade='delete'))


class ExtendedSecurityGroupPropertiesMixin(object):

    # NOTE(arosen): here we add a relationship so that from the ports model
    # it provides us access to SecurityGroupPortBinding and
    # NsxExtendedSecurityGroupProperties
    securitygroups_db.SecurityGroupPortBinding.extended_grp = orm.relationship(
        'NsxExtendedSecurityGroupProperties',
        foreign_keys="SecurityGroupPortBinding.security_group_id",
        primaryjoin=("NsxExtendedSecurityGroupProperties.security_group_id"
                     "==SecurityGroupPortBinding.security_group_id"))

    def _process_security_group_properties_create(self, context,
                                                  sg_res, sg_req,
                                                  default_sg=False):
        # TODO(roeyc): Add locking to ensure only one provider sg per tenant.
        self._validate_security_group_properties_create(
            context, sg_req, default_sg)
        with context.session.begin(subtransactions=True):
            properties = NsxExtendedSecurityGroupProperties(
                security_group_id=sg_res['id'],
                logging=sg_req.get(sg_logging.LOGGING, False),
                provider=sg_req.get(provider_sg.PROVIDER, False))
            context.session.add(properties)
        sg_res[sg_logging.LOGGING] = sg_req.get(sg_logging.LOGGING, False)
        sg_res[provider_sg.PROVIDER] = sg_req.get(provider_sg.PROVIDER, False)

    def _get_security_group_properties(self, context, security_group_id):
        with context.session.begin(subtransactions=True):
            prop = context.session.query(
                NsxExtendedSecurityGroupProperties).filter_by(
                    security_group_id=security_group_id).one()
        return prop

    def _process_security_group_properties_update(self, context,
                                                  sg_res, sg_req):
        if (sg_logging.LOGGING in sg_req
                and (sg_req[sg_logging.LOGGING] !=
                     sg_res.get(sg_logging.LOGGING, False))):
            prop = self._get_security_group_properties(context, sg_res['id'])
            with context.session.begin(subtransactions=True):
                prop.update({sg_logging.LOGGING: sg_req[sg_logging.LOGGING]})
            sg_res[sg_logging.LOGGING] = sg_req[sg_logging.LOGGING]

    def _is_security_group_logged(self, context, security_group_id):
        prop = self._get_security_group_properties(context, security_group_id)
        return prop.logging

    def _is_provider_security_group(self, context, security_group_id):
        sg_prop = self._get_security_group_properties(context,
                                                      security_group_id)
        return sg_prop.provider

    def _check_provider_security_group_exists(self, context,
                                              security_group_id, tenant_id):
        sg = self.get_security_group(context, security_group_id)
        return sg[provider_sg.PROVIDER] and sg['tenant_id'] == tenant_id

    def _get_tenant_provider_security_group(self, context, tenant_id):
        try:
            return context.session.query(
                NsxExtendedSecurityGroupProperties.security_group_id
            ).join(securitygroups_db.SecurityGroup).filter(
                securitygroups_db.SecurityGroup.tenant_id == tenant_id,
                NsxExtendedSecurityGroupProperties.provider == sa.true()).one()
        except exc.NoResultFound:
            pass

    def _validate_security_group_properties_create(self, context,
                                                   security_group, default_sg):
        self._validate_provider_security_group_create(context, security_group,
                                                      default_sg)

    def _validate_provider_security_group_create(self, context, security_group,
                                                 default_sg):
        if not security_group.get(provider_sg.PROVIDER, False):
            return

        if default_sg:
            raise Exception("Default security-group cannot be provider.")

        tenant_id = security_group['tenant_id']
        ssg = self._get_tenant_provider_security_group(context, tenant_id)
        if ssg:
            raise Exception("Provider Security-group already exists"
                            "(%s) for tenant %s." % (ssg, tenant_id))

    def _get_provider_security_groups_on_port(self, context, port):
        port = port['port']
        tenant_id = port['tenant_id']
        def_ssg = self._get_tenant_provider_security_group(context, tenant_id)
        requested_provider_sgs = port.get(provider_sg.PROVIDER_SECURITYGROUPS)

        if port.get('device_owner') and n_utils.is_port_trusted(port):
            return

        if not validators.is_attr_set(requested_provider_sgs):
            return [def_ssg] if def_ssg else []

        if len(requested_provider_sgs) > provider_sg.NUM_PROVIDER_SGS_ON_PORT:
            raise Exception("Can apply only %d provider security-groups "
                            "on a port.", provider_sg.NUM_PROVIDER_SGS_ON_PORT)

        for ssg in requested_provider_sgs:
            self._check_provider_security_group_exists(context, ssg, tenant_id)
        for sg in port.get(ext_sg.SECURITYGROUPS, []):
            if self._is_provider_security_group(context, sg):
                raise Exception("The security-group %s is not provider. Only "
                                "provider security-groups can listed "
                                "for port's 'provider_security_groups' "
                                "property.", sg)
        return requested_provider_sgs

    def _process_port_create_provider_security_group(self, context, port,
                                                     security_group_ids):
        if validators.is_attr_set(security_group_ids):
            for security_group_id in security_group_ids:
                self._create_port_security_group_binding(context, port['id'],
                                                         security_group_id)
        port[provider_sg.PROVIDER_SECURITYGROUPS] = security_group_ids or []

    def _process_port_update_provider_security_group(self, context, port,
                                                     original_port,
                                                     updated_port):
        p = port['port']
        provider_sg_specified = validators.is_attr_set(
            p.get(provider_sg.PROVIDER_SECURITYGROUPS))
        provider_sg_changed = provider_sg_specified and (
            set(original_port[provider_sg.PROVIDER_SECURITYGROUPS]) !=
            set(port.get[provider_sg.PROVIDER_SECURITYGROUPS]))
        # TBD(roeyc): Indication for whether sg port bindings were removed.
        sg_changed = (
            set(original_port[ext_sg.SECURITYGROUPS]) !=
            set(updated_port.get(ext_sg.SECURITYGROUPS, [])))

        if provider_sg_changed:
            updated_port[provider_sg.PROVIDER_SECURITYGROUPS] = (
                self._get_provider_security_groups_on_port(context, port))
        else:
            updated_port[provider_sg.PROVIDER_SECURITYGROUPS] = (
                original_port[provider_sg.PROVIDER_SECURITYGROUPS])
        if provider_sg_changed or sg_changed:
            if not sg_changed:
                query = context.session.query(ext_sg.SecurityGroupPortBinding)
                for sg in original_port[provider_sg.PROVIDER_SECURITYGROUPS]:
                    binding = query.filter_by(
                        port_id=p['id'], security_group_id=sg).one()
                    context.session.delete(binding)
            self._process_port_create_provider_security_group(
                context, updated_port,
                updated_port[provider_sg.PROVIDER_SECURITYGROUPS])

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        ext_sg.SECURITYGROUPS, ['_extend_security_group_with_properties'])

    def _extend_security_group_with_properties(self, sg_res, sg_db):
        if sg_db.ext_properties:
            sg_res[sg_logging.LOGGING] = sg_db.ext_properties.logging
            sg_res[provider_sg.PROVIDER] = sg_db.ext_properties.provider

    def _extend_port_dict_provider_security_group(self, port_res, port_db):
        # NOTE(arosen): this method overrides the one in the base
        # security group db class. The reason this is needed is because
        # we are storing provider security groups in the same security
        # groups db model. We need to do this here to remove the provider
        # security groups and put those on the port resource as their
        # own attribute.

        # Security group bindings will be retrieved from the SQLAlchemy
        # model. As they're loaded eagerly with ports because of the
        # joined load they will not cause an extra query.

        provider_groups = []
        not_provider_groups = []
        for sec_group_mapping in port_db.security_groups:
            if sec_group_mapping.extended_grp.provider is True:
                provider_groups.append(sec_group_mapping['security_group_id'])
            else:
                not_provider_groups.append(
                    sec_group_mapping['security_group_id'])

        port_res[ext_sg.SECURITYGROUPS] = not_provider_groups
        port_res[provider_sg.PROVIDER_SECURITYGROUPS] = provider_groups
        return port_res

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.PORTS, ['_extend_port_dict_provider_security_group'])
