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

from neutron.common import neutron_utils
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron_lib.api import validators

from vmware_nsx.extensions import securitygrouplogging as sg_logging
from vmware_nsx.extensions import strictsecuritygroup as strict_sg


class NsxExtendedSecurityGroupProperties(model_base.BASEV2):
    __tablename__ = 'nsx_extended_security_group_properties'

    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('securitygroups.id',
                                                ondelete="CASCADE"),
                                  primary_key=True)
    logging = sa.Column(sa.Boolean, default=False, nullable=False)
    strict = sa.Column(sa.Boolean, default=False, nullable=False)
    security_group = orm.relationship(
        securitygroups_db.SecurityGroup,
        backref=orm.backref('ext_properties', lazy='joined',
                            uselist=False, cascade='delete'))


class ExtendedSecurityGroupPropertiesMixin(object):

    def _process_security_group_properties_create(self, context,
                                                  sg_res, sg_req, default_sg):
        # TODO(roeyc): Add locking to ensure only one strict sg per tenant.
        self._validate_security_group_properties_create(
            context, sg_req, default_sg)
        with context.session.begin(subtransactions=True):
            properties = NsxExtendedSecurityGroupProperties(
                security_group_id=sg_res['id'],
                logging=sg_req.get(sg_logging.LOGGING, False),
                strict=sg_req.get(strict_sg.STRICT, False))
            context.session.add(properties)
        sg_res[sg_logging.LOGGING] = sg_req.get(sg_logging.LOGGING, False)
        sg_res[strict_sg.STRICT] = sg_req.get(strict_sg.STRICT, False)

    def _get_security_group_properties(self, context, security_group_id):
        return context.session.query(
            NsxExtendedSecurityGroupProperties).filter_by(
                security_group_id=security_group_id).one()

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

    def _is_security_group_strict(self, context, security_group_id):
        sg_prop = self._get_security_group_properties(context,
                                                      security_group_id)
        return sg_prop.strict

    def _check_strict_security_group_exists(self, context,
                                            security_group_id, tenant_id):
        sg = self.get_security_group(context, security_group_id)
        return sg[strict_sg.STRICT] and sg['tenant_id'] == tenant_id

    def _get_tenant_strict_security_group(self, context, tenant_id):
        try:
            return context.session.query(
                NsxExtendedSecurityGroupProperties.security_group_id
            ).filter_by(tenant_id=tenant_id, strict=True).one()
        except exc.NoResultFound:
            pass

    def _validate_security_group_properties_create(self, context,
                                                   security_group, default_sg):
        self._validate_strict_security_group_create(context, security_group,
                                                    default_sg)

    def _validate_strict_security_group_create(self, context, security_group,
                                               default_sg):
        if not security_group.get(strict_sg.STRICT, False):
            return

        if default_sg:
            raise Exception("Default security-group cannot be strict.")

        tenant_id = security_group['tenant_id']
        ssg = self._get_tenant_strict_security_group(context, tenant_id)
        if ssg:
            raise Exception("Strict Security-group already exists"
                            "(%(ssg)s) for tenant %(tenant_id)s.")

    def _get_strict_security_groups_on_port(self, context, port):
        port = port['port']
        tenant_id = port['tenant_id']
        def_ssg = self._get_tenant_strict_security_group(context, tenant_id)
        requested_strict_sgs = port.get(strict_sg.STRICT_SECURITY_GROUPS)

        if port.get('device_owner') and neutron_utils.is_port_trusted(port):
            return

        if not validators.is_attr_set(requested_strict_sgs):
            return [def_ssg] if def_ssg else []

        if not context.is_admin:
            raise Exception("Only users with admin privileges may specify "
                            "strict security-groups on port.")

        if len(requested_strict_sgs) > strict_sg.NUM_STRICT_SGS_ON_PORT:
            raise Exception("Can apply only %d strict security-groups "
                            "on a port.", strict_sg.NUM_STRICT_SGS_ON_PORT)

        for ssg in requested_strict_sgs:
            self._check_strict_security_group_exists(context, ssg, tenant_id)
        for sg in port.get(ext_sg.SECURITYGROUPS, []):
            if self._is_security_group_strict(context, sg):
                raise Exception("The security-group %s is not strict. Only "
                                "strict security-groups can listed "
                                "for port's 'strict_security_groups' "
                                "property.", sg)
        return requested_strict_sgs

    def _process_port_create_strict_security_group(self, context, port,
                                                   strict_security_group_ids):
        if validators.is_attr_set(strict_security_group_ids):
            for security_group_id in strict_security_group_ids:
                self._create_port_security_group_binding(context, port['id'],
                                                         security_group_id)
        port[strict_sg.STRICT_SECURITY_GROUPS] = (
            strict_security_group_ids or [])

    def _process_port_update_strict_security_group(self, context, port,
                                                   original_port,
                                                   updated_port):
        strict_sg_specified = validators.is_attr_set(
            port.get(strict_sg.STRICT_SECURITY_GROUPS))

        if strict_sg_specified:
            strict_secgroups = self._get_strict_security_groups_on_port(
                context, port)
        else:
            strict_secgroups = original_port[strict_sg.STRICT_SECURITY_GROUPS]
        updated_port[strict_sg.STRICT_SECURITY_GROUPS] = strict_secgroups

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        ext_sg.SECURITYGROUPS, ['_extend_security_group_with_properties'])

    def _extend_security_group_with_properties(self, sg_res, sg_db):
        if sg_db.ext_properties:
            sg_res[sg_logging.LOGGING] = sg_db.ext_properties.logging
