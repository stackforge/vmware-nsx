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

from cryptography import fernet
import hashlib
import logging

from oslo_config import cfg

from vmware_nsx._i18n import _LE
from vmware_nsx.db import db as nsx_db

LOG = logging.getLogger(__name__)
NSX_OPENSTACK_IDENTITY = "com.vmware.nsx.openstack"

# 32-byte base64-encoded secret for symmetric password encryption
# generated on init based on password provided in configuration
_SECRET = None


class DbCertificateStorageDriver(object):
    """Storage for certificate and private key in neutron DB"""
    def __init__(self, context):
        global _SECRET
        self._context = context
        if cfg.CONF.nsx_v3.nsx_client_cert_pk_password and not _SECRET:
            m = hashlib.md5()
            m.update(cfg.CONF.nsx_v3.nsx_client_cert_pk_password)
            _SECRET = m.hexdigest().encode('base64')

    def store_cert(self, purpose, certificate, private_key):
        # ecrypt private key
        if _SECRET:
            private_key = fernet.Fernet(_SECRET).encrypt(private_key)

        nsx_db.save_certificate(self._context.session, purpose,
                                certificate, private_key)

    def get_cert(self, purpose):
        cert, private_key = nsx_db.get_certificate(self._context.session,
                                                   purpose)
        if _SECRET and private_key:
            try:
                # Encrypted PK is stored in DB as string, while fernet expects
                # bytearray.
                private_key = fernet.Fernet(_SECRET).decrypt(
                        private_key.encode('ascii'))
            except fernet.InvalidToken:
                # unable to decrypt - probably due to change of password
                # cert and PK are useless, need to delete them
                LOG.error(_LE("Unable to decrypt private key, possibly due "
                              "to change of password. Certificate needs to be "
                              "regenerated"))
                self.delete_cert(purpose)
                return None, None

        return cert, private_key

    def delete_cert(self, purpose):
        return nsx_db.delete_certificate(self._context.session, purpose)


class DummyCertificateStorageDriver(object):
    """Dummy driver API implementation

    Used for external certificate import scenario
    (nsx_client_cert_storage == None)
    """

    def store_cert(self, purpose, certificate, private_key):
        pass

    def get_cert(self, purpose):
        return None, None

    def delete_cert(self, purpose):
        pass
