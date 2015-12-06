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

import logging

from neutron.callbacks import exceptions
from neutron.callbacks import manager

from vmware_nsx._i18n import _LE
from vmware_nsx.common import exceptions as nsx_exc

LOG = logging.getLogger(__name__)


class CallbacksManager(manager.CallbacksManager):
    def __init__(self):
        super(CallbacksManager, self).__init__()

    def _notify_loop(self, resource, event, trigger, **kwargs):
        """The notification loop."""
        LOG.debug("Notify callbacks for %(resource)s, %(event)s",
                  {'resource': resource, 'event': event})

        errors = []
        callbacks = self._callbacks[resource].get(event, {}).items()
        for callback_id, callback in callbacks:
            try:
                LOG.debug("Calling callback %s", callback_id)
                callback(resource, event, trigger, **kwargs)
            except nsx_exc.AdminUtilityOutOfSync:
                LOG.error(_LE("ERROR: %(resource)s out of sync"),
                          {'resource': resource})
                raise nsx_exc.AdminUtilityOutOfSync()
            except Exception as e:
                LOG.exception(_LE("Error during notification for "
                                  "%(callback)s %(resource)s, %(event)s"),
                              {'callback': callback_id,
                               'resource': resource,
                               'event': event})
                errors.append(exceptions.NotificationError(callback_id, e))
        return errors
