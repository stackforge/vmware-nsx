# Copyright 2018 VMware, Inc.
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

LOG = logging.getLogger(__name__)


def lb_hm_obj_to_dict(hm):
    # Translate the LBaaS HM to a dictionary skipping the pool object to avoid
    # recursions
    hm_dict = hm.to_dict(pool=False)
    # Translate the pool separately without it's internal objects
    hm_dict['pool'] = lb_pool_obj_to_dict(hm.pool, with_listeners=False)
    LOG.error("DEBUG ADIT lb_hm_obj_to_dict end %s", hm_dict)
    return hm_dict


def lb_listener_obj_to_dict(listener):
    # Translate the LBaaS listener to a dictionary skipping the some objects
    # to avoid recursions
    listener_dict = listener.to_dict(loadbalancer=False, default_pool=False)
    # Translate the default pool separately without it's internal objects
    listener_dict['default_pool'] = lb_pool_obj_to_dict(listener.default_pool,
                                                        with_listeners=False)
    LOG.error("DEBUG ADIT lb_listener_obj_to_dict %s", listener_dict)
    return listener_dict


def lb_pool_obj_to_dict(pool, with_listeners=True):
    pool_dict = pool.to_dict(listeners=False, listener=False)
    if with_listeners:
        # Translate the listener/s separately without it's internal objects
        pool_dict['listener'] = lb_listener_obj_to_dict(pool.listener)
        pool_dict['listeners'] = []
        if pool.listeners:
            for listener in pool.listeners:
                pool_dict['listeners'].append(
                    lb_listener_obj_to_dict(listener))
    return pool_dict
