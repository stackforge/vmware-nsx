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

import logging

def getLogger(name):
    return AdminLogger().getLogger(name)


def singleton(cls):
    instances = {}

    def get_instance():
        if cls not in instances:
            instances[cls] = cls()
        return instances[cls]

    return get_instance


@singleton
class AdminLogger(object):

    def __init__(self):
        from oslo_config import cfg
        CONSOLE_MESSAGE_FORMAT = "%(message)s"
        DEBUG_MESSAGE_FORMAT = '%(levelname)s: %(name)s %(message)s'
        logging.basicConfig(format=CONSOLE_MESSAGE_FORMAT,
                            level=logging.INFO)
      #  if cfg.CONF.verbose:
      #      logging.basicConfig(format=CONSOLE_MESSAGE_FORMAT,
      #                          level=logging.INFO)
      #  else:
      #      logging.basicConfig(format=DEBUG_MESSAGE_FORMAT,
      #                          level=logging.INFO)

    def getLogger(self, name):
        return logging.getLogger(name)
