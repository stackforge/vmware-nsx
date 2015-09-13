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

LOG = logging.getLogger(__name__)


# Decorator to demarcate the output of various hooks
# based on the callback function's name. Function name
# should follow the convention of component_operation_it_does
# to leverage the decorator.
def output_header(func):

    def func_desc(*args, **kwargs):
        component = '[{}]'.format(func.func_name.split('_')[0].upper())
        op_desc = [n.capitalize() for n in func.func_name.split('_')[1:]]
        LOG.info('==== {} {} ===='.format(component, ' '.join(op_desc)))
        return func(*args, **kwargs)
    func_desc.__name__ = func.func_name
    return func_desc
