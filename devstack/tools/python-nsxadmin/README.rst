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
#     under the License.


Admin Utility
=============

Introduction
------------

Purpose of this script is to build a framework which can be leveraged to build utilities to help the on-field ops in system debugging.

We support the following functions for now:
* Be able to read the database and configuration files.

* Be able to access the backend via API

* Compare data from different sources and decide next course of action.

**ToDo: Write formatters wrapper**
**ToDo: Support ports, logical switches**
**ToDo: Move towards design like openstack clients, things like packaging etc**
**ToDo: Autocomplete command line args**
**ToDo: Error when unsupported operations are called for**


Directory Structure
-------------------
nsxadmin/

  nsx_plugins/
    Contains code specific to different plugin versions.

      resources/
        Contains modules for various resources supported by the
        admin utility. These modules contains methods to perform
        operations on these resources. Would also contain the
        output formatters.


Installation
------------
::
  python setup.py install

Usage
-----
::
 nsxadmin -r <resource> -o <operation>


Help
----
::
 nsxadmin --help

