Admin Utility
=============

Introduction
------------

Purpose of this script is to build a framework which can be leveraged to build utilities to help the on-field ops in system debugging.

We support the following functions for now:
* Be able to read the database and configuration files.

* Be able to access the backend via API


Adding custom functions
-----------------------
Adding new functions is fairly straightforward:
* Define the function under appropriate package, ex: nsxadmin/nsx_plugins/nsx_v3/resources/function_resource.py

* In nsxadmin/shell.py, add the function to the callback registry.

::
         registry.subscribe(sg.neutron_clean_security_groups,
                            Resources.SECURITY_GROUPS,
                            Operations.NEUTRON_CLEAN)

* Add the Resources and Operations properties if they don't exist.

::
  class Operations(object):
      NEUTRON_CLEAN = 'neutron_clean'

::
  class Resources(object):
      SECURITY_GROUPS = 'security-groups'


* To test, do

::
    cd python-nsxadmin/
    sudo python setup.py install
    nsxadmin -r <resource_name_you_added> -o <operation_you_added>


Refer to the security groups example for reference implementation.

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
      nsx_v3/
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

