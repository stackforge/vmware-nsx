Admin Utility
=============

Introduction
------------

Purpose of this script is to build a framework which can be leveraged to build utilities to help the on-field ops in system debugging.


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


Example
-------
::
 gangil@htb-1n-eng-dhcp406:/opt/stack/vmware-nsx/devstack/tools/python-nsxadmin$ nsxadmin -r security-groups -o list
 Deprecated: Registering resources to apply quota limits to using the quota_items option is deprecated as of Liberty.Resource REST controllers should take care of registering resources with the quota engine.
 [Neutron] List security groups
 security groups
 +--------+------+
 | name   | id   |
 |--------+------|
 +--------+------+
 [NSX] List security groups
 Starting new HTTPS connection (1): 10.161.79.150
 Firewall Sections
 +------------------------------------------------+--------------------------------------+
 | display_name                                   | id                                   |
 |------------------------------------------------+--------------------------------------|
 | default - 261343f8-4f35-4e57-9cc7-6c4fc7723b72 | 91a05fbd-054a-48b6-8e60-3b5d445be8c7 |
 | default - 823247b6-bdb3-47be-8bac-0d1114fc1ad7 | 78116d4a-de77-4a8f-b3e5-e76f458840ea |
 | OS default section for security-groups         | 10a2fc6c-29c9-4d8d-ac2c-b24aafa15c79 |
 | Default Layer3 Section                         | e479e404-e712-4adb-879c-e432d510c056 |
 +------------------------------------------------+--------------------------------------+
 Starting new HTTPS connection (1): 10.161.79.150
 Firewall NS Groups
 +------------------------------------------------+--------------------------------------+
 | display_name                                   | id                                   |
 |------------------------------------------------+--------------------------------------|
 | NSGroup Container                              | c0b26e82-d49b-49f0-b68e-7449a59366e9 |
 | default - 261343f8-4f35-4e57-9cc7-6c4fc7723b72 | 2e5b5ca1-f687-4556-8130-9524b313474b |
 | default - 823247b6-bdb3-47be-8bac-0d1114fc1ad7 | b5cd9ae4-42b5-47a7-a1bf-9767ac62466e |
 +------------------------------------------------+--------------------------------------+


Help
----
::
 nsxadmin --help

