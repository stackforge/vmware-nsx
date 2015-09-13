Admin Utility
=============

Introduction
------------
Purpose of this script is to build a framework which can be leveraged to build utilities to help the on-field ops in system debugging.


Adding custom functions
-----------------------
Reference implementation can be viewed in admin/plugins/nsx_v3/resources/secruitygroups.py

Adding new functions is fairly straightforward:
* Define the function under appropriate package, ex: admin/plugins/nsx_v3/resources/function_resource.py
  We use neutron callbacks to provide hooks. So your function definition should be like:

::
  def function(resource, event, trigger, **kwargs):

* In admin/shell.py, add the function to the callback registry.

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
    admin -r <resource_name_you_added> -o <operation_you_added>


Refer to the security groups example for reference implementation.

**ToDo: Write formatters wrapper**
**ToDo: Support ports, logical switches**
**ToDo: Move towards design like openstack clients, things like packaging etc**
**ToDo: Autocomplete command line args**
**ToDo: Error when unsupported operations are called for**


Directory Structure
-------------------
admin/

  plugins/
    Contains code specific to different plugin versions.
      common/
      nsx_v3/
        resources/
          Contains modules for various resources supported by the
          admin utility. These modules contains methods to perform
          operations on these resources. Would also contain the
          output formatters.


Installation
------------
::
  pip install -r requirements.txt
  pip install -e .

Usage
-----
::
 nsxadmin -r <resource> -o <operation>


Example
-------
::
 $ nsxadmin -r security-groups -o list

 ====Deprecated: Registering resources to apply quota limits to using the quota_items option is deprecated as of Liberty.Resource REST controllers should take care of registering resources with the quota enginee [NSX] List Security Groups ====
 Firewall Sections
 +------------------------------------------------+--------------------------------------+
 | display_name                                   | id                                   |
 |------------------------------------------------+--------------------------------------|
 | default - 261343f8-4f35-4e57-9cc7-6c4fc7723b72 | 91a05fbd-054a-48b6-8e60-3b5d445be8c7 |
 | default - 823247b6-bdb3-47be-8bac-0d1114fc1ad7 | 78116d4a-de77-4a8f-b3e5-e76f458840ea |
 | OS default section for security-groups         | 10a2fc6c-29c9-4d8d-ac2c-b24aafa15c79 |
 | Default Layer3 Section                         | e479e404-e712-4adb-879c-e432d510c056 |
 +------------------------------------------------+--------------------------------------+
 {
     "Firewall NS Groups": [
         {
             "display_name": "NSGroup Container",
             "id": "c0b26e82-d49b-49f0-b68e-7449a59366e9"
         },
         {
             "display_name": "default - 261343f8-4f35-4e57-9cc7-6c4fc7723b72",
             "id": "2e5b5ca1-f687-4556-8130-9524b313474b"
         },
         {
             "display_name": "default - 823247b6-bdb3-47be-8bac-0d1114fc1ad7",
             "id": "b5cd9ae4-42b5-47a7-a1bf-9767ac62466e"
         }
     ]
 }
 ==== [NEUTRON] List Security Groups ====
 {
     "Security Groups": []
 }


Help
----
::
 $ nsxadmin --help

