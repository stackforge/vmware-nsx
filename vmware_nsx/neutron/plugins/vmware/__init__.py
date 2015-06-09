import os

from neutron.plugins.vmware import extensions

NSX_EXT_PATH = os.path.dirname(extensions.__file__)
NSX_POLICY_PATH = '/etc/neutron/plugins/vmware/policy'
