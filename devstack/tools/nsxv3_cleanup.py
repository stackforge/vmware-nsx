#!/usr/bin/env python

from optparse import OptionParser
from oslo_config import cfg

import vmware_nsx.neutron.plugins.vmware.common.config  # noqa
from vmware_nsx.neutron.plugins.vmware.nsxlib.v3 import dfw_api as firewall


def clean_security_groups():
    sections = firewall.list_sections()
    for section in sections[:-1]:
        print("Deleting firewall section %(display_name)s, section id %(id)s",
              section)
        firewall.delete_section(section['id'])

    nsgroups = firewall.list_nsgroups()
    for nsgroup in nsgroups:
        print("Deleting ns-group %(display_name)s, ns-group id %(id)s",
              nsgroup)
        firewall.delete_nsgroup(nsgroup['id'])


if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("--manager-ip", dest="manager_ip",
                      help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="admin", dest="username",
                      help="NSX Manager username")
    parser.add_option("-p", "--password", default="default", dest="password",
                      help="NSX Manager password")
    (options, args) = parser.parse_args()

    cfg.CONF.set_override('nsx_manager',  options.manager_ip, 'nsx_v3')
    cfg.CONF.set_override('nsx_user',  options.username, 'nsx_v3')
    cfg.CONF.set_override('nsx_password', options.password, 'nsx_v3')
    cfg.CONF.set_override('insecure',  True, 'nsx_v3')

    clean_security_groups()
