========================================
 Enabling NSX VPNaaS Plugin in DevStack
========================================

1. Download DevStack

2. Configure following flags in ``local.conf``::

     [[local|localrc]]
     enable_plugin neutron-vpnaas https://git.openstack.org/openstack/neutron-vpnaas
     NEUTRON_VPNAAS_SERVICE_PROVIDER=VPN:vmware:vmware_nsx.services.vpnaas.nsxv.ipsec_driver.NSXvIPsecVpnDriver:default

3. run ``stack.sh``
