============================================
 Enabling NSX VPNaaS Plugin in DevStack
============================================

1. Download DevStack

2. Configure following flags in ``local.conf``::

     [[local|localrc]]
     NEUTRON_VPNAAS_CONF=/etc/neutron/neutron_vpnaas.conf
     NSX_IPSEC_VPN_DRIVER=vmware_nsx.services.vpnaas.nsxv.vpnaas_driver.EdgeVPNDriver
     NSX_IPSEC_VPN_VALIDATOR=vmware_nsx.services.vpnaas.nsxv.vpnaas_validator.VpnValidator
     enable_plugin neutron-vpnaas https://git.openstack.org/openstack/neutron-vpnaas
     [[post-config|$NEUTRON_CONF]]
     [DEFAULT]
     service_plugins = neutron_vpnaas.services.vpn.plugin.VPNDriverPlugin
     [[post-config|$NEUTRON_VPNAAS_CONF]]
     [service_providers]
     service_provider=VPN:vmware:neutron_vpnaas.services.vpn.service_drivers.vmware_ipsec.VMwareIPsecVPNDriver:default

3. run ``stack.sh``
