================================================================
 Enabling NSXv IPAM for external & provider networks in Devstack
================================================================

1. Download DevStack

2. Update the ``local.conf`` file::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    ipam_driver = vmware_nsx.services.ipam.nsx_v.driver.NsxvIpamDriver

3. run ``stack.sh``
