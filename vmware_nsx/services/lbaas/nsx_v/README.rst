===========================================
 Enabling NSXv LBaaSv2 in DevStack DevStack
===========================================

1. Download DevStack

2. Add lbaas repo as an external repository and configure following flags in ``local.conf``::

    [[local]|[localrc]]
    enable_plugin neutron-lbaas https://git.openstack.org/openstack/neutron-lbaas
    enable_service q-lbaasv2

3. Configure the service provider::
    [[post-config|$NEUTRON_LBAAS_CONF]]
    [service_providers]
    service_provider = LOADBALANCERV2:VMWareEdge:neutron_lbaas.drivers.vmware.edge_driver_v2.EdgeLoadBalancerDriverV2:default
