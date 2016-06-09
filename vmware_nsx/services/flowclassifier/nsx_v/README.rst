===============================================================
 Enabling NSX Flow Classifier for service insertion in DevStack
===============================================================

1. Download DevStack

4. Update the ``local.conf`` file::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    service_plugins = networking_sfc.services.flowclassifier.plugin.FlowClassifierPlugin, networking_sfc.services.sfc.plugin.SfcPlugin

    [flowclassifier]
    drivers = vmware-nsxv

    [nsxv]
    service_insertion_redirect_to = <redirect to>

5. run ``stack.sh``
