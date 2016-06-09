===============================================================
 Enabling NSX Flow Classifier for service insertion in DevStack
===============================================================

1. Download DevStack

4. Update the ``local.conf`` file::

    [[post-config|$NEUTRON_CONF]]
    [DEFAULT]
    service_plugins = networking_sfc.services.flowclassifier.plugin.FlowClassifierPlugin, networking_sfc.services.sfc.plugin.SfcPlugin # DEBUG ADIT not sure we need both
    # DEBUG ADIT or this one??: vmware_nsx.services.flowclassifier.nsx_v.plugin:NsxvFlowClassifierPlugin 

    [flowclassifier]
    drivers = vmware-nsxv

5. run ``stack.sh``
