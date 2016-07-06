Admin Utility
=============

The NSXv and the NSXv3 support the nsxadmin utility. This enables and administrator to determine and rectify inconsistencies between the Neutron DB and the NSX.
usage: nsxadmin -r <resources> -o <operation>

NSXv
----

The following resources are supported: 'security-groups', 'edges', 'networks', 'firewall-sections', 'orphaned-edges', 'spoofguard-policy', 'missing-edges', 'backup-edges', 'nsx-security-groups', 'dhcp-binding' and  'metadata'

- Edge Datastore HA: This admin utility can be used on upgrade after the customer added ha_datastore_id to the nsx.ini configuration, in order to update the deployment of existing edges. The new edge appliances configuration will be taken from the nsx.ini, including the datastrore_id, ha_datastore_id, edge_ha. The edge current resource pool & appliance size will not change::

    nsxadmin -r edges -o nsx-update --property edge-id=<edge-id> --property appliances=True

-  List missing edges on NSX. This includes missing networks on those edges::

    nsxadmin -r missing-edges -o list

- Ability to update or get the teaming policy for a DVS::

   nsxadmin -r networks -o nsx-update --property dvs-id=<id> --property teamingpolicy=<policy>

- Security groups. This adds support to list security-groups mappings and miss-matches between the mappings and backend resources as: firewall-sections and nsx-security-groups::

   nsxadmin --resource security-groups --operation list
   nsxadmin -r nsx-security-groups -o {list, list-missmatches}
   nsxadmin -r firewall-sections -o {list, list-missmatches}

- Support getting network morefs::

   nsxadmin -r networks -o list

- Spoofguard support::

   nsxadmin -r spoofguard-policy -o list-mismatches
   nsxadmin -r spoofguard-policy -o clean --property policy-id=spoofguardpolicy-10
   nsxadmin -r spoofguard-policy -o list --property reverse (entries defined on NSXv and not in Neutron)

- Update the size of an edge::

   nsxadmin -r edges -o nsx-update --property edge-id=edge-55 --property size=compact

- Update DHCP bindings on an edge::

   nsxadmin -r dhcp-binding -o nsx-update --property edge-id=edge-15

- Delete backup edge::

   nsxadmin -r backup-edges -o clean --property edge-id=edge-9

- List backup edges::

   nsxadmin -r backup-edges -o list


NSXv3
-----
The following resources are supported: 'security-groups', 'routers', 'networks', 'nsx-security-groups', 'dhcp-binding' and 'ports'.

- List missing networks::

    nsxadmin -r networks -o list-mismatches

- List missing routers::

    nsxadmin -r routers -o list-mismatches

- List missing ports::

    nsxadmin -r ports -o list-mismatches
