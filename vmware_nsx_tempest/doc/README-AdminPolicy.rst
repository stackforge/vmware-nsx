Admin Policy
============

Admin policy, neutron extension secuirty-group-policy provides organization
to enforce traffic forwarding utilizing NSX security policy.

The "Admin Policy" feature is admin priviledge, normal project/tenant is not
able to create security-group-policy.

This feature can be enabled manually at current release.

Enable security-group-policy extention
======================================

Instruction is from the view of devstackview:

#. Add following items to /etc/neutron/policy.json::

    "create_security_group:logging": "rule:admin_only",
    "update_security_group:logging": "rule:admin_only",
    "get_security_group:logging": "rule:admin_only",
    "create_security_group:provider": "rule:admin_only",
    "create_port:provider_security_groups": "rule:admin_only",
    "create_security_group:policy": "rule:admin_only",
    "update_security_group:policy": "rule:admin_only",

#. Add following key=value pair to session [nsxv] of /etc/neutron/plugin/vmware/nsx.ini

    use_nsx_policies = True
    default_policy_id = policy-6
    allow_tenant_rules_with_policy = False

    # NOTE: For automation, set allow_tenant_rules_with_policy to True

tempest.conf & devstack local.conf
==================================

At session [nsxv] add the following 3 key=value pair:

    default_policy_id = policy-11
    alt_policy_id = policy-22
    allow_tenant_rules_with_policy = False

    # NOTE: default_policy_id and allow_tenant_rules_with_policy need to match nsx.ini

default_policy_id and alt_policy_id:

    For API tests, both must exist at NSX.

    For scenario tests, please refer to test plan: https://goo.gl/PiA0KQ

    In short::

    policy-11 (policy-AA at script & test-plan) firewall rules::
        action-1: dhcp-in/any/Policy-security-group/dhcp/Allow
        action-2: dhcp-out/Policy-security-group/dhcp/Allow
        action-3: ping-in/any/Policy-security-group/ICMP/Allow
        action-4: ping-out/Policy-security-group/any/ICMP/Allow/
        action-5: ssh-in/any/Policy-security-group/SSH/Allow/
        action-5: ssh-in/any/Policy-security-group/SSH/Allow/
        action-7: http-ok/any/Policy-security-group/HTTP,HTTPS/Allow/
        action-8: sorry-nothing-allowed/any/Policy-security-group/Any/Reject

        You can import policy-AA to NSX using the admin-policy-AA.blueprint

    policy-22 (policy-BB at script & test-plan) firewall rules::
        action-1: dhcp-in/any/Policy-security-group/dhcp/Allow
        action-2: dhcp-out/Policy-security-group/dhcp/Allow
        action-4: ping-out/Policy-security-group/any/ICMP/Allow/
        action-5: ssh-in/any/Policy-security-group/SSH/Allow/
        action-5: ssh-in/any/Policy-security-group/SSH/Allow/
        action-7: http-ok/any/Policy-security-group/HTTP,HTTPS/Allow/
        action-8: sorry-nothing-allowed/any/Policy-security-group/Any/Reject

        NOTE on ping: same as policy-11 but only allowed from Policy-security-group
        You can import policy-BB to NSX using the admin-policy-AA.blueprint
