Admin Policy
============

Admin policy, neutron extension secuirty-group-policy provides organization
to enforce traffic forwarding policy utilizing NSX security policy.

The "Admin Policy" feature is admin priviledge, normal project/tenant is not
able to create security-group-policy.

This feature can be enabled manually at current release.

Enable security-group-policy extention
======================================

Instruction is from the devstack view:

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

    # NOTE: default_policy_id an allow_tenant_rules_with_policy need to match nsx.ini

default_policy_id and alt_policy_id:

    For API tests, both must exist at NSX.

    For scenario tests, please refer to test plan: https://goo.gl/PiA0KQ

    In short::
    policy-11 (policy-AA at script & test-plan):
        ssh in/out allowed
        ping in/out allowed
    policy-22 (policy-BB at script & test-plan):
        ssh in/out allowed
        ping out allowed
        ping in allowed from security-group

