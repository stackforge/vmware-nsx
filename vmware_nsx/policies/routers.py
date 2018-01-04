from oslo_policy import policy


rules = [
    policy.RuleDefault('create_router:distributed',
                       'rule:admin_or_owner',
                       description='Rule of create router distributed'),
    policy.RuleDefault('get_router:distributed',
                       'rule:admin_or_owner',
                       description='Rule of get router distributed'),
    policy.RuleDefault('update_router:distributed',
                       'rule:admin_or_owner',
                       description='Rule of update router distributed'),
    policy.RuleDefault('get_router:ha',
                       'rule:admin_only',
                       description='Rule of get router ha'),
    policy.RuleDefault('create_router',
                       'rule:regular_user',
                       description='Rule of create router'),
    policy.RuleDefault('create_router:external_gateway_info:enable_snat',
                       'rule:admin_or_owner',
                       description='Rule of create ext gw enable snat router'),
    policy.RuleDefault('create_router:ha',
                       'rule:admin_only',
                       description='Rule of create ha router'),
    policy.RuleDefault('get_router',
                       'rule:admin_or_owner',
                       description='Rule of get router'),
    policy.RuleDefault('update_router:external_gateway_info:enable_snat',
                       'rule:admin_or_owner',
                       description='Rule of update ext gw enable snat router'),
    policy.RuleDefault('update_router:ha',
                       'rule:admin_only',
                       description='Rule of update ha router'),
    policy.RuleDefault('delete_router',
                       'rule:admin_or_owner',
                       description='Rule of delete router'),
    policy.RuleDefault('add_router_interface',
                       'rule:admin_or_owner',
                       description='Rule of add router iface'),
    policy.RuleDefault('remove_router_interface',
                       'rule:admin_or_owner',
                       description='Rule of remove router iface'),
    policy.RuleDefault('create_router:external_gateway_info:external_fixed_ips',
                       'rule:admin_only',
                       description='Rule of create router '
                                   'ext gw info ext fixed ips'),
    policy.RuleDefault('update_router:external_gateway_info:external_fixed_ips',
                       'rule:admin_only',
                       description='Rule of update router '
                                   'ext gw info ext fixed ips'),
]


def list_rules():
    return rules
