from oslo_policy import policy


rules = [
    policy.RuleDefault('get_bgp_speaker',
                       'rule:admin_only',
                       description='Rule of getting BGP speaker'),
    policy.RuleDefault('create_bgp_speaker',
                       'rule:admin_only',
                       description='Rule of creating BGP speaker'),
    policy.RuleDefault('update_bgp_speaker',
                       'rule:admin_only',
                       description='Rule of updating BGP speaker'),
    policy.RuleDefault('delete_bgp_speaker',
                       'rule:admin_only',
                       description='Rule of deleting BGP speaker'),
    policy.RuleDefault('get_bgp_peer',
                       'rule:admin_only',
                       description='Rule of getting BGP peer'),
    policy.RuleDefault('create_bgp_peer',
                       'rule:admin_only',
                       description='Rule of creating BGP peer'),
    policy.RuleDefault('update_bgp_peer',
                       'rule:admin_only',
                       description='Rule of updating BGP peer'),
    policy.RuleDefault('delete_bgp_peer',
                       'rule:admin_only',
                       description='Rule of deleting BGP peer'),
    policy.RuleDefault('add_bgp_peer',
                       'rule:admin_only',
                       description='Rule of adding BGP peer'),
    policy.RuleDefault('remove_bgp_peer',
                       'rule:admin_only',
                       description='Rule of removing BGP peer'),
    policy.RuleDefault('add_gateway_network',
                       'rule:admin_only',
                       description='Rule of adding gateway network'),
    policy.RuleDefault('remove_gateway_network',
                       'rule:admin_only',
                       description='Rule of removing gateway network'),
    policy.RuleDefault('get_advertised_routes',
                       'rule:admin_only',
                       description='Rule of getting advertised routes'),

]


def list_rules():
    return rules

