from oslo_policy import policy


rules = [
    policy.RuleDefault('create_network_profile',
                       'rule:admin_only',
                       description='Rule of creating network profile'),
    policy.RuleDefault('update_network_profile',
                       'rule:admin_only',
                       description='Rule of updating network profile'),
    policy.RuleDefault('delete_network_profile',
                       'rule:admin_only',
                       description='Rule of deleting network profile'),
    policy.RuleDefault('get_network_profile',
                       '',
                       description='Rule of getting network profile'),
    policy.RuleDefault('get_network_profiles',
                       '',
                       description='Rule of getting network profiles'),
    policy.RuleDefault('update_policy_profiles',
                       'rule:admin_only',
                       description='Rule of getting network profiles'),
    policy.RuleDefault('get_policy_profile',
                       '',
                       description='Rule of getting policy profile'),
    policy.RuleDefault('get_policy_profiles',
                       '',
                       description='Rule of getting policy profile'),
]


def list_rules():
    return rules