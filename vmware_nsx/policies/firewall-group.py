from oslo_policy import policy


rules = [
    policy.RuleDefault(
        'shared_firewall_groups',
        'field:firewall_groups:shared=True',
        description=('')),

    policy.RuleDefault(
        'create_firewall_group',
        '',
        description=('')),
    policy.RuleDefault(
        'update_firewall_group',
        'rule:admin_or_owner',
        description=('')),
    policy.RuleDefault(
        'delete_firewall_group',
        'rule:admin_or_owner',
        description=('')),

    policy.RuleDefault(
        'create_firewall_group:shared',
        'rule:admin_only',
        description=('')),
    policy.RuleDefault(
        'update_firewall_group:shared',
        'rule:admin_only',
        description=('')),
    policy.RuleDefault(
        'delete_firewall_group:shared',
        'rule:admin_only',
        description=('')),

    policy.RuleDefault(
        'get_firewall_group',
        'rule:admin_or_owner or rule:shared_firewall_groups',
        description=('')),
]


def list_rules():
    return rules