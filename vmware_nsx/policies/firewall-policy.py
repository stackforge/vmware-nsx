from oslo_policy import policy


rules = [
    policy.RuleDefault(
        'shared_firewall_policies',
        'field:firewall_policies:shared=True',
        description=('')),

    policy.RuleDefault(
        'create_firewall_policy',
        '',
        description=('')),
    policy.RuleDefault(
        'update_firewall_policy',
        'rule:admin_or_owner',
        description=('')),
    policy.RuleDefault(
        'delete_firewall_policy',
        'rule:admin_or_owner',
        description=('')),

    policy.RuleDefault(
        'create_firewall_policy:shared',
        'rule:admin_only',
        description=('')),
    policy.RuleDefault(
        'update_firewall_policy:shared',
        'rule:admin_only',
        description=('')),
    policy.RuleDefault(
        'delete_firewall_policy:shared',
        'rule:admin_only',
        description=('')),

    policy.RuleDefault(
        'get_firewall_policy',
        'rule:admin_or_owner or rule:shared_firewall_policies',
        description=('')),
]


def list_rules():
    return rules