from oslo_policy import policy


rules = [
    policy.RuleDefault(
        'shared_firewall_rules',
        'field:firewall_rules:shared=True',
        description=('')),

    policy.RuleDefault(
        'create_firewall_rule',
        '',
        description=('')),
    policy.RuleDefault(
        'update_firewall_rule',
        'rule:admin_or_owner',
        description=('')),
    policy.RuleDefault(
        'delete_firewall_rule',
        'rule:admin_or_owner',
        description=('')),

    policy.RuleDefault(
        'create_firewall_rule:shared',
        'rule:admin_only',
        description=('')),
    policy.RuleDefault(
        'update_firewall_rule:shared',
        'rule:admin_only',
        description=('')),
    policy.RuleDefault(
        'delete_firewall_rule:shared',
        'rule:admin_only',
        description=('')),

    policy.RuleDefault(
        'get_firewall_rule',
        'rule:admin_or_owner or rule:shared_firewall_rules',
        description=('')),

    policy.RuleDefault(
        'insert_rule',
        'rule:admin_or_owner',
        description=('')),
    policy.RuleDefault(
        'remove_rule',
        'rule:admin_or_owner',
        description=('')),
]


def list_rules():
    return rules