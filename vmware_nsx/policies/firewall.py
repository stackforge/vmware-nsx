from oslo_policy import policy


rules = [
    policy.RuleDefault(
        'create_firewall',
        '',
        description=('')),
    policy.RuleDefault(
        'update_firewall',
        'rule:admin_or_owner',
        description=('')),
    policy.RuleDefault(
        'delete_firewall',
        'rule:admin_or_owner',
        description=('')),

    policy.RuleDefault(
        'shared_firewalls',
        'field:firewalls:shared=True',
        description=('')),
    policy.RuleDefault(
        'create_firewall:shared',
        'rule:admin_only',
        description=('')),
    policy.RuleDefault(
        'update_firewall:shared',
        'rule:admin_only',
        description=('')),
    policy.RuleDefault(
        'delete_firewall:shared',
        'rule:admin_only',
        description=('')),

    policy.RuleDefault(
        'get_firewall',
        'rule:admin_or_owner or rule:shared_firewalls',
        description=('')),
]


def list_rules():
    return rules