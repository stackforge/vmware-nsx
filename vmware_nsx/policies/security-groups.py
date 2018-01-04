from oslo_policy import policy


rules = [
    policy.RuleDefault('create_security_group:logging',
                       'rule:admin_only',
                       description='Rule of create security group logging'),
    policy.RuleDefault('update_security_group:logging',
                       'rule:admin_only',
                       description='Rule of update security group logging'),
    policy.RuleDefault('get_security_group:logging',
                       'rule:admin_only',
                       description='Rule of getting security group logging'),
    policy.RuleDefault('create_security_group:provider',
                       'rule:admin_only',
                       description='Rule of create security group provider'),
    policy.RuleDefault('create_security_group:policy',
                       'rule:admin_only',
                       description='Rule of create security group policy'),
    policy.RuleDefault('update_security_group:policy',
                       'rule:admin_only',
                       description='Rule of update security group policy'),
]


def list_rules():
    return rules
