from oslo_policy import policy


rules = [
    policy.RuleDefault('create_port:provider_security_groups',
                       'rule:admin_only',
                       description='Rule of create port security groups'),
    policy.RuleDefault('update_port:provider_security_groups',
                       'rule:admin_only',
                       description='Rule of update port security groups'),

]


def list_rules():
    return rules
