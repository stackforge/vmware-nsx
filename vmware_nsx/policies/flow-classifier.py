from oslo_policy import policy


rules = [
    policy.RuleDefault('create_flow_classifier',
                       'rule:admin_only',
                       description='Rule of creating flow classifier'),
    policy.RuleDefault('update_flow_classifier',
                       'rule:admin_only',
                       description='Rule of updating flow classifier'),
    policy.RuleDefault('delete_flow_classifier',
                       'rule:admin_only',
                       description='Rule of delete flow classifier'),
    policy.RuleDefault('get_flow_classifier',
                       'rule:admin_only',
                       description='Rule of getting flow classifier'),

]


def list_rules():
    return rules
