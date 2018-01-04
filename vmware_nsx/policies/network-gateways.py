from oslo_policy import policy


rules = [
    policy.RuleDefault('create_network_gateway',
                       'rule:admin_or_owner',
                       description='Rule of creating network gateway'),
    policy.RuleDefault('update_network_gateway',
                       'rule:admin_or_owner',
                       description='Rule of updating network gateway'),
    policy.RuleDefault('delete_network_gateway',
                       'rule:admin_or_owner',
                       description='Rule of deleting network gateway'),
    policy.RuleDefault('connect_network',
                       'rule:admin_or_owner',
                       description='Rule of connecting network'),
    policy.RuleDefault('disconnect_network',
                       'rule:admin_or_owner',
                       description='Rule of disconnecting network'),
    policy.RuleDefault('create_gateway_device',
                       'rule:admin_or_owner',
                       description='Rule of creating gateway device'),
    policy.RuleDefault('update_gateway_device',
                       'rule:admin_or_owner',
                       description='Rule of updating gateway device'),
    policy.RuleDefault('delete_gateway_device',
                       'rule:admin_or_owner',
                       description='Rule of deleting gateway device'),


]


def list_rules():
    return rules