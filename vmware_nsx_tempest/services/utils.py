"""
Utils function for NSX-v neutron plugin automation
"""


def ceil(a, b):
    if b == 0:
        return 0
    div = a / b
    mod = 0 if a % b is 0 else 1
    return div + mod


if __name__ == "__main__":
    """
    Add unit test of the util functions
    """
    pass
