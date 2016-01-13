==================================================
vmware_nsx_tempest development and execution Guide
==================================================

vmware_nsx_tempest hosts vmware_nsx's functional api and scenario tests.

All vmware_nsx_tempest tests are in "master" branch. For this reason,
it is recommended to have your a devel version of vmware-nsx repo installed
outside /opt/stack/ directory. For example /opt/devtest, in doing so, you
can install editable vmware-nsx repo under tempest VENV environemnt.

Installation:
-------------

Installed at your own env, or example /opt/devtest/:
cd /opt/devtest
git clone https://github.com/openstack/vmware-nsx

Assume the tempest directory is at /opt/devtest/os-tempest.

    cd /opt/devtest/os-tempest
    source .venv/bin/activate
    pip install -e /opt/devtest/vmware-nsx/

Validate installed vmware_nsx_tempest succesfully do:

    cd /opt/devtest/os-tempest
    testr list-tests vmware_nsx_tempest.*l2_gateway

    if no test lists created, your installation failed.
