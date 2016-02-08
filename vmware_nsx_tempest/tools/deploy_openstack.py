# Copyright 2016 VMware Inc
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import paramiko
import requests
import six
import sys

from oslo_serialization import jsonutils

requests.packages.urllib3.disable_warnings()

LOCAL_CONF = "http://10.34.57.161/config/nsxt/esx_kvm/%s_local.conf"
P3_DEVSTACK = 'http://p3-review.eng.vmware.com/devstack'
P3_VMWARE_NSX = 'http:\/\/p3-review.eng.vmware.com\/vmware_nsx'
UPSTREAM_VMWARE_NSX = 'https:\/\/git.openstack.org\/openstack\/vmware-nsx'


def _set_url(api=None, secure=None, host=None, endpoint=None):
    api = "v1" if api is None else api
    secure = True if secure is None else secure
    http_type = 'https' if secure else 'http'
    url = '%s://%s/api/%s%s' % (http_type, host, api, endpoint)
    return url


def _set_headers(username, password):
    content_type = "application/json"
    accept_type = "application/json"
    auth_cred = username + ":" + password
    auth = base64.b64encode(auth_cred)
    headers = {}
    headers['Authorization'] = "Basic %s" % auth
    headers['Content-Type'] = content_type
    headers['Accept'] = accept_type
    return headers


def get(host=None, username=None, password=None, endpoint=None, params=None):
    """
    Basic query method for json API request
    """
    url = _set_url(host=host, endpoint=endpoint)
    headers = _set_headers(username, password)
    response = requests.get(url, headers=headers,
                            verify=False, params=params)
    return response


def validate_testbed_json(testbed, kvm):
    if kvm:
        if not ('kvm' in testbed):
            return False
        elif not ('4' in testbed['kvm']):
            return False
    for key, value in six.iteritems(testbed):
        if key != 'network' and key != 'vm':
            for index in value.keys():
                if not testbed[key][index]['ip']:
                    return False
    return True


def get_kvm_client(testbed, index):
    """ Get kvm paramiko SSHClient based on the index"""
    kvm_ip = testbed['kvm'][index]['ip']
    kvm_client = paramiko.SSHClient()
    kvm_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kvm_client.connect(kvm_ip, username='nicira', password='nicira')
    return kvm_client


def exec_command(client, cmd):
    """
    Execute commands on the client
    """
    stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
    if stdout.channel.recv_exit_status() != 0:
        print "Commands %s return error" % cmd
        sys.exit(-1)
    else:
        print "+++ %s" % cmd
        print "--- %s" % stdout.read()


def pre_stack_setup(testbed_json, branch, node):
    """
    Preparation before stack

    Steps:
        - $ sudo apt-get -f -y install
        - $ sudo rm -rf /usr/local/lib/python2.7/dist-packages/*
        - $ cd /opt/stack/nova; git checkout branch; git pull --rebase
        - $ cd ~/devstack; git checkout branch; git pull --rebase
        - $ wget
          http://10.34.57.161/config/nsxt/esx_kvm/controller_local.conf
          or http://10.34.57.161/config/nsxt/esx_kvm/kvm_compute_local.conf
        - $ mv controller_local.conf local.conf
          or mv kvm_compute_local.conf local.conf
    """
    if node == 'controller':
        kvm_client = get_kvm_client(testbed, '3')
    else:
        kvm_client = get_kvm_client(testbed, '4')
    local_conf = LOCAL_CONF % node

    # Check if there is any existing setup.
    #check_existing_setup(kvm_client)

    p3_nova = 'sudo rm -rf /opt/stack/nova'
    upstream_nova = (('cd /opt/stack/nova; git fetch; git checkout %s; '
                      'git pull -r') % branch)
    nova_cmd = p3_nova if branch == 'kermit' else upstream_nova
    upstream_devstack = (('cd ~/devstack; git fetch; git checkout %s; '
                          'git pull -r;') % branch)
    kermit_devstack = (('mkdir ~/vio; cd ~/vio; git clone %s; cd devstack; ' 
                        'git checkout %s') % (P3_DEVSTACK, branch))
    devstack_cmd = kermit_devstack if branch == 'kermit' else upstream_devstack
    devstack_dir = '~/vio/devstack' if branch == 'kermit' else '~/devstack'

    # Continue with the setup
    cmds = [
        'sudo apt-get -f -y install',
        'sudo rm -rf /usr/local/lib/python2.7/dist-packages/*',
        nova_cmd,
        devstack_cmd,
        'cd %s; wget %s; mv %s_local.conf local.conf' % (devstack_dir,
                                                         local_conf, node)
    ]
    for cmd in cmds:
        exec_command(kvm_client, cmd)

    kvm_client.close()


def get_tz_uuid(host, username, password, tz_type):
    response = get(host, username, password, endpoint="/transport-zones")
    all_tz_zones = response.json()['results']
    tz_zones = [z['id'] for z in all_tz_zones if
                z['transport_type'] == tz_type]
    if len(tz_zones) == 0:
        print "ERROR: Cannot find %s transport zone" % tz_type
        sys.exit(-1)
    else:
        return tz_zones[0]


def get_tier0_router_uuid(host, username, password):
    endpoint = "/logical-routers?router_type=TIER0"
    response = get(host, username, password, endpoint=endpoint)
    tier0_routers = response.json()['results']
    if len(tier0_routers) == 0:
        print "ERROR: Cannot find tier0 router"
        sys.exit(-1)
    else:
        return tier0_routers[0]['id']


def get_edge_cluster_uuid(host, username, password):
    endpoint = "/edge-clusters"
    response = get(host, username, password, endpoint=endpoint)
    results = response.json()['results']
    if len(results) > 0:
        return results[0]['id']
    else:
        print "ERROR: cannot find edge clusters"
        sys.exit(-1)


def config_ctrl_local_conf(testbed_json, branch):
    """
    Read data from manager and config local.conf

    Steps:
        - Change nsx_manager ip in [nsxv3] section
        - Change vCenter ip address
        - Change branch name for vmware-nsx plugin
        - Add NSX_MANAGER
        - Add OVERLAY_TZ_UUID
        - Add VLAN_TZ_UUID
        - Add TIER0_UUID
        - Add EDGE_CLUSTER_UUID
    """
    nsx_manager = list()
    for key, value in six.iteritems(testbed['nsxmanager']):
        nsx_manager.append(value['ip'])
    nsx_manager1_ip = nsx_manager[0]
    nsx_managers_ip = (",").join(nsx_manager)
    nsx_username = testbed['nsxmanager']['1']['username']
    nsx_password = testbed['nsxmanager']['1']['password']
    overlay_tz_uuid = get_tz_uuid(nsx_manager1_ip,
                                  nsx_username,
                                  nsx_password,
                                  'OVERLAY')
    vlan_tz_uuid = get_tz_uuid(nsx_manager1_ip,
                               nsx_username,
                               nsx_password,
                               'VLAN')
    tier0_router_uuid = get_tier0_router_uuid(nsx_manager1_ip,
                                              nsx_username,
                                              nsx_password)
    edge_cluster_uuid = get_edge_cluster_uuid(nsx_manager1_ip,
                                              nsx_username,
                                              nsx_password)
    kvm3_client = get_kvm_client(testbed, '3')
    if '/' in branch:
        branch = branch.replace('/', '\/')
    vmware_nsx_repo = (P3_VMWARE_NSX if branch == 'kermit' else
                       UPSTREAM_VMWARE_NSX)
    to_be_replaced = {
        '<nsx-manager1-ip>': nsx_manager1_ip,
        '<nsx-managers-ip>': nsx_managers_ip,
        '<nsx-username>': nsx_username,
        '<nsx-password>': nsx_password,
        '<vcenter-ip>': testbed['vc']['1']['ip'],
        '<os-branch>': branch,
        '<vmware-nsx-repo>': vmware_nsx_repo,
        '<vlan-tz-uuid>': vlan_tz_uuid,
        '<overlay-tz-uuid>': overlay_tz_uuid,
        '<tier0-router-uuid>': tier0_router_uuid,
        '<edge-cluster-uuid>': edge_cluster_uuid
    }
    for key, value in six.iteritems(to_be_replaced):
        devstack_dir = '~/vio/devstack' if branch == 'kermit' else '~/devstack'
        cmd = "cd %s; sed -i -e 's/%s/%s/g' local.conf" % (devstack_dir, key,
                                                           value)
        exec_command(kvm3_client, cmd)

    kvm3_client.close()


def setup_kvm_controller(testbed, branch):
    print "+++ Start the stack process on os controller... ..."
    kvm3_client = get_kvm_client(testbed, '3')
    devstack_dir = '~/vio/devstack' if branch == 'kermit' else '~/devstack'
    cmd = "cd %s; ./stack.sh" % devstack_dir
    exec_command(kvm3_client, cmd)
    kvm3_client.close()


def change_kvm_compute_hostname(testbed):
    kvm4_client = get_kvm_client(testbed, '4')
    # Change the hostname of kvm compute node
    cmd1 = "sudo hostnamectl set-hostname kvm-compute-node1"
    cmd2 = ("sudo sed -i -e 's/htb-1n-eng-dhcp8/kvm-compute-node1/g' "
            "/etc/hosts")
    for cmd in [cmd1, cmd2]:
        exec_command(kvm4_client, cmd)

    kvm4_client.close()


def config_compute_local_conf(testbed_json, branch):
    """
    Read data from testbed json file and config local.conf

    Steps:
        - Change branch name for vmware-nsx plugin
        - Change the service host ip
        - Change the host ip
    """
    kvm4_client = get_kvm_client(testbed, '4')
    git_base = '#GIT_BASE' if branch == 'kermit' else 'GIT_BASE'
    if '/' in branch:
        branch = branch.replace('/', '\/')
    vmware_nsx_repo = (P3_VMWARE_NSX if branch == 'kermit' else
                       UPSTREAM_VMWARE_NSX)
    to_be_replaced = {
        '<git-base>': git_base,
        '<vmware-nsx-repo>': vmware_nsx_repo,
        '<os-branch>': branch,
        '<service-host-ip>': testbed['kvm']['3']['ip'],
        '<this-host-ip>': testbed['kvm']['4']['ip']
    }
    for key, value in six.iteritems(to_be_replaced):
        devstack_dir = '~/vio/devstack' if branch == 'kermit' else '~/devstack'
        cmd = "sed -i -e 's/%s/%s/g' %s/local.conf" % (key, value,
                                                       devstack_dir)
        exec_command(kvm4_client, cmd)

    kvm4_client.close()


def setup_kvm_compute(testbed, branch):
    print "+++ Start the stack process on kvm compute... ..."
    kvm4_client = get_kvm_client(testbed, '4')
    devstack_dir = '~/vio/devstack' if branch == 'kermit' else '~/devstack'
    cmd = "cd %s; ./stack.sh" % devstack_dir
    exec_command(kvm4_client, cmd)

    kvm4_client.close()

def do_restack(testbed, branch, node):
    print "+++ Start the stack process on kvm compute... ..."
    if node == "controller":
        kvm_client = get_kvm_client(testbed, '3')
    else:
        kvm_client = get_kvm_client(testbed, '4')
    devstack_dir = '~/vio/devstack' if branch == 'kermit' else '~/devstack'
    cmds = [
        "cd /opt/stack/neutron; git pull -r;",
        "cd /opt/stack/vmware-nsx; git pull -r",
        "cd %s; ./unstack.sh; ./stack.sh" % devstack_dir,
    ]
    for cmd in cmds:
        exec_command(kvm_client, cmd)

    kvm_client.close()

def check_existing_setup(client):
    """
    Check if there is any existing setup

    If there is already a setup running, unstack first and then
    remove the openstack repos cloned.
    """
    stack_check_cmd = "ps aux | grep 'SCREEN -d -m -S stack' | grep -v grep"
    cmd_output = exec_command(client, stack_check_cmd)
    if cmd_output is '':
        print ("There is no existing OpenStack setup running. "
               "Continue to setup OpenStack...")
    else:
        print ("There is already OpenStack setup running. "
               "Cleanup it up first...")
        cleanup_setup(client)

def cleanup_setup(client):
    """
    Cleanup existing setup

    Steps:
        - unstack
        - rm -rf ~/.config/openstack/clouds.yaml
    """
    cmds = [
        '~/devstack/unstack.sh',
        'rm -rf ~/.config/openstack/clouds.yaml'
    ]
    for cmd in cmds:
        exec_command(client, cmd)

def setup_external_vm():
    """
    Configure the external VM
    """
    pass


if __name__ == '__main__':
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-t", "--testbed", dest="testbed",
                      help="NSX testbed json file")
    parser.add_option("-k", "--kvm-compute", dest="kvm_compute",
                      action="store_true",
                      help="Setup kvm compute node or not")
    parser.add_option("-e", "--external-vm", dest="external_vm",
                      action="store_true",
                      help="Setup kvm compute node or not")
    parser.add_option("-b", "--branch", default="master", dest="branch",
                      help="OpenStack branch to setup")
    parser.add_option("-r", "--restack", dest="restack",
                      help="Unstack and stack")

    (options, args) = parser.parse_args()
    kvm_compute_str = "Yes" if options.kvm_compute else "No"
    print "testbed json file: %s" % options.testbed
    print "Setup kvm compute node?: %s" % kvm_compute_str
    print "The OpenStack branch: %s" % options.branch

    with open(options.testbed) as testbed_json:
        testbed = jsonutils.load(testbed_json)
        # Validate the testbed json file before setup
        if not validate_testbed_json(testbed, options.kvm_compute):
            print ("ERROR: the testbed json provided doesn't meet "
                   "the requirements!")
            sys.exit(-1)

        if options.restack:
            do_restack(testbed, options.branch, 'controller')
            if options.kvm_compute:
                do_restack(testbed, options.branch, 'kvm_compute')
        else:
            # Pre-stack setup on OS controller
            pre_stack_setup(testbed, options.branch, 'controller')
            # Gather all information and write to local.conf on OS controller
            config_ctrl_local_conf(testbed, options.branch)
            # Start the stack process on OS controller
            setup_kvm_controller(testbed, options.branch)
    
            # Setup the KVM compute
            if options.kvm_compute:
                pre_stack_setup(testbed, options.branch, 'kvm_compute')
                change_kvm_compute_hostname(testbed)
                config_compute_local_conf(testbed, options.branch)
                setup_kvm_compute(testbed, options.branch)

        # Setup the external VM
        if options.external_vm:
            setup_external_vm()
