#!/usr/bin/env bash

export SSHPASS=ca\$hc0w

set -x

echo "Logged in to tongl-launcher-htb"

JENKINS_DIR=/opt/jenkins
JENKINS_JOB=nsx-neutron-bat
JENKINS_WORKSPACE=$JENKINS_DIR/workspace/$JENKINS_JOB
TESTBED_JSON=$JENKINS_WORKSPACE/testbed.json
VDNET_DIR=/src/nsx-qe/vdnet/automation
YAML_FILE=yaml/openstack/nsxt-neutron-bat.yaml
BUILD_FILE=yaml/cat/vdnet_master_status/bumblebee_release_builds.yaml
TDS=NSXTransformers.Openstack.HybridEdge.OSDeploy.DeployOSMH3NodesTestbed
RUN_TEMPEST_SH=http://10.34.57.161/utils/nsxt/run-tempest-nsxv3.sh
USERNAME=tongl
MAX_DEPLOY_TRY=3
VDNET_CMD="main/vdnet -c $YAML_FILE -t $TDS --interactive CreateIPDiscoveryProfile --exitoninteractive true --testrunid $TEST_RUN_ID"
EXT_USER=root
IP_REGEX='[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'

function clean_up {
  echo ">>> Cleaning up testbed after test execution completes..."
  pushd $VDNET_DIR
  sudo -u $USERNAME -H sh -c "main/vdnet -c $YAML_FILE --testbed forceclean --testrunid $TEST_RUN_ID"
  test_dir=$(ls /tmp/vdnet -tr | grep -e "[0-9]\{8\}\-[0-9]\{6\}")
  for dir in $test_dir; do rm -rf /tmp/vdnet/$dir; done
  popd
}

function copy_testbed_json {
  test_dir=$(ls /tmp/vdnet -tr | tail -1 | grep -e "[0-9]\{8\}\-[0-9]\{6\}")
  if [ "$test_dir" != "" ]; then
    testbed_json=/tmp/vdnet/$test_dir/testbed.json
    cp $testbed_json $JENKINS_WORKSPACE
  fi
}

function deploy_topo {
  pushd $VDNET_DIR
  i=0
  while [ $i -lt $MAX_DEPLOY_TRY ]; do
    echo ">>> Trying to deploy testbed #$i times..." 
    echo ">>> $VDNET_CMD"
    sudo -u $USERNAME -H sh -c "$VDNET_CMD"
    return_code=$?
    echo ">>> Deployment return code is $return_code" 
    if [ $return_code -eq 0 ]; then
      echo ">>> Testbed deployment SUCCESS!"
      copy_testbed_json
      break
    else
      echo ">>> Deployment FAILED with error code: $return_code. Cleanup and try again!"
      clean_up
      (( i++ ))
    fi
  done
  if [ $i -eq $MAX_DEPLOY_TRY ]; then
    echo ">>> ERROR: Deployment FAILED with error code: $return_code!!!"
    exit $return_code
  fi
  popd
}

function is_existing_setup {
  test_dir=$(ls /tmp/vdnet -tr | tail -1 | grep -e "[0-9]\{8\}\-[0-9]\{6\}")
  if [ "$test_dir" == "" ]; then
    echo ">>> There is no setup. Deploying a fresh testbed."
    setup_exist=0
    deploy_topo
  else
    echo ">>> There is an existing setup. Reusing the setup!"
    setup_exist=1
  fi
}

function exec_remote_cmd {
  if [ "$1" == "scp" ]; then
    sshpass -e scp -o StrictHostKeyChecking=no $2 $3
  else
    sshpass -e ssh -o StrictHostKeyChecking=no $2@$3 "$4"
  fi
}

function run_tempest {
  echo ">>> Copying tempest.conf from devstack to external VM..." 
  exec_remote_cmd "scp" $EXT_USER@$DEVSTACK_VM_IP:/opt/stack/tempest/etc/tempest.conf $JENKINS_WORKSPACE
  exec_remote_cmd "scp" $JENKINS_WORKSPACE/tempest.conf $EXT_USER@$EXT_VM_IP:~
  echo ">>> Executing tempest test suites on external VM..."
  if [ $setup_exist -eq 0 ]; then
    exec_remote_cmd "ssh" $EXT_USER $EXT_VM_IP "wget $RUN_TEMPEST_SH; bash run-tempest-nsxv3.sh --set-env --all"
    return_code=$?
  else
    exec_remote_cmd "ssh" $EXT_USER $EXT_VM_IP "rm -rf /opt/stack/tempest/*.html"
    exec_remote_cmd "ssh" $EXT_USER $EXT_VM_IP "wget $RUN_TEMPEST_SH; bash run-tempest-nsxv3.sh --all"
    return_code=$?
  fi
  if [ $return_code -eq 0 ]; then
    exec_remote_cmd "scp" $EXT_USER@$EXT_VM_IP:/opt/stack/tempest/*.html $JENKINS_WORKSPACE
  else
    echo ">>> ERROR: Run tempest step failed with error code ($return_code)"
    clean_up
    exit $return_code
  fi
}

# Change the build number
if [ "$NSX_BUILD_NO" != "default" ]; then
  echo ">>> Replacing nsx build with: $NSX_BUILD_NO..."
  sed -i "s/nsxtransformers = [0-9]\{7\}/nsxtransformers = $NSX_BUILD_NO/" $VDNET_DIR/$BUILD_FILE
fi 
if [ "$ESX_BUILD_NO" != "default" ]; then
  echo ">>> Replacing esx build with: $ESX_BUILD_NO..."
  sed -i "s/esx60 = [0-9]\{7\}/esx60 = $ESX_BUILD_NO/" $VDNET_DIR/$BUILD_FILE
fi 

is_existing_setup

EXT_VM_IP=$(cat $TESTBED_JSON | grep '"vm"' -A3 | awk -F '"' '{print $4}' | grep $IP_REGEX)
DEVSTACK_VM_IP=$(cat $TESTBED_JSON | grep ubuntu1404OpenStack-3 -a7 | awk -F '"' '{print $4}' | grep $IP_REGEX)

if [ $setup_exist -eq 0 ]; then
  python $JENKINS_DIR/tools/deployOpenStack.py -t $TESTBED_JSON -b $OS_BRANCH -k
  return_code=$?
  if [ $return_code -eq 0 ]; then
    echo ">>> OpenStack deployment SUCCESS!!!"
    run_tempest
  else
    echo ">>> ERROR: Return code from deployOpenStack is ($return_code)"
    clean_up
    exit $return_code    
  fi
else
  python $JENKINS_DIR/tools/deployOpenStack.py -t $TESTBED_JSON -b $OS_BRANCH -r -k
  return_code=$?
  if [ $return_code -eq 0 ]; then
    echo ">>> OpenStack restack SUCCESS!!!"
    run_tempest
  else
    echo ">>> ERROR: Return code from deployOpenStack is ($return_code)"
    clean_up
    exit $return_code    
  fi
fi

if [ "$CLEAN_UP" = true ]; then
  clean_up
fi

set +x
