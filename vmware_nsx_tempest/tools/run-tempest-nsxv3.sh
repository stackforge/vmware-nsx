#!/usr/bin/env bash

#set -e

ROOT_DIR=/opt/stack
export TOOLS_PATH=$ROOT_DIR/tempest
VENV=$TOOLS_PATH/.venv/bin/activate
TEST_SUITE_PATH=$ROOT_DIR/vmware-nsx/vmware_nsx_tempest/tests/suites/nsxv3

function usage {
  echo "Usage: $0 [OPTIONS]..."
  echo "Run tempest test suite(s)"
  echo ""
  echo "  -h, --help              Print usage message"
  echo "  -e, --set-env           Setup environment before running tempest"
  echo "  -a, --all               Run all tempest test suites"
  echo "  -n, --api-network       Run tempest api network suite"
  echo "  -s, --scenario          Run tempest scenario suite"
  echo "  -i, --nsxv3-api         Run NSXv3 specific api suite"
  echo "  -o, --nsxv3-scenario    Run NSXv3 specific scenario suite"
  echo "  -b, --nsx-build         NSX build number"
}

function process_options {
  i=1
  while [ $i -le $# ]; do
    case "${!i}" in
      -h|--help) usage;;
      -e|--set-env) set_env=1;;
      -a|--all) api_network_suite=1; scenario_suite=1; nsx_api_suite=1; nsx_scenario_suite=1;;
      -n|--api-network) api_network_suite=1;;
      -s|--scenario) scenario_suite=1;;
      -i|--nsx-api) nsx_api_suite=1;;
      -o|--nsx-scenario) nsx_scenario_suite=1;;
      -b|--nsx-build)
        (( i++ ))
        nsx_build=${!i};;
    esac
    (( i++ ))
  done
}

function setup_env {
  # get the gateway of mgmt network
  MGMT_GW=$(route -n | grep 10.0.0.0 | awk '{print $2}')
  sudo route add default gw $MGMT_GW eth0
  sudo ifconfig eth1:1 172.24.4.1/24
  sudo apt-get update && apt-get -y upgrade
  sudo aptitude reinstall perl perl-base perl-modules
  sudo apt-get -y install python-pip python-dev libffi-dev libssl-dev git
  
  # install virtualenv
  sudo pip install virtualenv
  
  # install upstream tempest
  mkdir -p $ROOT_DIR
  pushd $ROOT_DIR
  git clone https://github.com/openstack/tempest.git tempest
  git clone https://github.com/openstack/vmware-nsx
  git clone https://github.com/openstack/oslo-incubator
  python $ROOT_DIR/oslo-incubator/tools/install_venv.py
  
  # install vmware-nsx-tempest repo for /opt/stack/os-tempest
  pushd $ROOT_DIR/tempest
  source $VENV
  pip install -e $ROOT_DIR/vmware-nsx

  # copy tempest.conf
  cp ~/tempest.conf etc/
  popd
  popd
}

function run_tempest {
  pushd $ROOT_DIR/tempest
  if [ $set_env -ne 1 ]; then
    source $VENV
  fi
  # run tempest test suite
  ./run_tempest.sh -- --load-list=$TEST_SUITE_PATH/$1
  
  # upload the tempest test results
  #DATE=`date +"%Y%m%d-%H%M"`
  #python subunit2html.py .testrepository/0 $DATE-$nsx_build-$1.html
  python subunit2html.py .testrepository/0 $1.html
  #DATE=`date +"%Y%m%d-%H%M"`
  #scp tempest_results.html root@10.34.57.161:/var/www/logs/nsxt/$DATE-$nsx_build-$1.html
  clean_up
  popd
}

function clean_up {
  # cleanup the test results
  rm -rf .testrepository
}

set_env=0
all=0
api_network_suite=0
scenario_suite=0
nsx_api_suite=0
nsx_scenario_suite=0
nsx_build=""

process_options $@

if [ $set_env -eq 1 ]; then
  setup_env
fi

declare -a suite_arr=("tempest-api-network" "tempest-scenario" "nsxv3-api" "nsxv3-scenario")

if [ $all -eq 1 ]; then
  for suite in "${suite_arr[@]}"; do
    run_tempest "$suite"
  done
else
  if [ $api_network_suite -eq 1 ]; then
    run_tempest "tempest-api-network"
  fi
  if [ $scenario_suite -eq 1 ]; then
    run_tempest "tempest-scenario"
  fi
  if [ $nsx_api_suite -eq 1 ]; then
    run_tempest "nsxv3-api"
  fi
  if [ $nsx_scenario_suite -eq 1 ]; then
    run_tempest "nsxv3-scenario"
  fi
fi
