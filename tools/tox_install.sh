#! /bin/sh

set -e

DIR=$(dirname $0)
${DIR}/tox_install_project.sh neutron neutron $*
${DIR}/tox_install_project.sh networking-l2gw networking_l2gw $*
${DIR}/tox_install_project.sh networking-sfc networking_sfc $*
${DIR}/tox_install_project.sh neutron-lbaas neutron_lbaas $*
${DIR}/tox_install_project.sh vmware-nsxlib vmware_nsxlib $*
${DIR}/tox_install_project.sh neutron-fwaas neutron_fwaas $*
${DIR}/tox_install_project.sh neutron-dynamic-routing neutron-dynamic-routing $*
${DIR}/tox_install_project.sh neutron-vpnaas neutron-vpnaas $*

CONSTRAINTS_FILE=$1
shift

install_cmd="pip install"
if [ $CONSTRAINTS_FILE != "unconstrained" ]; then
    install_cmd="$install_cmd -c$CONSTRAINTS_FILE"
fi

$install_cmd -U $*
