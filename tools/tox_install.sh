#! /bin/sh

set -e

CONSTRAINTS_FILE=$1
shift

install_cmd="pip install"
if [ $CONSTRAINTS_FILE != "unconstrained" ]; then
    install_cmd="$install_cmd -c$CONSTRAINTS_FILE"
fi

$install_cmd -U $*
