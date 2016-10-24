#!/bin/bash

set -o errexit
set -o pipefail

CDEFAULT='\e[39m'
CRED='\e[31m'
CYELLOW='\e[33m'
CGREEN='\e[32m'

echo -e "${CGREEN} ACCL build process STARTED${CDEFAULT}"

SCRIPT_DIR=$(dirname $0)
cd $SCRIPT_DIR
SCRIPT_DIR=$(pwd)

if [ -e /opt/3rd_party ]; then
	for system in linux android linux_x86; do
        cd $SCRIPT_DIR/src
        make -f Makefile.$system clean all > /dev/null
        mv accl.{a,o} ../prebuilt/${system}
    done
else
	echo "Please run FRAMEWORK/select-tool-version.sh -t 3rd_party -v VERSION"
fi

echo -e "${CGREEN} ACCL build process COMPLETED${CDEFAULT}\n"

TREE_OK=$(which tree)
[ "${TREE_OK}" != '' ] && tree -h ${SCRIPT_DIR}/prebuilt
