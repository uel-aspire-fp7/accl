#!/bin/bash

SCRIPT_DIR=$(dirname $0)
cd $SCRIPT_DIR
SCRIPT_DIR=$(pwd)

if [ -e /opt/3rd_party ]; then
	for system in linux android serverlinux; do
	    cd $SCRIPT_DIR

        [ -e prebuilt/$system ] || mkdir -p prebuilt/$system

        cd $SCRIPT_DIR/src
        make -f Makefile.$system clean && \
        make -f Makefile.$system && \
        cp accl.o ../prebuilt/$system && \
        cp accl.a ../prebuilt/$system
    done
else
	echo "Please run FRAMEWORK/select-tool-version.sh -t 3rd_party -v VERSION"
fi