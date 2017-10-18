#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

# Get the repo and build directories, go to the build directory
repo_dir=$(dirname $0)
build_dir=$1
mkdir -p $build_dir
cd $build_dir

# Create extra symlinks
ln -s $repo_dir/src/ $build_dir/include
ln -s $repo_dir/src/ $build_dir/src
