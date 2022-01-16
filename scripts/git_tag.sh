#!/bin/bash

# get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# get the current version
VERSION=$(python3 $DIR/get_version.py)

# Announce the tag
echo "Creating tag v$VERSION"

cd $DIR/..
git tag v$VERSION -m "v$VERSION"
git push --tags
