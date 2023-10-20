#!/bin/bash

# get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# get the current version
VERSION=$($DIR/get_version.sh)


# Announce the tag
echo "Creating tag v$VERSION"

cd $DIR/..
git tag v$VERSION -m "v$VERSION"
git push --tags
