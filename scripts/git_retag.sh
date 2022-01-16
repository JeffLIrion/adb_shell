#!/bin/bash

# get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# get the current version
VERSION=$(python3 $DIR/get_version.py)

# Announce the tag
echo "Re-tagging v$VERSION"

cd $DIR/..

# https://stackoverflow.com/a/8044605
git push origin ":refs/tags/v$VERSION"
git tag -fa "v$VERSION"
git push origin master --tags
