#!/bin/bash

set -e

# Make sure there is only 1 argument passed
if [ "$#" -ne 1 ]; then
    echo "You must provide a new package name"
    exit 1
fi

# Make sure the new package name is not empty
if [ -z "$1" ]; then
    echo "You must provide a non-empty package name"
    exit 1
fi

# get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# get the current package name
PACKAGE=$($DIR/get_package_name.sh)

# Announce the renaming
echo "Renaming from '$PACKAGE' to '$1'"

# .gitignore
sed -i "s|$PACKAGE|$1|g" $DIR/../.gitignore

# Doxyfile
sed -i "s|$PACKAGE|$1|g" $DIR/../Doxyfile

# Makefile
sed -i "s|$PACKAGE|$1|g" $DIR/../Makefile

# setup.py
sed -i "s|$PACKAGE|$1|g" $DIR/../setup.py

# docs/Makefile
sed -i "s|$PACKAGE|$1|g" $DIR/../docs/Makefile

# docs/make.bat
sed -i "s|$PACKAGE|$1|g" $DIR/../docs/make.bat

# docs/source/conf.py
sed -i "s|$PACKAGE|$1|g" $DIR/../docs/source/conf.py
