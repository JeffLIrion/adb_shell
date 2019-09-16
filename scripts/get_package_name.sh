#!/bin/bash

set -e

# get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

RSTRIP="'*"
LSTRIP="*'"

# get the package name
PACKAGE_LINE=$(grep 'name=' $DIR/../setup.py || echo '')
PACKAGE_TEMP=${PACKAGE_LINE%$RSTRIP}
PACKAGE=${PACKAGE_TEMP##$LSTRIP}

# Make sure `PACKAGE` is not empty
if [ -z "$PACKAGE" ]; then
    echo "Package name could not be determined" >&2
    exit 1
fi

echo "$PACKAGE"
