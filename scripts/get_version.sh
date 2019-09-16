#!/bin/bash

set -e

# get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

RSTRIP="'*"
LSTRIP="*'"

# get the package name
PACKAGE=$($DIR/get_package_name.sh)

# get the current version
VERSION_LINE=$(grep '__version__' "$DIR/../$PACKAGE/__init__.py" || echo '')
VERSION_TEMP=${VERSION_LINE%"'"}

VERSION=${VERSION_TEMP##$LSTRIP}

# Make sure `VERSION` is not empty
if [ -z "$VERSION" ]; then
    echo "Version could not be determined" >&2
    exit 1
fi

echo "$VERSION"
