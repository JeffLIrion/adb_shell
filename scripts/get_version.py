#!/usr/bin/env python3
import sys

__license__ = "Unlicense"

if __name__ == "__main__":
    import setuptools_scm

    v = setuptools_scm.get_version(local_scheme="no-local-version").rsplit(".", 1)
    if not v:
        print("Version could not be determined", file=sys.stderr)
        sys.exit(1)
    if v[-1].startswith("dev"):
        v = v[:-1]
    print(".".join(v))
