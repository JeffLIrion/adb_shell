#!/usr/bin/env python3
import sys
import typing
from pathlib import Path

import tomli

__license__ = "Unlicense"
__copyright__ = """
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this software, either in source code form or as a compiled binary, for any purpose, commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this software dedicate any and all copyright interest in the software to the public domain. We make this dedication for the benefit of the public at large and to the detriment of our heirs and successors. We intend this dedication to be an overt act of relinquishment in perpetuity of all present and future rights to this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org/>
"""


def extractFromPEP621(pyproject) -> None:
    project = pyproject.get("project", None)
    if isinstance(project, dict):
        return project.get("name", None)

    return None


def getPackageName(rootDir: Path) -> str:
    tomlPath = Path(rootDir / "pyproject.toml")

    with tomlPath.open("rb") as f:
        pyproject = tomli.load(f)

    fromPEP621 = extractFromPEP621(pyproject)
    if fromPEP621:
        return fromPEP621


def main():
    if len(sys.argv) > 1:
        p = sys.argv[1]
    else:
        p = "."
    pn = getPackageName(Path(p))
    if pn:
        print(pn, file=sys.stdout)
    else:
        print("Package name could not be determined", file=sys.stderr)


if __name__ == "__main__":
    main()
