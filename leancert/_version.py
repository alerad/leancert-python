"""Package version lookup with a source-tree fallback."""

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    __version__ = version("leancert")
except PackageNotFoundError:  # Running directly from an unpackaged checkout.
    project = (Path(__file__).parent.parent / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', project, re.MULTILINE)
    __version__ = match.group(1) if match else "0+unknown"
