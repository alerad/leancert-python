"""Reject release wheels containing development or platform-specific debris."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path, PurePosixPath


def check_wheel(path: Path) -> None:
    if not path.name.endswith("-py3-none-any.whl"):
        raise ValueError(f"wheel is not tagged as pure Python: {path.name}")

    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        forbidden = []
        for name in names:
            parts = PurePosixPath(name).parts
            if (
                parts[:2] in (("leancert", "bin"), ("leancert", "tests"))
                or name.endswith((".pyc", ".pyo"))
                or "__pycache__" in parts
            ):
                forbidden.append(name)

        if forbidden:
            formatted = "\n".join(f"  - {name}" for name in forbidden)
            raise ValueError(f"wheel contains forbidden files:\n{formatted}")
        if "leancert/py.typed" not in names:
            raise ValueError("wheel is missing leancert/py.typed")

        wheel_metadata = [name for name in names if name.endswith(".dist-info/WHEEL")]
        if len(wheel_metadata) != 1:
            raise ValueError("wheel must contain exactly one WHEEL metadata file")
        metadata = archive.read(wheel_metadata[0]).decode("utf-8")
        if "Root-Is-Purelib: true" not in metadata:
            raise ValueError("wheel metadata does not declare a pure-Python wheel")


def main(paths: list[str]) -> int:
    if not paths:
        print("usage: python scripts/check_wheel.py dist/*.whl", file=sys.stderr)
        return 2
    for raw_path in paths:
        path = Path(raw_path)
        check_wheel(path)
        print(f"wheel contents ok: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
