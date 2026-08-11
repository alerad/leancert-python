# Releasing leancert-python

## 1. Release runtime dependencies

Release the minimum compatible `lean-runtime` version first. Then publish the
Bridge's multi-platform ready program and copy the final immutable OCI index
digest into `DEFAULT_BRIDGE_PROGRAM_REFERENCE` in `leancert/client.py`.

Do not copy Core, Lean, protocol, or capability versions into the SDK. Bridge
CI derives them from the resolved Lake graph and live binary handshake and
content-addresses them inside the program description. The SDK integration
contract must download the pinned digest and verify that embedded profile
against the running handshake before release.

The exact Bridge package reference remains the source-build fallback used for
replay audits and custom registered-enclosure profiles. Core, Bridge, Runtime,
and SDK versions remain independent.

## 2. Validate wheel build

Run CI workflow `Build Wheels` manually or open a PR.

For a local release build, start from a clean checkout or remove only the
generated packaging directories before building. Setuptools does not guarantee
that stale files already present under `build/` are removed:

```bash
rm -rf build dist leancert.egg-info
pip install -e ".[release]"
python -m build
python scripts/check_wheel.py dist/*.whl
twine check dist/*
```

## 3. Publish package

Create and push a tag matching the version in `pyproject.toml` (for example `v0.3.2`).

The publish job builds one pure Python wheel plus an sdist, verifies the wheel
on Linux, macOS, and Windows, and uploads both to PyPI.

## Notes

- Wheels contain no Lean or Bridge binaries.
- Wheels contain no SDK test suite or bytecode caches.
- Supply-chain identity comes from the content-addressed `lean-runtime`
  environment; mathematical compatibility comes from the Bridge handshake.
