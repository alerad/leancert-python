# Releasing leancert-python

## 1. Release runtime dependencies

Release the minimum compatible `lean-runtime` version first. Update the exact
Bridge package reference in `leancert/client.py` only when the SDK needs a new
mathematical Bridge contract. Core, Bridge, runtime, and SDK versions remain
independent; the runtime lock records their exact revisions together.

## 2. Validate wheel build

Run CI workflow `Build Wheels` manually or open a PR.

## 3. Publish package

Create and push a tag matching the version in `pyproject.toml` (for example `v0.3.2`).

The publish job builds one pure Python wheel plus an sdist, verifies the wheel
on Linux, macOS, and Windows, and uploads both to PyPI.

## Notes

- Wheels contain no Lean or Bridge binaries.
- Supply-chain identity comes from the content-addressed `lean-runtime`
  environment; mathematical compatibility comes from the Bridge handshake.
