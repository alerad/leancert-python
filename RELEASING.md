# Releasing leancert-python

## 1. Pick bridge release

Update `bridge-version.txt` to the bridge tag to bundle (for example `bridge-v4.31.0`).

## 2. Validate wheel build

Run CI workflow `Build Wheels` manually or open a PR.

## 3. Publish package

Create and push a tag matching the version in `pyproject.toml` (for example `v0.3.2`).

The publish job builds wheels, verifies a smoke test, and uploads to PyPI.

## Notes

- Wheels are built by downloading `lean_bridge` assets from `alerad/leancert-bridge` releases.
- Runtime compatibility is enforced via bridge `get_info` and `bridge_api_version` major check.
