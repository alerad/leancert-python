"""Independent verification of exported LeanCert projects."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, Literal

from lean_runtime import ExecutionPolicy, LeanRuntimeError, Runtime

from . import ast
from .client import LeanClient
from .exceptions import ProtocolViolation
from .protocol import (
    INTEGRAL_AUTHORITIES,
    SCALAR_ROOT_AUTHORITIES,
    ReplayBoundPayload,
    ReplayEventualPayload,
    ReplayIntegralPayload,
    ReplayKrawczykPayload,
    ReplayScalarRootPayload,
    ReplayStrictBoundPayload,
)

EXPORT_SCHEMA_VERSION = "leancert-export/1"
EXPORT_TARGET = "LeanCertExport"
EXPORT_MANIFEST = "artifact.json"
MAX_METADATA_BYTES = 10 * 1024 * 1024
REQUIRED_FILES = frozenset(
    {
        "LeanCertExport.lean",
        "lean-toolchain",
        "lakefile.toml",
        "claim.json",
        "certificate.json",
        "provenance.json",
    }
)
IGNORED_DISCOVERY_DIRECTORIES = frozenset(
    {".git", ".lake", ".venv", "venv", "build", "dist", "__pycache__"}
)
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
CLAIM_ID_PATTERN = re.compile(r"lc-ast-v[0-9]+:sha256:[0-9a-f]{64}")
TOOLCHAIN_PATTERN = re.compile(r"leanprover/lean4:v[0-9]+\.[0-9]+\.[0-9]+")
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
ENVIRONMENT_ID_PATTERN = re.compile(r"env_[0-9a-f]{64}")


class VerificationExitCode(IntEnum):
    SUCCESS = 0
    VERIFICATION_FAILED = 1
    INVALID_ARTIFACT = 2
    INFRASTRUCTURE_FAILURE = 3
    RESOURCE_LIMIT = 4


ArtifactStatus = Literal[
    "verified",
    "verification_failed",
    "invalid_artifact",
    "infrastructure_failure",
    "resource_limit",
]


@dataclass(frozen=True, slots=True)
class ArtifactVerification:
    path: str
    status: ArtifactStatus
    message: str
    claim_id: str | None = None
    trust_class: str | None = None
    certificate_digests: tuple[str, ...] = ()
    elapsed_seconds: float = 0.0
    build_output: str = ""

    @property
    def verified(self) -> bool:
        return self.status == "verified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "message": self.message,
            "claim_id": self.claim_id,
            "trust_class": self.trust_class,
            "certificate_digests": list(self.certificate_digests),
            "elapsed_seconds": self.elapsed_seconds,
            "build_output": self.build_output,
        }


@dataclass(frozen=True, slots=True)
class VerificationReport:
    artifacts: tuple[ArtifactVerification, ...]
    required_trust: str | None
    elapsed_seconds: float

    @property
    def verified(self) -> bool:
        return bool(self.artifacts) and all(item.verified for item in self.artifacts)

    @property
    def verified_count(self) -> int:
        return sum(item.verified for item in self.artifacts)

    @property
    def exit_code(self) -> VerificationExitCode:
        statuses = {item.status for item in self.artifacts}
        if not statuses:
            return VerificationExitCode.INVALID_ARTIFACT
        if "infrastructure_failure" in statuses:
            return VerificationExitCode.INFRASTRUCTURE_FAILURE
        if "resource_limit" in statuses:
            return VerificationExitCode.RESOURCE_LIMIT
        if "invalid_artifact" in statuses:
            return VerificationExitCode.INVALID_ARTIFACT
        if "verification_failed" in statuses:
            return VerificationExitCode.VERIFICATION_FAILED
        return VerificationExitCode.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "leancert-verification-report/1",
            "required_trust": self.required_trust,
            "verified": self.verified,
            "verified_count": self.verified_count,
            "artifact_count": len(self.artifacts),
            "elapsed_seconds": self.elapsed_seconds,
            "exit_code": int(self.exit_code),
            "artifacts": [item.to_dict() for item in self.artifacts],
        }


class ArtifactValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ValidatedArtifact:
    path: Path
    claim_id: str
    trust_class: str
    target: str
    certificate_digests: tuple[str, ...]
    environment_id: str | None
    runtime_package_ref: str | None


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ArtifactValidationError(f"required metadata is not a regular file: {path.name}")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ArtifactValidationError(f"cannot inspect {path.name}: {exc}") from exc
    if size > MAX_METADATA_BYTES:
        raise ArtifactValidationError(f"metadata file exceeds 10 MiB: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_pairs)
    except ArtifactValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactValidationError(f"cannot read {path.name}: {exc}") from exc


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ArtifactValidationError(f"cannot read {path.name}: {exc}") from exc


def _payload_digest(payload: Any) -> str:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ArtifactValidationError(f"certificate payload is not canonical JSON: {exc}") from exc
    return _sha256_bytes(encoded)


def write_export_manifest(
    directory: Path,
    *,
    claim_id: str,
    certificate_digests: tuple[str, ...],
) -> None:
    files = {name: file_digest(directory / name) for name in sorted(REQUIRED_FILES)}
    payload = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "claim_id": claim_id,
        "trust_class": "kernel",
        "target": EXPORT_TARGET,
        "certificate_digests": list(certificate_digests),
        "files": files,
    }
    (directory / EXPORT_MANIFEST).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def discover_exported_projects(paths: list[str | os.PathLike[str]]) -> tuple[Path, ...]:
    discovered: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve()
        if path.is_file():
            if path.name != EXPORT_MANIFEST:
                raise ArtifactValidationError(f"expected {EXPORT_MANIFEST}, got file: {path}")
            discovered.add(path.parent)
            continue
        if not path.exists():
            raise ArtifactValidationError(f"verification path does not exist: {path}")
        if not path.is_dir():
            raise ArtifactValidationError(f"verification path is not a directory: {path}")
        if (path / EXPORT_MANIFEST).is_file():
            discovered.add(path)
            continue
        for root, directories, files in os.walk(path, followlinks=False):
            directories[:] = sorted(
                name
                for name in directories
                if name not in IGNORED_DISCOVERY_DIRECTORIES
                and not (Path(root) / name).is_symlink()
            )
            if EXPORT_MANIFEST in files:
                project = Path(root).resolve()
                discovered.add(project)
                directories[:] = []
    return tuple(sorted(discovered, key=lambda item: str(item)))


def _certificate_entries(certificate: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(certificate, dict):
        raise ArtifactValidationError("certificate.json must contain an object")
    if "certificates" in certificate:
        entries = certificate["certificates"]
        if not isinstance(entries, list) or not entries:
            raise ArtifactValidationError("certificate.json certificates must be non-empty")
        if any(not isinstance(item, dict) for item in entries):
            raise ArtifactValidationError("certificate entries must be objects")
        return tuple(entries)
    return (certificate,)


def _validate_certificate(certificate: Any, claim_id: str) -> tuple[str, ...]:
    if not isinstance(certificate, dict) or certificate.get("claim_id") != claim_id:
        raise ArtifactValidationError("certificate claim_id does not match artifact claim_id")
    digests: list[str] = []
    for entry in _certificate_entries(certificate):
        required = {
            "schema_version",
            "payload_digest",
            "checker",
            "verifier",
            "verification_route",
            "payload",
        }
        if not required.issubset(entry):
            raise ArtifactValidationError(
                "certificate entry is missing authority or payload fields"
            )
        digest = entry["payload_digest"]
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise ArtifactValidationError("certificate payload_digest is malformed")
        if entry["verification_route"] != "compiled_checker":
            raise ArtifactValidationError("certificate verification route is not compiled_checker")
        if not all(isinstance(entry[name], str) and entry[name] for name in required - {"payload"}):
            raise ArtifactValidationError("certificate authority fields must be non-empty strings")
        payload = entry["payload"]
        if not isinstance(payload, dict):
            raise ArtifactValidationError("certificate payload must be an object")
        schema = entry["schema_version"]
        try:
            if schema == "bound-check/2":
                parsed_payload = ReplayBoundPayload.parse(payload)
            elif schema == "strict-bound-check/1":
                parsed_payload = ReplayStrictBoundPayload.parse(payload)
            elif schema == "krawczyk-check/1":
                parsed_payload = ReplayKrawczykPayload.parse(payload)
            elif schema == "eventual-bound-check/1":
                parsed_payload = ReplayEventualPayload.parse(payload)
            elif schema == "scalar-root-check/1":
                parsed_payload = ReplayScalarRootPayload.parse(payload)
            elif schema == "integral-check/1":
                parsed_payload = ReplayIntegralPayload.parse(payload)
            else:
                raise ArtifactValidationError(f"unsupported certificate schema: {schema!r}")
        except ProtocolViolation as exc:
            raise ArtifactValidationError(f"certificate payload is not canonical: {exc}") from exc
        if parsed_payload.digest != digest or _payload_digest(payload) != digest:
            raise ArtifactValidationError("certificate payload digest does not match its payload")

        if schema == "bound-check/2":
            assert isinstance(parsed_payload, ReplayBoundPayload)
            direction = parsed_payload.direction
            suffix = "Upper" if direction == "upper" else "Lower" if direction == "lower" else None
            if suffix is None:
                raise ArtifactValidationError("bound certificate payload family is malformed")
            expected_checker = f"LeanCert.Validity.GlobalOpt.checkGlobal{suffix}Bound"
            expected_verifier = (
                "LeanCert.Validity.GlobalOpt.verify_global_upper_bound"
                if direction == "upper"
                else "LeanCert.Validity.GlobalOpt.verify_global_lower_bound"
            )
        elif schema == "strict-bound-check/1":
            assert isinstance(parsed_payload, ReplayStrictBoundPayload)
            upper = parsed_payload.relation == "lt"
            expected_checker = (
                "LeanCert.Validity.GlobalOpt.checkGlobalUpperBound"
                if upper
                else "LeanCert.Validity.GlobalOpt.checkGlobalLowerBound"
            )
            expected_verifier = (
                "LeanCert.Validity.GlobalOpt.verify_global_upper_bound"
                if upper
                else "LeanCert.Validity.GlobalOpt.verify_global_lower_bound"
            )
        elif schema == "krawczyk-check/1":
            expected_checker = "LeanCert.Engine.krawczykCheck"
            expected_verifier = "LeanCert.Validity.verify_unique_system_root"
        elif schema == "eventual-bound-check/1":
            expected_checker = "LeanCert.Validity.checkReciprocalPowerUpper"
            expected_verifier = "LeanCert.Validity.verify_reciprocal_power_upper"
        elif schema == "scalar-root-check/1":
            assert isinstance(parsed_payload, ReplayScalarRootPayload)
            expected_checker, expected_verifier = SCALAR_ROOT_AUTHORITIES[parsed_payload.claim]
        else:
            assert schema == "integral-check/1"
            assert isinstance(parsed_payload, ReplayIntegralPayload)
            expected_checker, expected_verifier = INTEGRAL_AUTHORITIES[parsed_payload.relation]
        if entry["checker"] != expected_checker or entry["verifier"] != expected_verifier:
            raise ArtifactValidationError("certificate authority does not match its schema")
        digests.append(digest)
    return tuple(digests)


def _validate_project(path: Path, required_trust: str | None) -> _ValidatedArtifact:
    manifest = _read_json(path / EXPORT_MANIFEST)
    expected_fields = {
        "schema_version",
        "claim_id",
        "trust_class",
        "target",
        "certificate_digests",
        "files",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_fields:
        raise ArtifactValidationError("artifact manifest fields do not match leancert-export/1")
    if manifest["schema_version"] != EXPORT_SCHEMA_VERSION:
        raise ArtifactValidationError("unsupported artifact schema version")
    claim_id = manifest["claim_id"]
    if not isinstance(claim_id, str) or CLAIM_ID_PATTERN.fullmatch(claim_id) is None:
        raise ArtifactValidationError("artifact claim_id is malformed")
    trust_class = manifest["trust_class"]
    if trust_class != "kernel":
        raise ArtifactValidationError("artifact trust_class is not kernel")
    if required_trust is not None and trust_class != required_trust:
        raise ArtifactValidationError(
            f"artifact trust class {trust_class!r} does not satisfy {required_trust!r}"
        )
    if manifest["target"] != EXPORT_TARGET:
        raise ArtifactValidationError("artifact build target is not LeanCertExport")
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != REQUIRED_FILES:
        raise ArtifactValidationError("artifact file manifest is incomplete")
    for name in sorted(REQUIRED_FILES):
        expected = files[name]
        file_path = path / name
        if file_path.is_symlink() or not file_path.is_file():
            raise ArtifactValidationError(f"artifact file is missing or symlinked: {name}")
        if not isinstance(expected, str) or SHA256_PATTERN.fullmatch(expected) is None:
            raise ArtifactValidationError(f"artifact file digest is malformed: {name}")
        try:
            actual = file_digest(file_path)
        except OSError as exc:
            raise ArtifactValidationError(f"cannot hash artifact file {name}: {exc}") from exc
        if actual != expected:
            raise ArtifactValidationError(f"artifact file digest mismatch: {name}")

    claim_payload = _read_json(path / "claim.json")
    try:
        claim = ast.decode_canonical_strict(claim_payload)
        computed_claim_id = str(ast.semantic_digest(claim))
    except Exception as exc:
        raise ArtifactValidationError(
            f"claim.json is not a canonical semantic claim: {exc}"
        ) from exc
    if computed_claim_id != claim_id:
        raise ArtifactValidationError("claim digest does not match claim.json")

    certificate_digests = _validate_certificate(_read_json(path / "certificate.json"), claim_id)
    manifest_digests = manifest["certificate_digests"]
    if not isinstance(manifest_digests, list) or tuple(manifest_digests) != certificate_digests:
        raise ArtifactValidationError("artifact certificate digests do not match certificate.json")

    provenance = _read_json(path / "provenance.json")
    if not isinstance(provenance, dict):
        raise ArtifactValidationError("provenance.json must contain an object")
    toolchain = provenance.get("lean_toolchain")
    source = provenance.get("leancert_source")
    revision = provenance.get("leancert_resolved_revision")
    environment_id = provenance.get("environment_id")
    runtime_package_ref = provenance.get("runtime_package_ref")
    if not isinstance(toolchain, str) or TOOLCHAIN_PATTERN.fullmatch(toolchain) is None:
        raise ArtifactValidationError("provenance does not pin a released Lean toolchain")
    if source != "https://github.com/alerad/leancert.git":
        raise ArtifactValidationError("provenance does not use the canonical LeanCert source")
    if not isinstance(revision, str) or REVISION_PATTERN.fullmatch(revision) is None:
        raise ArtifactValidationError("provenance does not pin a full LeanCert revision")
    has_environment = isinstance(environment_id, str) and (
        ENVIRONMENT_ID_PATTERN.fullmatch(environment_id) is not None
    )
    has_package = isinstance(runtime_package_ref, str) and (
        re.fullmatch(r"github:alerad/leancert-bridge@[0-9a-f]{40,64}", runtime_package_ref)
        is not None
    )
    if not has_environment and not has_package:
        raise ArtifactValidationError(
            "provenance pins neither a runtime environment nor an exact Bridge package"
        )
    if _read_text(path / "lean-toolchain").strip() != toolchain:
        raise ArtifactValidationError("lean-toolchain disagrees with provenance")
    lakefile = _read_text(path / "lakefile.toml")
    if f'git = "{source}"' not in lakefile or f'rev = "{revision}"' not in lakefile:
        raise ArtifactValidationError("lakefile dependency disagrees with provenance")
    lean_source = _read_text(path / "LeanCertExport.lean")
    if lean_source.count("#assert_trust kernel") < len(certificate_digests):
        raise ArtifactValidationError("Lean source lacks a kernel trust assertion per certificate")
    if lean_source.count("decide +kernel") < len(certificate_digests):
        raise ArtifactValidationError("Lean source lacks fixed-certificate kernel reduction")
    return _ValidatedArtifact(
        path,
        claim_id,
        trust_class,
        manifest["target"],
        certificate_digests,
        environment_id if has_environment else None,
        runtime_package_ref if has_package else None,
    )


def verify_exported_projects(
    paths: list[str | os.PathLike[str]],
    *,
    require_trust: Literal["kernel"] | None = "kernel",
    runtime: Runtime | None = None,
    timeout: float = 900,
    fail_fast: bool = False,
) -> VerificationReport:
    """Validate artifacts and kernel-check them in their exact managed environments."""
    started = time.monotonic()
    if not paths:
        paths = ["."]
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    results: list[ArtifactVerification] = []
    try:
        projects = discover_exported_projects(paths)
    except ArtifactValidationError as exc:
        return VerificationReport(
            (ArtifactVerification(str(Path(paths[0])), "invalid_artifact", str(exc)),),
            require_trust,
            time.monotonic() - started,
        )
    if not projects:
        return VerificationReport(
            (
                ArtifactVerification(
                    str(Path(paths[0]).expanduser().resolve()),
                    "invalid_artifact",
                    f"no {EXPORT_MANIFEST} files found",
                ),
            ),
            require_trust,
            time.monotonic() - started,
        )

    selected_runtime = runtime or Runtime()

    for project in projects:
        item_started = time.monotonic()
        try:
            validated = _validate_project(project, require_trust)
        except ArtifactValidationError as exc:
            results.append(
                ArtifactVerification(
                    str(project),
                    "invalid_artifact",
                    str(exc),
                    elapsed_seconds=time.monotonic() - item_started,
                )
            )
            if fail_fast:
                break
            continue
        try:
            if validated.environment_id is not None:
                environment = selected_runtime.environment(validated.environment_id)
            else:
                assert validated.runtime_package_ref is not None
                environment = LeanClient(
                    package_ref=validated.runtime_package_ref,
                    runtime=runtime,
                    resolution_timeout_seconds=timeout,
                ).environment
            execution = environment.check_files(
                {"LeanCertExport.lean": _read_text(project / "LeanCertExport.lean")},
                entrypoint="LeanCertExport.lean",
                policy=ExecutionPolicy(
                    timeout_seconds=timeout,
                    max_output_bytes=10_000_000,
                ),
            )
        except LeanRuntimeError as exc:
            results.append(
                ArtifactVerification(
                    str(project),
                    "infrastructure_failure",
                    f"could not open or execute the managed environment: {exc}",
                    validated.claim_id,
                    validated.trust_class,
                    validated.certificate_digests,
                    time.monotonic() - item_started,
                )
            )
        else:
            output = execution.stdout + execution.stderr
            if execution.timed_out:
                status: ArtifactStatus = "resource_limit"
                message = f"kernel check exceeded {timeout:g} seconds"
            elif execution.ok:
                status = "verified"
                message = "kernel checked in the originating managed environment"
            else:
                status = "verification_failed"
                message = "managed kernel check rejected the artifact"
            results.append(
                ArtifactVerification(
                    str(project),
                    status,
                    message,
                    validated.claim_id,
                    validated.trust_class,
                    validated.certificate_digests,
                    execution.elapsed_seconds,
                    output,
                )
            )
        if fail_fast and not results[-1].verified:
            break
    return VerificationReport(tuple(results), require_trust, time.monotonic() - started)


__all__ = [
    "ArtifactStatus",
    "ArtifactVerification",
    "EXPORT_MANIFEST",
    "EXPORT_SCHEMA_VERSION",
    "VerificationExitCode",
    "VerificationReport",
    "discover_exported_projects",
    "file_digest",
    "verify_exported_projects",
    "write_export_manifest",
]
