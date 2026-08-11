# LeanCert v2 SDK - Client
# Copyright (c) 2024 LeanCert Contributors. All rights reserved.

"""
Low-level client for communication with the Lean kernel.

This module handles managed Lean execution and the line-delimited JSON protocol.
It should not be used directly by end users - use the Solver class instead.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import replace
from fractions import Fraction
from pathlib import Path
from typing import Any

from lean_runtime import (
    Environment,
    ExecutionPolicy,
    ExecutionResult,
    InteractiveSession,
    ReadyProgram,
    Runtime,
)
from lean_runtime import EnvironmentError as RuntimeEnvironmentError

from .domain import Interval
from .enclosures import EnclosureEnvironment, EnclosureProfile
from .exceptions import BridgeError, BridgeRemoteError, ProtocolViolation
from .protocol import (
    BoundOperationOutcome,
    BridgeHandshake,
    EventualOperationOutcome,
    StrictBoundOperationOutcome,
    SystemRootOperationOutcome,
)


def _bridge_core_expression(value: dict[str, Any]) -> dict[str, Any]:
    from .expression_codec import lower_bridge_expression

    return lower_bridge_expression(value)


DEFAULT_BRIDGE_SOURCE_REVISION = "270dbc5e5c7dfd9d5dfd57981514eb95874980d1"
DEFAULT_BRIDGE_PACKAGE_REF = f"github:alerad/leancert-bridge@{DEFAULT_BRIDGE_SOURCE_REVISION}"
DEFAULT_BRIDGE_PROGRAM_LIBRARY = "ghcr.io/alerad/leancert-bridge-programs"
DEFAULT_BRIDGE_PROGRAM_REFERENCE = (
    "sha256:a9a53f1eae587b83c32a0df61e592f4b50180d49033f3b41b83603893ad077c5"
)
DEFAULT_RUNTIME_LIBRARIES = ("ghcr.io/alerad/leancert-runtime",)
DEFAULT_BRIDGE_COMMAND = ("lake", "exe", "@LeanCertBridge/lean_bridge")
DEFAULT_ARTIFACT_COMMAND = (
    "lake",
    "exe",
    "@LeanCertBridge/lean_bridge_runtime_prepare",
)
_PROGRAM_PROFILE_KEYS = frozenset(
    {
        "lean.toolchain",
        "leancert.bridge.revision",
        "leancert.bridge.version",
        "leancert.capability.digest",
        "leancert.core.revision",
        "leancert.core.version",
        "leancert.protocol.version",
    }
)


def _program_profile(program: ReadyProgram, *, required: bool) -> Mapping[str, str] | None:
    value = getattr(program.description, "provenance", None)
    if not value:
        if required:
            raise BridgeError("Pinned Bridge program does not contain a verified stack profile")
        return None
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) and isinstance(item, str) and item for key, item in value.items()
    ):
        raise BridgeError("Bridge program contains malformed stack provenance")
    missing = _PROGRAM_PROFILE_KEYS - set(value)
    if missing:
        raise BridgeError(
            "Bridge program stack profile is incomplete: " + ", ".join(sorted(missing))
        )
    if value["leancert.bridge.revision"] != program.description.source_revision:
        raise BridgeError("Bridge program profile disagrees with its source revision")
    if any(
        re.fullmatch(r"[0-9a-f]{40,64}", value[key]) is None
        for key in ("leancert.bridge.revision", "leancert.core.revision")
    ):
        raise BridgeError("Bridge program profile contains a non-exact source revision")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value["leancert.capability.digest"]) is None:
        raise BridgeError("Bridge program profile contains an invalid capability identity")
    if value["lean.toolchain"] != program.description.toolchain:
        raise BridgeError("Bridge program profile disagrees with its Lean toolchain")
    capability_id = getattr(program.description, "capability_id", None)
    if capability_id != value["leancert.capability.digest"]:
        raise BridgeError("Bridge program profile disagrees with its capability identity")
    return value


def _validate_profile_handshake(profile: Mapping[str, str], contract: BridgeHandshake) -> None:
    expected = {
        "leancert.bridge.version": contract.bridge_version,
        "leancert.capability.digest": contract.capability_digest,
        "leancert.core.version": contract.leancert_version,
        "leancert.protocol.version": str(contract.protocol_version),
    }
    mismatches = [
        key for key, actual in expected.items() if actual is None or profile.get(key) != actual
    ]
    if not profile["lean.toolchain"].endswith(f":v{contract.lean_version}"):
        mismatches.append("lean.toolchain")
    if mismatches:
        raise ProtocolViolation(
            "Bridge program profile disagrees with its live handshake: "
            + ", ".join(sorted(mismatches))
        )


def _new_default_runtime() -> Runtime:
    """Prefer LeanCert's downloadable environments while honoring user policy."""
    if "LEAN_RUNTIME_LIBRARIES" in os.environ:
        return Runtime()
    return Runtime(libraries=DEFAULT_RUNTIME_LIBRARIES)


_DEFAULT_RUNTIME = _new_default_runtime()
_DEFAULT_ENVIRONMENTS: dict[tuple[str, tuple[str, ...]], Environment] = {}
_DEFAULT_ENVIRONMENTS_LOCK = threading.Lock()


class LeanClient:
    """
    Low-level client for the Lean math kernel.

    Uses :mod:`lean_runtime` to resolve, build, cache, and execute the Bridge in
    a content-addressed environment. Communication uses the Bridge's versioned
    line-delimited JSON protocol over a managed interactive session.

    This class manages the interactive-session lifecycle and should be used as a
    context manager to ensure proper cleanup.

    Example:
        with LeanClient() as client:
            result = client.call('ping', {})
    """

    def __init__(
        self,
        package_ref: str = DEFAULT_BRIDGE_PACKAGE_REF,
        *,
        runtime: Runtime | None = None,
        environment: Environment | None = None,
        program: ReadyProgram | None = None,
        execution_policy: ExecutionPolicy | None = None,
        resolution_timeout_seconds: float = 3600,
        artifact_command: Sequence[str] = DEFAULT_ARTIFACT_COMMAND,
        command: Sequence[str] = DEFAULT_BRIDGE_COMMAND,
        enclosure_profile: str | Path | EnclosureProfile | None = None,
        program_library: str = DEFAULT_BRIDGE_PROGRAM_LIBRARY,
        program_reference: str = DEFAULT_BRIDGE_PROGRAM_REFERENCE,
        require_program_profile: bool | None = None,
    ):
        """
        Initialize the client.

        Args:
            package_ref: Exact Bridge Git reference managed by ``lean-runtime``.
            runtime: Optional runtime instance, useful for a custom cache/backend.
            environment: Optional pre-built environment. This is the extension
                point for downstream profiled Bridge executables.
            program: Optional pre-built ready program, primarily for testing or
                an explicitly managed runtime profile.
            execution_policy: Resource policy for the interactive Bridge session.
            resolution_timeout_seconds: Maximum time allowed for first-use Lake
                dependency resolution. Cold Mathlib clones can exceed the
                runtime's shorter general-purpose default on slow networks.
            artifact_command: Managed hydration command retained in the exact
                environment lock and run before the environment build. Pass an
                empty sequence for a Bridge package without external artifacts.
            command: Command to start inside the managed environment.
            program_library: OCI library containing ready Bridge programs.
            program_reference: Immutable digest or legacy revision reference.
            require_program_profile: Require content-addressed stack provenance.
                Digest references enable this automatically.
        """
        if not package_ref:
            raise ValueError("package_ref must not be empty")
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise ValueError("command must contain non-empty strings")
        if any(not isinstance(part, str) or not part for part in artifact_command):
            raise ValueError("artifact_command must contain non-empty strings")
        if (
            isinstance(resolution_timeout_seconds, bool)
            or not isinstance(resolution_timeout_seconds, (int, float))
            or not math.isfinite(resolution_timeout_seconds)
            or resolution_timeout_seconds <= 0
        ):
            raise ValueError("resolution_timeout_seconds must be a finite positive number")
        self.package_ref = package_ref
        self.runtime = runtime or _DEFAULT_RUNTIME
        if environment is not None and program is not None:
            raise ValueError("environment and program are mutually exclusive")
        self._uses_default_runtime = runtime is None and environment is None and program is None
        self._environment = environment
        self._program = program
        self.program_library = program_library
        self.program_reference = program_reference
        self.require_program_profile = (
            program_reference.startswith("sha256:")
            if require_program_profile is None
            else require_program_profile
        )
        self.execution_policy = execution_policy or ExecutionPolicy(
            timeout_seconds=3600,
            max_output_bytes=10_000_000,
        )
        self.resolution_timeout_seconds = float(resolution_timeout_seconds)
        self.artifact_command = tuple(artifact_command)
        self.command = tuple(command)
        self.enclosure_profile = (
            enclosure_profile
            if isinstance(enclosure_profile, EnclosureProfile)
            else None
            if enclosure_profile is None
            else EnclosureProfile.load(enclosure_profile)
        )
        self._session: InteractiveSession | None = None
        self.execution_result: ExecutionResult | None = None
        self._request_id = 0
        self._contract_checked = False
        self._bridge_info: dict[str, Any] | None = None
        self._bridge_contract: BridgeHandshake | None = None
        self._io_lock = threading.RLock()
        self._enclosures: EnclosureEnvironment | None = None

    @property
    def uses_ready_program(self) -> bool:
        """Whether ordinary Bridge execution uses the small precompiled program."""
        return self.enclosure_profile is None and self._environment is None

    @property
    def program(self) -> ReadyProgram:
        """Return the ready-to-run Bridge program, downloading it on first use."""
        if self.enclosure_profile is not None:
            raise BridgeError("registered enclosure profiles require a full managed environment")
        if self._program is None:
            self._program = self.runtime.download_program(
                self.program_library,
                self.program_reference,
                expected_source_revision=(
                    None
                    if self.program_reference.startswith("sha256:")
                    else DEFAULT_BRIDGE_SOURCE_REVISION
                ),
            )
        _program_profile(self._program, required=self.require_program_profile)
        return self._program

    @property
    def environment(self) -> Environment:
        """Return the exact managed environment, resolving it on first use."""
        if self._environment is None:
            if self._uses_default_runtime:
                with _DEFAULT_ENVIRONMENTS_LOCK:
                    cache_key = (self.package_ref, self.artifact_command)
                    self._environment = _DEFAULT_ENVIRONMENTS.get(cache_key)
                    if self._environment is None:
                        self._environment = self._resolve_environment()
                        _DEFAULT_ENVIRONMENTS[cache_key] = self._environment
            else:
                self._environment = self._resolve_environment()
        return self._environment

    def _resolve_environment(self) -> Environment:
        """Resolve and materialize the exact Bridge environment once."""
        if not self.artifact_command:
            return self.runtime.open_references(
                [self.package_ref], timeout=self.resolution_timeout_seconds
            )
        alias_material = json.dumps(
            {
                "package_ref": self.package_ref,
                "artifact_command": self.artifact_command,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        alias = "leancert-" + hashlib.sha256(alias_material).hexdigest()[:32]
        try:
            return self.runtime.environment(alias)
        except RuntimeEnvironmentError as exc:
            if not (
                str(exc).startswith("unknown environment:")
                or "environment alias is dangling" in str(exc)
            ):
                raise
        spec = self.runtime.spec_from_references([self.package_ref])
        if len(spec.packages) != 1:
            raise BridgeError("one Bridge package reference must resolve to one direct package")
        package = replace(spec.packages[0], artifact_command=self.artifact_command)
        hydrated_spec = replace(spec, packages=(package,))
        lock = self.runtime.prepare(hydrated_spec, timeout=self.resolution_timeout_seconds)
        return self.runtime.open_exact(lock, name=alias)

    @property
    def environment_id(self) -> str | None:
        if self._environment is not None:
            return self._environment.id
        if self._program is not None:
            return self._program.description.source_environment_id
        return None

    @property
    def program_id(self) -> str | None:
        return None if self._program is None else self._program.id

    @property
    def program_copy_id(self) -> str | None:
        return None if self._program is None else self._program.copy_id

    def _new_worker_client(self) -> LeanClient:
        """Clone this client's execution route for one parallel worker.

        Ready-program execution and managed source environments are deliberately
        separate routes.  In particular, reading ``environment`` on a
        ready-program client would hydrate the full source environment merely to
        start a worker.  Resolve the active route once here and pass that exact
        target to the worker instead.
        """
        target = (
            {"program": self.program}
            if self.uses_ready_program
            else {"environment": self.environment}
        )
        return LeanClient(
            package_ref=self.package_ref,
            runtime=self.runtime,
            execution_policy=self.execution_policy,
            resolution_timeout_seconds=self.resolution_timeout_seconds,
            artifact_command=self.artifact_command,
            command=self.command,
            enclosure_profile=self.enclosure_profile,
            program_library=self.program_library,
            program_reference=self.program_reference,
            require_program_profile=self.require_program_profile,
            **target,
        )

    @property
    def execution_id(self) -> str | None:
        return None if self._session is None else self._session.execution_id

    def _ensure_session(self) -> InteractiveSession:
        """Ensure the managed interactive Bridge session is running."""
        if self._session is None or not self._session.running:
            if self._session is not None:
                self.execution_result = self._session.close()
            self._contract_checked = False
            self._bridge_info = None
            self._bridge_contract = None
            self._enclosures = None
            command = list(self.command)
            if self.enclosure_profile is not None:
                command.extend(["--enclosure-profile", str(self.enclosure_profile.path)])
            if self.enclosure_profile is None and self._environment is None:
                self._session = self.program.spawn_interactive(policy=self.execution_policy)
            else:
                self._session = self.environment.spawn_interactive(
                    command,
                    policy=self.execution_policy,
                )
        return self._session

    def _check_bridge_contract(self) -> None:
        """Verify bridge API compatibility once per process lifecycle."""
        if self._contract_checked:
            return

        info = self._call_raw("get_info", {})
        contract = BridgeHandshake.parse(info)
        if self.enclosure_profile is None and self._environment is None:
            profile = _program_profile(self.program, required=self.require_program_profile)
            if profile is not None:
                _validate_profile_handshake(profile, contract)
        if self.enclosure_profile is not None:
            self.enclosure_profile.validate_handshake(contract.enclosure_profile)
        self._bridge_info = dict(contract.raw)
        self._bridge_contract = contract
        self._contract_checked = True

    def _retire_session(self, session: InteractiveSession) -> ExecutionResult:
        """Finalize one unusable session and clear all process-local contract state."""
        result = session.close()
        self.execution_result = result
        if self._session is session:
            self._session = None
        self._bridge_info = None
        self._bridge_contract = None
        self._enclosures = None
        self._contract_checked = False
        return result

    @staticmethod
    def _execution_failure_detail(result: ExecutionResult, fallback: str) -> str:
        diagnostic = next(
            (
                item.message
                for item in result.diagnostics
                if item.severity == "error" and item.message
            ),
            None,
        )
        detail = diagnostic or result.stderr.strip() or result.stdout.strip() or fallback
        limit = 2_000
        return detail if len(detail) <= limit else detail[:limit] + "…"

    def _call_raw(self, method: str, params: dict[str, Any]) -> Any:
        """
        Send a raw line-delimited JSON request without compatibility pre-checks.

        Args:
            method: The RPC method name.
            params: Parameters for the method.

        Returns:
            The result from the bridge.

        Raises:
            BridgeError: If the call fails.
        """
        session = self._ensure_session()

        self._request_id += 1
        request = {
            "id": self._request_id,
            "method": method,
            "params": params,
        }

        # Send request
        try:
            request_json = json.dumps(
                request, allow_nan=False, ensure_ascii=False, separators=(",", ":")
            )
        except (TypeError, ValueError) as exc:
            raise ProtocolViolation(f"Request is not valid JSON data: {exc}") from exc
        try:
            response_line = session.request_line(request_json)
        except RuntimeEnvironmentError as exc:
            result = self._retire_session(session)
            detail = self._execution_failure_detail(result, str(exc))
            raise BridgeError(
                "Bridge session ended unexpectedly "
                f"(execution_id={session.execution_id}, exit_code={result.exit_code}): {detail}"
            ) from exc

        try:
            response = json.loads(response_line)
        except json.JSONDecodeError as exc:
            self._retire_session(session)
            excerpt = response_line if len(response_line) <= 500 else response_line[:500] + "…"
            raise BridgeError(
                f"Bridge returned malformed JSON: {exc}; response={excerpt!r}"
            ) from exc

        if not isinstance(response, dict):
            raise BridgeError("Bridge response must be a JSON object")
        if response.get("id") != self._request_id:
            raise BridgeError(
                f"Bridge response id mismatch: expected {self._request_id}, "
                f"got {response.get('id')!r}"
            )

        has_result = "result" in response
        has_error = "error" in response
        if has_result == has_error:
            raise ProtocolViolation("Bridge response must contain exactly one of result or error")
        unexpected = set(response) - {"id", "result", "error"}
        if unexpected:
            raise ProtocolViolation(
                "Bridge response contains unexpected envelope fields: "
                + ", ".join(sorted(unexpected))
            )
        if has_error:
            error = response["error"]
            if isinstance(error, dict):
                code = error.get("code")
                message = error.get("message")
                if not isinstance(code, str) or not code or not isinstance(message, str):
                    raise ProtocolViolation(
                        "Structured bridge error requires non-empty code and string message"
                    )
                raise BridgeRemoteError(code, message, error.get("data"))
            if not isinstance(error, str):
                raise ProtocolViolation("Bridge error must be a string or structured error object")
            raise BridgeError(error)
        return response["result"]

    def call(self, method: str, params: dict[str, Any]) -> Any:
        """
        Make a call over the bridge's custom line-delimited JSON protocol.

        Performs a one-time bridge contract check using `get_info` before
        non-handshake calls.
        """
        with self._io_lock:
            if method not in {"ping", "get_info"} and not self._contract_checked:
                self._check_bridge_contract()
            contract = self._bridge_contract
            if contract is not None and not contract.supports(method):
                raise BridgeError(
                    f"Bridge {self._bridge_info.get('bridge_version', '<unknown>')} "
                    f"does not advertise operation {method!r}"
                )
            return self._call_raw(method, params)

    def ping(self) -> str:
        """Test connection to the bridge."""
        return self.call("ping", {})

    def get_info(self) -> dict[str, Any]:
        """Get bridge metadata including API and Lean versions."""
        result = self.call("get_info", {})
        contract = BridgeHandshake.parse(result)
        if self.enclosure_profile is None and self._environment is None:
            profile = _program_profile(self.program, required=self.require_program_profile)
            if profile is not None:
                _validate_profile_handshake(profile, contract)
        if self.enclosure_profile is not None:
            self.enclosure_profile.validate_handshake(contract.enclosure_profile)
        self._bridge_info = dict(contract.raw)
        self._bridge_contract = contract
        self._contract_checked = True
        return dict(contract.raw)

    @property
    def bridge_info(self) -> dict[str, Any]:
        """Return cached handshake data, performing the handshake if needed."""
        if self._bridge_info is None:
            return self.get_info()
        return dict(self._bridge_info)

    @property
    def bridge_contract(self) -> BridgeHandshake:
        """Return the negotiated, typed bridge contract."""
        if self._bridge_contract is None:
            self.get_info()
        assert self._bridge_contract is not None
        return self._bridge_contract

    @property
    def enclosures(self) -> EnclosureEnvironment:
        """Return function handles from the immutable negotiated profile."""
        if self.enclosure_profile is None:
            raise BridgeError("this Bridge process was not configured with an enclosure profile")
        contract = self.bridge_contract
        assert contract.enclosure_profile is not None
        if self._enclosures is None:
            self._enclosures = EnclosureEnvironment(
                self.enclosure_profile, contract.enclosure_profile
            )
        return self._enclosures

    def check_registered_enclosure(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.call("check_registered_enclosure", params)

    def replay_registered_enclosure(
        self, claim: dict[str, Any], certificate: Mapping[str, Any]
    ) -> dict[str, Any]:
        return self.call(
            "replay_registered_enclosure",
            {"claim": claim, "certificate": dict(certificate)},
        )

    def eval_interval(
        self,
        expr_json: dict,
        box_json: list[dict],
        taylor_depth: int = 10,
    ) -> dict:
        """Evaluate an expression over a box."""
        return self.call(
            "eval_interval",
            {
                "expr": expr_json,
                "box": box_json,
                "taylorDepth": taylor_depth,
            },
        )

    def eval_interval_dyadic(
        self,
        expr_json: dict,
        box_json: list[dict],
        precision: int = -53,
        taylor_depth: int = 10,
        round_after_ops: int = 0,
    ) -> dict:
        """
        Evaluate an expression using high-performance Dyadic arithmetic.

        Dyadic arithmetic (n * 2^e) avoids denominator explosion that occurs
        with rational arithmetic on deep expressions. It's 10-100x faster for
        complex expressions like neural networks or nested Taylor series.

        Args:
            expr_json: Expression in JSON format.
            box_json: Box (list of intervals) in JSON format.
            precision: Minimum exponent for outward rounding. -53 gives IEEE
                      double-like precision (~15 decimal digits). Use -100 for
                      higher precision.
            taylor_depth: Number of Taylor terms for transcendental functions.
            round_after_ops: Round after this many operations (0 = always).

        Returns:
            Dict with:
              - lo, hi: Rational bounds (for compatibility)
              - dyadic: Dict with lo/hi as Dyadic (mantissa, exponent)
        """
        return self.call(
            "eval_interval_dyadic",
            {
                "expr": expr_json,
                "box": box_json,
                "config": {
                    "precision": precision,
                    "taylorDepth": taylor_depth,
                    "roundAfterOps": round_after_ops,
                },
            },
        )

    def eval_interval_affine(
        self,
        expr_json: dict,
        box_json: list[dict],
        taylor_depth: int = 10,
        max_noise_symbols: int = 0,
    ) -> dict:
        """
        Evaluate an expression using Affine Arithmetic.

        Affine arithmetic tracks correlations between variables, solving the
        "dependency problem" in interval arithmetic. For example:
        - x - x on [-1, 1] with interval gives [-2, 2]
        - x - x on [-1, 1] with affine gives [0, 0] (exact!)

        Args:
            expr_json: Expression in JSON format.
            box_json: Box (list of intervals) in JSON format.
            taylor_depth: Number of Taylor terms for transcendental functions.
            max_noise_symbols: Max noise symbols before consolidation (0 = no limit).

        Returns:
            Dict with:
              - lo, hi: Interval bounds
              - affine: Dict with c0 (central value) and radius
        """
        return self.call(
            "eval_interval_affine",
            {
                "expr": expr_json,
                "box": box_json,
                "config": {
                    "taylorDepth": taylor_depth,
                    "maxNoiseSymbols": max_noise_symbols,
                },
            },
        )

    def global_min(
        self,
        expr_json: dict,
        box_json: list[dict],
        max_iters: int = 1000,
        tolerance: dict | None = None,
        use_monotonicity: bool = True,
        taylor_depth: int = 10,
    ) -> dict:
        """Find global minimum."""
        return self.call(
            "global_min",
            {
                "expr": expr_json,
                "box": box_json,
                "maxIters": max_iters,
                "tolerance": {"n": 1, "d": 1000} if tolerance is None else tolerance,
                "useMonotonicity": use_monotonicity,
                "taylorDepth": taylor_depth,
            },
        )

    def global_max(
        self,
        expr_json: dict,
        box_json: list[dict],
        max_iters: int = 1000,
        tolerance: dict | None = None,
        use_monotonicity: bool = True,
        taylor_depth: int = 10,
    ) -> dict:
        """Find global maximum."""
        return self.call(
            "global_max",
            {
                "expr": expr_json,
                "box": box_json,
                "maxIters": max_iters,
                "tolerance": {"n": 1, "d": 1000} if tolerance is None else tolerance,
                "useMonotonicity": use_monotonicity,
                "taylorDepth": taylor_depth,
            },
        )

    def global_min_dyadic(
        self,
        expr_json: dict,
        box_json: list[dict],
        max_iters: int = 1000,
        tolerance: dict | None = None,
        use_monotonicity: bool = True,
        taylor_depth: int = 10,
        precision: int = -53,
    ) -> dict:
        """
        Find global minimum using Dyadic arithmetic.

        Dyadic arithmetic (n * 2^e) avoids denominator explosion that occurs
        with rational arithmetic on deep expressions.
        """
        return self.call(
            "global_min_dyadic",
            {
                "expr": expr_json,
                "box": box_json,
                "maxIters": max_iters,
                "tolerance": {"n": 1, "d": 1000} if tolerance is None else tolerance,
                "useMonotonicity": use_monotonicity,
                "taylorDepth": taylor_depth,
                "precision": precision,
            },
        )

    def global_max_dyadic(
        self,
        expr_json: dict,
        box_json: list[dict],
        max_iters: int = 1000,
        tolerance: dict | None = None,
        use_monotonicity: bool = True,
        taylor_depth: int = 10,
        precision: int = -53,
    ) -> dict:
        """
        Find global maximum using Dyadic arithmetic.

        Dyadic arithmetic (n * 2^e) avoids denominator explosion that occurs
        with rational arithmetic on deep expressions.
        """
        return self.call(
            "global_max_dyadic",
            {
                "expr": expr_json,
                "box": box_json,
                "maxIters": max_iters,
                "tolerance": {"n": 1, "d": 1000} if tolerance is None else tolerance,
                "useMonotonicity": use_monotonicity,
                "taylorDepth": taylor_depth,
                "precision": precision,
            },
        )

    def global_min_affine(
        self,
        expr_json: dict,
        box_json: list[dict],
        max_iters: int = 1000,
        tolerance: dict | None = None,
        use_monotonicity: bool = True,
        taylor_depth: int = 10,
        max_noise_symbols: int = 0,
    ) -> dict:
        """
        Find global minimum using Affine arithmetic.

        Affine arithmetic tracks correlations between variables, solving the
        "dependency problem" in interval arithmetic. For example:
        - x - x on [-1, 1] with interval gives [-2, 2]
        - x - x on [-1, 1] with affine gives [0, 0] (exact!)
        """
        return self.call(
            "global_min_affine",
            {
                "expr": expr_json,
                "box": box_json,
                "maxIters": max_iters,
                "tolerance": {"n": 1, "d": 1000} if tolerance is None else tolerance,
                "useMonotonicity": use_monotonicity,
                "taylorDepth": taylor_depth,
                "maxNoiseSymbols": max_noise_symbols,
            },
        )

    def global_max_affine(
        self,
        expr_json: dict,
        box_json: list[dict],
        max_iters: int = 1000,
        tolerance: dict | None = None,
        use_monotonicity: bool = True,
        taylor_depth: int = 10,
        max_noise_symbols: int = 0,
    ) -> dict:
        """
        Find global maximum using Affine arithmetic.

        Affine arithmetic tracks correlations between variables, solving the
        "dependency problem" in interval arithmetic.
        """
        return self.call(
            "global_max_affine",
            {
                "expr": expr_json,
                "box": box_json,
                "maxIters": max_iters,
                "tolerance": {"n": 1, "d": 1000} if tolerance is None else tolerance,
                "useMonotonicity": use_monotonicity,
                "taylorDepth": taylor_depth,
                "maxNoiseSymbols": max_noise_symbols,
            },
        )

    def check_bound(
        self,
        expr_json: dict,
        box_json: list[dict],
        bound: dict,
        is_upper_bound: bool,
        taylor_depth: int = 10,
    ) -> dict:
        """Check if a bound holds."""
        result = self.call(
            "check_bound",
            {
                "expr": expr_json,
                "box": box_json,
                "bound": bound,
                "isUpperBound": is_upper_bound,
                "taylorDepth": taylor_depth,
            },
        )
        contract = self._bridge_contract
        typed_contract = contract.typed_contract if contract is not None else False
        direction = "upper" if is_upper_bound else "lower"
        if contract is None:
            BoundOperationOutcome.parse(
                result, typed_contract=typed_contract, expected_direction=direction
            )
        else:
            contract.parse_bound_outcome(result, expected_direction=direction)
        return result

    def check_strict_bound(
        self,
        expr_json: dict,
        box_json: list[dict],
        bound: dict,
        relation: str,
        taylor_depth: int = 10,
    ) -> dict:
        """Check ``expr < bound`` (lt) or ``bound < expr`` (gt)."""
        if relation not in {"lt", "gt"}:
            raise ValueError("strict-bound relation must be 'lt' or 'gt'")
        result = self.call(
            "check_strict_bound",
            {
                "expr": expr_json,
                "box": box_json,
                "relation": relation,
                "bound": bound,
                "taylorDepth": taylor_depth,
            },
        )
        contract = self._bridge_contract
        if contract is None:
            outcome = StrictBoundOperationOutcome.parse(result, expected_relation=relation)
        else:
            outcome = contract.parse_strict_bound_outcome(result, expected_relation=relation)
        if outcome.target_bound.fraction != Fraction(bound["n"], bound["d"]):
            raise ProtocolViolation("strict-bound target contradicts the request")
        return result

    def integrate(
        self,
        expr_json: dict,
        interval_json: dict,
        partitions: int = 10,
        taylor_depth: int = 10,
    ) -> dict:
        """Compute integral bounds."""
        return self.call(
            "integrate",
            {
                "expr": expr_json,
                "interval": interval_json,
                "partitions": partitions,
                "taylorDepth": taylor_depth,
            },
        )

    def find_roots(
        self,
        expr_json: dict,
        interval_json: dict,
        max_iter: int = 1000,
        tolerance: dict | None = None,
        taylor_depth: int = 10,
    ) -> dict:
        """Find roots using bisection."""
        return self.call(
            "find_roots",
            {
                "expr": expr_json,
                "interval": interval_json,
                "maxIter": max_iter,
                "tolerance": {"n": 1, "d": 1000} if tolerance is None else tolerance,
                "taylorDepth": taylor_depth,
            },
        )

    def verify_adaptive(
        self,
        expr_json: dict,
        box_json: list[dict],
        bound: dict,
        is_upper_bound: bool,
        max_iters: int = 1000,
        tolerance: dict | None = None,
        taylor_depth: int = 10,
    ) -> dict:
        """
        Verify a bound using adaptive optimization.

        This method verifies f <= c (upper) or f >= c (lower) by
        minimizing c - f (for upper) or f - c (for lower) and checking
        if the minimum is >= 0.
        """
        request = {
            "expr": expr_json,
            "box": box_json,
            "bound": bound,
            "isUpperBound": is_upper_bound,
            "maxIters": max_iters,
            "tolerance": {"n": 1, "d": 1000} if tolerance is None else tolerance,
            "taylorDepth": taylor_depth,
        }
        response = self.call(
            "verify_adaptive",
            request,
        )
        contract = self.bridge_contract
        if contract.api_version >= type(contract.api_version)(2, 2, 0):
            outcome = contract.parse_adaptive_outcome(
                response, expected_direction="upper" if is_upper_bound else "lower"
            )
            if outcome.certificate is not None:
                payload = response["certificate"]["payload"]
                expected_config = {
                    "max_iterations": max_iters,
                    "tolerance": request["tolerance"],
                    "use_monotonicity": True,
                    "taylor_depth": taylor_depth,
                }
                expected = {
                    "expression": _bridge_core_expression(expr_json),
                    "box": box_json,
                    "bound": bound,
                    "direction": "upper" if is_upper_bound else "lower",
                    "config": expected_config,
                }
                for key, value in expected.items():
                    if payload.get(key) != value:
                        raise ProtocolViolation(
                            f"adaptive certificate {key} does not match the checked request"
                        )
        return response

    def find_unique_root(
        self,
        expr_json: dict,
        interval_json: dict,
        taylor_depth: int = 10,
    ) -> dict:
        """
        Find a unique root using Newton contraction.

        Checks if Newton iteration contracts, which proves both existence
        and uniqueness of a root in the interval.

        Returns a dict with:
          - unique: bool (True if unique root proven)
          - reason: str ('newton_contraction', 'no_contraction', 'newton_step_failed')
          - interval: dict with lo/hi (refined interval if Newton succeeded)
        """
        return self.call(
            "find_unique_root",
            {
                "expr": expr_json,
                "interval": interval_json,
                "taylorDepth": taylor_depth,
            },
        )

    def check_unique_system_root(
        self,
        system_json: list[dict[str, Any]],
        box_json: list[dict[str, Any]],
        *,
        candidate: dict[str, Any] | None = None,
        max_iterations: int = 8,
        max_dimension: int = 4,
        precision_bits: int = 20,
        taylor_depth: int = 10,
    ) -> dict[str, Any]:
        """Check a unique nonlinear-system root through Contract 2.3."""
        request: dict[str, Any] = {
            "system": system_json,
            "box": box_json,
            "maxIterations": max_iterations,
            "maxDimension": max_dimension,
            "precisionBits": precision_bits,
            "taylorDepth": taylor_depth,
        }
        if candidate is not None:
            request["candidate"] = candidate
        response = self.call("check_unique_system_root", request)
        contract = self.bridge_contract
        if contract.api_version >= type(contract.api_version)(2, 3, 0):
            outcome = contract.parse_system_root_outcome(response)
        else:
            outcome = SystemRootOperationOutcome.parse(response)
        if outcome.certificate is not None:
            payload = outcome.certificate.payload
            expected_system = tuple(_bridge_core_expression(item) for item in system_json)
            if tuple(dict(item) for item in payload.system) != expected_system:
                raise ProtocolViolation(
                    "Krawczyk certificate system does not match the checked request"
                )
            expected_box = tuple(
                (
                    Fraction(item["lo"]["n"], item["lo"]["d"]),
                    Fraction(item["hi"]["n"], item["hi"]["d"]),
                )
                for item in box_json
            )
            actual_box = tuple((item.lower.fraction, item.upper.fraction) for item in payload.box)
            if actual_box != expected_box or payload.taylor_depth != taylor_depth:
                raise ProtocolViolation(
                    "Krawczyk certificate box or Taylor depth contradicts the request"
                )
        return response

    def check_eventual_bound(
        self,
        coefficient: Fraction,
        bound: Fraction,
        exponent: int,
        *,
        cutoff: int | None = None,
        max_checks: int = 1000,
    ) -> dict[str, Any]:
        """Check or discover a reciprocal-power cutoff through Contract 2.4."""
        request: dict[str, Any] = {
            "coefficient": {
                "n": coefficient.numerator,
                "d": coefficient.denominator,
            },
            "bound": {"n": bound.numerator, "d": bound.denominator},
            "exponent": exponent,
            "maxChecks": max_checks,
        }
        if cutoff is not None:
            request["cutoff"] = cutoff
        response = self.call("check_eventual_bound", request)
        contract = self.bridge_contract
        if contract.api_version >= type(contract.api_version)(2, 4, 0):
            outcome = contract.parse_eventual_outcome(response)
        else:
            outcome = EventualOperationOutcome.parse(response)
        if outcome.certificate is not None:
            payload = outcome.certificate.payload
            if (
                payload.coefficient.fraction != coefficient
                or payload.bound.fraction != bound
                or payload.exponent != exponent
                or (cutoff is not None and payload.cutoff != cutoff)
            ):
                raise ProtocolViolation(
                    "eventual-bound certificate payload contradicts the checked request"
                )
        return response

    def check_scalar_root(
        self,
        expr_json: dict[str, Any],
        interval_json: dict[str, Any],
        claim: str,
        *,
        taylor_depth: int = 10,
    ) -> dict[str, Any]:
        """Check a fixed scalar-root claim through Bridge Contract 2.5."""
        if claim not in {"exists", "unique", "excluded"}:
            raise ValueError("scalar-root claim must be exists, unique, or excluded")
        request = {
            "expr": expr_json,
            "interval": interval_json,
            "claim": claim,
            "taylorDepth": taylor_depth,
        }
        response = self.call("check_scalar_root", request)
        outcome = self.bridge_contract.parse_scalar_root_outcome(response, expected_claim=claim)
        if outcome.certificate is not None:
            payload = outcome.certificate.payload
            expected_expression = _bridge_core_expression(expr_json)
            if dict(payload.expression) != expected_expression:
                raise ProtocolViolation(
                    "scalar-root certificate expression contradicts the checked request"
                )
            expected_interval = (
                Fraction(interval_json["lo"]["n"], interval_json["lo"]["d"]),
                Fraction(interval_json["hi"]["n"], interval_json["hi"]["d"]),
            )
            actual_interval = (
                payload.interval.lower.fraction,
                payload.interval.upper.fraction,
            )
            if actual_interval != expected_interval or payload.taylor_depth != taylor_depth:
                raise ProtocolViolation(
                    "scalar-root certificate interval or Taylor depth contradicts the request"
                )
        return response

    def check_integral(
        self,
        expr_json: dict[str, Any],
        interval_json: dict[str, Any],
        relation: str,
        bound: Fraction,
        *,
        start_partitions: int = 32,
        max_partitions: int = 4096,
    ) -> dict[str, Any]:
        """Check an exact equality or one-sided bound through Contract 2.6."""
        if relation not in {"eq", "lower", "upper"}:
            raise ValueError("integral relation must be eq, lower, or upper")
        request = {
            "expr": expr_json,
            "interval": interval_json,
            "relation": relation,
            "bound": {"n": bound.numerator, "d": bound.denominator},
            "startPartitions": start_partitions,
            "maxPartitions": max_partitions,
        }
        response = self.call("check_integral", request)
        outcome = self.bridge_contract.parse_integral_outcome(response, expected_relation=relation)
        expected_interval = (
            Fraction(interval_json["lo"]["n"], interval_json["lo"]["d"]),
            Fraction(interval_json["hi"]["n"], interval_json["hi"]["d"]),
        )
        actual_outcome_interval = (
            outcome.interval.lower.fraction,
            outcome.interval.upper.fraction,
        )
        if actual_outcome_interval != expected_interval or outcome.bound.fraction != bound:
            raise ProtocolViolation("integral outcome contradicts the checked request")
        if outcome.certificate is not None:
            payload = outcome.certificate.payload
            expected_expression = _bridge_core_expression(expr_json)
            actual_interval = (
                payload.interval.lower.fraction,
                payload.interval.upper.fraction,
            )
            if (
                dict(payload.expression) != expected_expression
                or actual_interval != expected_interval
                or payload.relation != relation
                or payload.bound.fraction != bound
            ):
                raise ProtocolViolation(
                    "integral certificate payload contradicts the checked request"
                )
        return response

    def forward_interval(
        self,
        layers_json: list[dict],
        input_json: list[dict],
        precision: int = -53,
    ) -> dict:
        """
        Propagate intervals through a neural network.

        This runs verified interval arithmetic forward propagation through
        a sequential neural network (list of layers with ReLU activations).

        Args:
            layers_json: List of layer dicts, each with:
              - weights: List of rows, each row a list of rationals {n, d}
              - bias: List of rationals {n, d}
            input_json: List of interval dicts with lo/hi as rationals
            precision: Dyadic precision for interval arithmetic (-53 = IEEE double)

        Returns:
            Dict with:
              - output: List of interval dicts (lo/hi as rationals)
              - numLayers: Number of layers
              - outputDim: Output dimension

        Example:
            >>> client = LeanClient()
            >>> layers = [
            ...     {"weights": [[{"n": 1, "d": 1}]], "bias": [{"n": 0, "d": 1}]},
            ... ]
            >>> inputs = [{"lo": {"n": 0, "d": 1}, "hi": {"n": 1, "d": 1}}]
            >>> result = client.forward_interval(layers, inputs)
            >>> print(result["output"])
        """
        return self.call(
            "forward_interval",
            {
                "layers": layers_json,
                "input": input_json,
                "precision": precision,
            },
        )

    def deriv_interval(
        self,
        expr_json: dict,
        box_json: list[dict],
        taylor_depth: int = 10,
    ) -> dict:
        """
        Compute derivative interval bounds over a box.

        This computes bounds on all partial derivatives (the gradient) over a box
        using forward-mode automatic differentiation. The result can be used to
        compute Lipschitz constants for epsilon-delta continuity proofs.

        Args:
            expr_json: Expression AST as JSON dict
            box_json: List of interval dicts (one per variable)
            taylor_depth: Taylor series depth for transcendental functions

        Returns:
            Dict with:
              - gradients: List of intervals, one per variable, each containing
                          the range of ∂f/∂xᵢ over the box
              - lipschitz_bound: max(|∂f/∂xᵢ|) over all variables and the box
              - num_vars: Number of variables

        Example:
            >>> client = LeanClient()
            >>> # f(x) = x^2, domain [0, 1]
            >>> expr = {"kind": "pow", "base": {"kind": "var", "idx": 0}, "exp": 2}
            >>> box = [{"lo": {"n": 0, "d": 1}, "hi": {"n": 1, "d": 1}}]
            >>> result = client.deriv_interval(expr, box)
            >>> # gradient of x^2 is 2x, so on [0,1] it's [0, 2]
            >>> print(result["lipschitz_bound"])  # Should be 2
        """
        return self.call(
            "deriv_interval",
            {
                "expr": expr_json,
                "box": box_json,
                "taylorDepth": taylor_depth,
            },
        )

    def close(self) -> None:
        """Close the managed session and retain its exact execution result."""
        with self._io_lock:
            if self._session is not None:
                self.execution_result = self._session.close()
                self._session = None
            self._bridge_info = None
            self._bridge_contract = None
            self._enclosures = None
            self._contract_checked = False

    def __enter__(self) -> LeanClient:
        """Context manager entry."""
        return self

    def __exit__(self, *args) -> None:
        """Context manager exit."""
        self.close()

    def __del__(self) -> None:
        """Best-effort fallback for a client abandoned without ``close``.

        Context management remains the deterministic lifecycle API. This
        fallback prevents abandoned managed sessions from accumulating process
        handles and file descriptors in long-lived applications and test runs.
        """
        try:
            self.close()
        except Exception:
            # Finalizers can run during partial construction or interpreter
            # shutdown, when attributes and imported modules may be unavailable.
            pass


def _parse_rat(data: dict) -> Fraction:
    """Parse a rational from kernel JSON."""
    return Fraction(data["n"], data["d"])


def _parse_interval(data: dict) -> Interval:
    """Parse an interval from kernel JSON."""
    return Interval(_parse_rat(data["lo"]), _parse_rat(data["hi"]))


def _parse_dyadic(data: dict) -> Fraction:
    """
    Parse a Dyadic number (mantissa * 2^exponent) from kernel JSON.

    Returns a Fraction for exact representation.
    """
    mantissa = data["mantissa"]
    exponent = data["exponent"]
    if exponent >= 0:
        return Fraction(mantissa * (2**exponent), 1)
    else:
        return Fraction(mantissa, 2 ** (-exponent))


def _parse_dyadic_interval(data: dict) -> Interval:
    """Parse a Dyadic interval from kernel JSON."""
    return Interval(_parse_dyadic(data["lo"]), _parse_dyadic(data["hi"]))
