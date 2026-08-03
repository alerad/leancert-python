# LeanCert v2 SDK - Result Types
# Copyright (c) 2024 LeanCert Contributors. All rights reserved.

"""
Result types and certificates for LeanCert v2.

This module provides rich result objects that include verification status
and exportable certificates.
"""

from __future__ import annotations

import hashlib
import json
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any, Literal, Optional

from .domain import Interval


class ProofResult:
    """Marker base for every typed outcome returned by :func:`leancert.prove`."""

    def __bool__(self) -> bool:
        raise TypeError("Proof outcomes have no truth value; inspect their concrete result type")


@dataclass(frozen=True)
class ExactLogicalResult(ProofResult):
    """A claim decided by exact SDK normalization, outside Bridge authority."""

    original_claim: Any
    normalized_claim: Any
    claim_id: Any
    authority: Literal["python_exact_normalizer"] = "python_exact_normalizer"


@dataclass(frozen=True)
class NormalizedTrue(ExactLogicalResult):
    """Exact normalization reduced the claim to ``TrueClaim``."""


@dataclass(frozen=True)
class NormalizedFalse(ExactLogicalResult):
    """Exact normalization reduced the claim to ``FalseClaim``."""


@dataclass(frozen=True)
class ConjunctionResult(ProofResult):
    """Child-preserving result for a recursively routed conjunction."""

    children: tuple[ProofResult, ...]
    original_claim: Any
    normalized_claim: Any
    claim_id: Any


@dataclass(frozen=True)
class VerifiedConjunction(ConjunctionResult):
    """Every non-trivial child has checked evidence; exact children are labeled."""

    def export_lean_project(self, path: str, *, verify: bool = True):
        from .export import export_verified_conjunction

        return export_verified_conjunction(self, path, verify=verify)


@dataclass(frozen=True)
class IncompleteConjunction(ConjunctionResult):
    """At least one conjunction child was not established."""


@dataclass(frozen=True)
class BoundComparisonLowering:
    """Proof-relevant record of a semantic comparison lowered to a bound check."""

    lhs: Any
    rhs: Any
    checked_expression: Any
    direction: Literal["lower", "upper"]
    bound: Fraction
    rule: Literal[
        "lhs_le_constant",
        "constant_le_rhs",
        "subtract_rhs_le_zero",
    ]
    strict: bool = False


@dataclass(frozen=True)
class BridgeProvenance:
    """Exact negotiated environment that performed a checked operation."""

    bridge_api_version: str | None = None
    protocol_version: str | None = None
    bridge_version: str | None = None
    lean_version: str | None = None
    leancert_version: str | None = None
    source_revision: str | None = None
    source_digest: str | None = None
    environment_digest: str | None = None
    build_profile: str | None = None
    capability_digest: str | None = None
    lean_toolchain: str | None = None
    leancert_source: str | None = None
    leancert_input_revision: str | None = None
    leancert_resolved_revision: str | None = None


@dataclass(frozen=True)
class ReplayBoundConfig:
    max_iterations: int
    tolerance: Fraction
    use_monotonicity: bool
    taylor_depth: int


@dataclass(frozen=True)
class ReplayableBoundCertificate:
    """Canonical fixed checker input issued by Bridge Contract 2.1."""

    schema_version: str
    payload_schema: str
    checker: str
    verifier: str
    verification_route: str
    payload_digest: str
    expression: Mapping[str, Any]
    box: tuple[Interval, ...]
    bound: Fraction
    direction: Literal["lower", "upper"]
    config: ReplayBoundConfig
    canonical_payload: Mapping[str, Any]


@dataclass(frozen=True)
class ReplayableStrictBoundCertificate:
    """Exact interior bound and fixed checker input from Bridge Contract 2.7."""

    schema_version: str
    payload_schema: str
    checker: str
    verifier: str
    verification_route: str
    payload_digest: str
    expression: Mapping[str, Any]
    box: tuple[Interval, ...]
    relation: Literal["lt", "gt"]
    target_bound: Fraction
    certified_bound: Fraction
    config: ReplayBoundConfig
    canonical_payload: Mapping[str, Any]

    @property
    def direction(self) -> Literal["lower", "upper"]:
        return "upper" if self.relation == "lt" else "lower"

    @property
    def bound(self) -> Fraction:
        return self.target_bound


@dataclass(frozen=True)
class ReplayableRegisteredEnclosureCertificate:
    """Profile-bound fixed registered-enclosure replay input from Contract 2.8."""

    schema_version: str
    replay_payload_schema: str
    payload_digest: str
    profile_name: str
    leancert_revision: str
    environment_digest: str
    claim: Mapping[str, Any]
    retained: Mapping[str, Any]

    @classmethod
    def load(cls, path: str) -> ReplayableRegisteredEnclosureCertificate:
        with open(path, encoding="utf-8") as stream:
            payload = json.load(stream)
        if not isinstance(payload, dict) or set(payload) != {"claim", "certificate"}:
            raise ValueError("registered enclosure evidence must contain claim and certificate")
        claim = payload["claim"]
        retained = payload["certificate"]
        if not isinstance(claim, dict) or not isinstance(retained, dict):
            raise ValueError("registered enclosure claim and certificate must be JSON objects")
        profile = retained.get("profile")
        if not isinstance(profile, dict):
            raise ValueError("registered enclosure certificate lacks profile identity")
        if retained.get("schema") != "registered-enclosure-check/1":
            raise ValueError("unsupported registered enclosure certificate schema")
        if retained.get("replay_payload_schema") != "checked-registered-enclosure/1":
            raise ValueError("unsupported registered enclosure replay payload schema")
        for field_name in ("name", "leancert_revision", "environment_digest"):
            if not isinstance(profile.get(field_name), str) or not profile[field_name]:
                raise ValueError(f"registered enclosure profile {field_name} is missing")

        def freeze(value):
            from types import MappingProxyType

            if isinstance(value, dict):
                return MappingProxyType({key: freeze(item) for key, item in value.items()})
            if isinstance(value, list):
                return tuple(freeze(item) for item in value)
            return value

        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return cls(
            str(retained.get("schema", "")),
            str(retained.get("replay_payload_schema", "")),
            "sha256:" + hashlib.sha256(canonical).hexdigest(),
            str(profile.get("name", "")),
            str(profile.get("leancert_revision", "")),
            str(profile.get("environment_digest", "")),
            freeze(claim),
            freeze(retained),
        )

    def save(self, path: str) -> None:
        def thaw(value):
            if isinstance(value, Mapping):
                return {key: thaw(item) for key, item in value.items()}
            if isinstance(value, (tuple, list)):
                return [thaw(item) for item in value]
            return value

        payload = {"claim": thaw(self.claim), "certificate": thaw(self.retained)}
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))

    def replay(self, client: Any) -> Mapping[str, Any]:
        from .operations.enclosures import replay_registered_certificate

        return replay_registered_certificate(self, client)


@dataclass(frozen=True)
class LeanProjectArtifact:
    path: str
    claim_id: str
    certificate_digests: tuple[str, ...]


@dataclass(frozen=True)
class ExportPrepared:
    artifact: LeanProjectArtifact


@dataclass(frozen=True)
class ExportVerified:
    artifact: LeanProjectArtifact
    trust_class: Literal["kernel"]
    build_output: str


@dataclass(frozen=True)
class ExportUnsupported:
    reason: str


@dataclass(frozen=True)
class ExportDependencyUnavailable:
    reason: str


@dataclass(frozen=True)
class ExportResourceLimit:
    artifact: LeanProjectArtifact
    reason: str
    timeout_seconds: float
    build_output: str = ""


@dataclass(frozen=True)
class ExportVerificationMismatch:
    artifact: LeanProjectArtifact
    reason: str
    build_output: str


@dataclass(frozen=True)
class BoundCheckEvidence:
    """Retained evidence from one lower- or upper-bound bridge operation."""

    direction: Literal["lower", "upper"]
    requested_bound: Fraction
    enclosure: Interval
    status: Literal[
        "verified",
        "inconclusive",
        "rejected",
        "unsupported",
        "domain_obstruction",
    ]
    operation: str
    backend: Optional[str]
    taylor_depth: int
    certificate: Optional[Mapping[str, Any]] = None
    replay_certificate: (
        ReplayableBoundCertificate
        | ReplayableStrictBoundCertificate
        | ReplayableRegisteredEnclosureCertificate
        | None
    ) = None
    raw_response: Mapping[str, Any] = field(default_factory=dict)
    strict: bool = False


@dataclass(frozen=True)
class CandidateCounterexample:
    """A search-produced point that has not itself established falsity."""

    values: Mapping[str, Fraction]
    enclosure: Optional[Interval] = None


@dataclass(frozen=True)
class CheckedCounterexample(CandidateCounterexample):
    """A point enclosure lying wholly on the violating side of a bound."""


@dataclass(frozen=True)
class BoundCheck(ProofResult):
    """Typed checked outcome, retained as the legacy bound-result name."""

    expression: Any
    domain: Any
    lower: Optional[Fraction]
    upper: Optional[Fraction]
    checks: tuple[BoundCheckEvidence, ...]
    provenance: BridgeProvenance
    lowerings: tuple[BoundComparisonLowering, ...] = field(default=(), kw_only=True)
    original_claim: Any | None = field(default=None, kw_only=True)
    normalized_claim: Any | None = field(default=None, kw_only=True)
    claim_id: Any | None = field(default=None, kw_only=True)

    @property
    def is_verified(self) -> bool:
        return isinstance(self, Verified)

    def __bool__(self) -> bool:
        raise TypeError(
            "Bound-check outcomes have no truth value; use isinstance(result, Verified)"
        )


@dataclass(frozen=True)
class Verified(BoundCheck):
    """Every requested bound was accepted by the checked bridge route."""

    def export_lean_project(
        self,
        path: str,
        *,
        verify: bool = True,
    ):
        """Export and optionally kernel-check the retained fixed certificates."""
        from .export import export_verified_bound

        return export_verified_bound(self, path, verify=verify)


@dataclass(frozen=True)
class VerifiedRegisteredEnclosure(Verified):
    """A downstream registered enclosure established by a fresh kernel proof."""

    def replay(self, client: Any) -> tuple[Mapping[str, Any], ...]:
        results = []
        for check in self.checks:
            certificate = check.replay_certificate
            if not isinstance(certificate, ReplayableRegisteredEnclosureCertificate):
                raise TypeError("result contains non-registered enclosure evidence")
            results.append(certificate.replay(client))
        return tuple(results)

    def export_lean_project(self, path: str, *, verify: bool = True):
        return ExportUnsupported(
            "registered enclosure export requires packaging the downstream Lean modules; "
            "use fixed Bridge replay in the same profiled environment"
        )


@dataclass(frozen=True)
class Rejected(BoundCheck):
    """A checked point enclosure proves that a requested bound is false."""

    counterexample: CheckedCounterexample
    refutation_check: BoundCheckEvidence | None = field(default=None, kw_only=True)


@dataclass(frozen=True)
class Inconclusive(BoundCheck):
    """Available enclosures were insufficient to decide the requested bound."""

    reason: str
    candidate_counterexample: Optional[CandidateCounterexample] = None


@dataclass(frozen=True)
class Unsupported(BoundCheck):
    """The selected checked route does not support the expression or request."""

    reason: str


@dataclass(frozen=True)
class DomainObstruction(BoundCheck):
    """The checker could not establish the operation's domain preconditions."""

    reason: str


@dataclass(frozen=True)
class KrawczykSearchEvidence:
    source: Literal["automatic", "provided"]
    attempts: int
    refinements: int
    contraction_bound: Fraction
    failure: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class ReplayableKrawczykCertificate:
    schema_version: str
    payload_schema: str
    checker: str
    verifier: str
    verification_route: str
    payload_digest: str
    system: tuple[Mapping[str, Any], ...]
    box: tuple[Interval, ...]
    center: tuple[Fraction, ...]
    preconditioner: tuple[tuple[Fraction, ...], ...]
    taylor_depth: int
    canonical_payload: Mapping[str, Any]


@dataclass(frozen=True)
class SystemRootResult(ProofResult):
    equations: tuple[Any, ...]
    variables: tuple[Any, ...]
    domain: Any
    provenance: BridgeProvenance
    search: KrawczykSearchEvidence
    requested_uniqueness: bool = field(default=True, kw_only=True)
    established_uniqueness: bool = field(default=False, kw_only=True)
    original_claim: Any | None = field(default=None, kw_only=True)
    normalized_claim: Any | None = field(default=None, kw_only=True)
    claim_id: Any | None = field(default=None, kw_only=True)


@dataclass(frozen=True)
class VerifiedSystemRoot(SystemRootResult):
    """A fixed Krawczyk checker certified exactly one root in the box."""

    certificate: ReplayableKrawczykCertificate

    def export_lean_project(self, path: str, *, verify: bool = True):
        """Export and optionally kernel-check the fixed Krawczyk certificate."""
        from .export import export_verified_system_root

        return export_verified_system_root(self, path, verify=verify)


@dataclass(frozen=True)
class CandidateRejected(SystemRootResult):
    """A well-formed untrusted Krawczyk candidate failed to certify the claim."""

    reason: str


@dataclass(frozen=True)
class UnsupportedSystemRoot(SystemRootResult):
    reason: str


@dataclass(frozen=True)
class ReplayableScalarRootCertificate:
    schema_version: str
    payload_schema: str
    checker: str
    verifier: str
    verification_route: str
    payload_digest: str
    expression: Mapping[str, Any]
    interval: Interval
    claim: Literal["exists", "unique", "excluded"]
    taylor_depth: int
    canonical_payload: Mapping[str, Any]


@dataclass(frozen=True)
class ScalarRootResult(ProofResult):
    expression: Any
    variable: Any
    domain: Any
    requested_claim: Literal["exists", "unique", "excluded"]
    provenance: BridgeProvenance
    original_claim: Any | None = field(default=None, kw_only=True)
    normalized_claim: Any | None = field(default=None, kw_only=True)
    claim_id: Any | None = field(default=None, kw_only=True)


@dataclass(frozen=True)
class VerifiedRootExistence(ScalarRootResult):
    certificate: ReplayableScalarRootCertificate

    def export_lean_project(self, path: str, *, verify: bool = True):
        from .export import export_verified_scalar_root

        return export_verified_scalar_root(self, path, verify=verify)


@dataclass(frozen=True)
class VerifiedUniqueRoot(ScalarRootResult):
    certificate: ReplayableScalarRootCertificate

    def export_lean_project(self, path: str, *, verify: bool = True):
        from .export import export_verified_scalar_root

        return export_verified_scalar_root(self, path, verify=verify)


@dataclass(frozen=True)
class VerifiedRootExclusion(ScalarRootResult):
    certificate: ReplayableScalarRootCertificate

    def export_lean_project(self, path: str, *, verify: bool = True):
        from .export import export_verified_scalar_root

        return export_verified_scalar_root(self, path, verify=verify)


@dataclass(frozen=True)
class ScalarRootCandidateRejected(ScalarRootResult):
    reason: str


@dataclass(frozen=True)
class UnsupportedScalarRoot(ScalarRootResult):
    reason: str


@dataclass(frozen=True)
class IntegralSearchEvidence:
    source: Literal["exact", "automatic"]
    start_partitions: int | None = None
    max_partitions: int | None = None
    chosen_partitions: int | None = None
    attempts: int = 0
    failure: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class ReplayableIntegralCertificate:
    schema_version: str
    payload_schema: str
    checker: str
    verifier: str
    verification_route: str
    payload_digest: str
    expression: Mapping[str, Any]
    interval: Interval
    relation: Literal["eq", "lower", "upper"]
    bound: Fraction
    partitions: int | None
    canonical_payload: Mapping[str, Any]


@dataclass(frozen=True)
class CheckedIntegralResult(ProofResult):
    integrand: Any
    variable: Any
    domain: Any
    relation: Literal["eq", "lower", "upper"]
    bound: Fraction
    enclosure: Interval | None
    provenance: BridgeProvenance
    search: IntegralSearchEvidence
    original_claim: Any | None = field(default=None, kw_only=True)
    normalized_claim: Any | None = field(default=None, kw_only=True)
    claim_id: Any | None = field(default=None, kw_only=True)


@dataclass(frozen=True)
class VerifiedIntegralEquality(CheckedIntegralResult):
    certificate: ReplayableIntegralCertificate

    def export_lean_project(self, path: str, *, verify: bool = True):
        from .export import export_verified_integral

        return export_verified_integral(self, path, verify=verify)


@dataclass(frozen=True)
class VerifiedIntegralBound(CheckedIntegralResult):
    certificate: ReplayableIntegralCertificate

    def export_lean_project(self, path: str, *, verify: bool = True):
        from .export import export_verified_integral

        return export_verified_integral(self, path, verify=verify)


@dataclass(frozen=True)
class IntegralCandidateRejected(CheckedIntegralResult):
    reason: str


@dataclass(frozen=True)
class InconclusiveIntegral(CheckedIntegralResult):
    reason: str


@dataclass(frozen=True)
class IntegralDomainObstruction(CheckedIntegralResult):
    reason: str


@dataclass(frozen=True)
class UnsupportedIntegral(CheckedIntegralResult):
    reason: str


@dataclass(frozen=True)
class EventualSearchEvidence:
    source: Literal["automatic", "provided"]
    checks: int | None = None
    configured_limit: int | None = None
    exponential_steps: int | None = None
    refinement_steps: int | None = None
    lower_bracket: int | None = None
    upper_bracket: int | None = None
    refinement_complete: bool | None = None
    last_cutoff: int | None = None


@dataclass(frozen=True)
class ReplayableEventualCertificate:
    schema_version: str
    payload_schema: str
    checker: str
    verifier: str
    verification_route: str
    payload_digest: str
    coefficient: Fraction
    bound: Fraction
    exponent: int
    cutoff: int
    canonical_payload: Mapping[str, Any]


@dataclass(frozen=True)
class EventualBoundResult(ProofResult):
    variable: Any
    coefficient: Fraction | None
    bound: Fraction | None
    exponent: int | None
    cutoff: int | None
    provenance: BridgeProvenance
    search: EventualSearchEvidence
    original_claim: Any | None = field(default=None, kw_only=True)
    normalized_claim: Any | None = field(default=None, kw_only=True)
    claim_id: Any | None = field(default=None, kw_only=True)


@dataclass(frozen=True)
class VerifiedEventualBound(EventualBoundResult):
    """The exact fixed-cutoff checker certified the entire natural-number tail."""

    certificate: ReplayableEventualCertificate

    def export_lean_project(self, path: str, *, verify: bool = True):
        """Export and optionally kernel-check the retained fixed cutoff."""
        from .export import export_verified_eventual_bound

        return export_verified_eventual_bound(self, path, verify=verify)


@dataclass(frozen=True)
class EventualCandidateRejected(EventualBoundResult):
    reason: str


@dataclass(frozen=True)
class InconclusiveEventualBound(EventualBoundResult):
    reason: str


@dataclass(frozen=True)
class UnsupportedEventualBound(EventualBoundResult):
    reason: str


@dataclass
class Certificate:
    """
    A verification certificate that can be saved and reloaded.

    Certificates contain all the information needed to reproduce
    and verify a computation.
    """

    operation: str
    expr_json: dict[str, Any]
    domain_json: list[dict[str, Any]]
    result_json: dict[str, Any]
    verified: bool
    lean_version: str
    leancert_version: str
    computation_time_ms: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "operation": self.operation,
            "expr": self.expr_json,
            "domain": self.domain_json,
            "result": self.result_json,
            "verified": self.verified,
            "lean_version": self.lean_version,
            "leancert_version": self.leancert_version,
            "computation_time_ms": self.computation_time_ms,
            "metadata": self.metadata,
        }

    def save(self, path: str) -> None:
        """Save certificate to a JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> Certificate:
        """Load certificate from a JSON file."""
        with open(path) as f:
            data = json.load(f)

        return cls(
            operation=data["operation"],
            expr_json=data["expr"],
            domain_json=data["domain"],
            result_json=data["result"],
            verified=data["verified"],
            lean_version=data["lean_version"],
            leancert_version=data["leancert_version"],
            computation_time_ms=data.get("computation_time_ms"),
            metadata=data.get("metadata", {}),
        )

    def hash(self) -> str:
        """Compute SHA256 hash of the certificate content."""
        # Create deterministic JSON string
        content = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_lean_tactic(self) -> str:
        """Deprecated compatibility spelling for a non-authoritative proof sketch."""
        warnings.warn(
            "Certificate.to_lean_tactic() is not authoritative; use "
            "Verified.export_lean_project() for replayable evidence",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.render_proof_sketch()

    def render_proof_sketch(self) -> str:
        """
        Render illustrative Lean text without claiming it replays a certificate.

        Returns a string of Lean code that can be pasted into a Lean file.
        This legacy renderer may contain tactic reconstruction and is not an
        independently rebuildable proof artifact.

        Example output for find_bounds:
            theorem bound_check : ∀ x ∈ Set.Icc 0 1, x^2 ≤ 1 := by
              interval_bound 10

        Example output for verify_bound:
            theorem upper_bound_check : ∀ x ∈ I, f x ≤ 1.5 := by
              interval_bound 10
        """
        lines = []
        lines.append(f"-- Certificate hash: {self.hash()[:16]}...")
        lines.append(f"-- Generated from: {self.operation}")
        lines.append("")

        if self.operation == "find_bounds":
            lines.extend(self._to_lean_find_bounds())
        elif self.operation == "verify_bound":
            lines.extend(self._to_lean_verify_bound())
        elif self.operation == "find_roots":
            lines.extend(self._to_lean_find_roots())
        elif self.operation == "integrate":
            lines.extend(self._to_lean_integrate())
        else:
            lines.append(f"-- Unknown operation: {self.operation}")
            lines.append(f"-- Raw result: {self.result_json}")

        return "\n".join(lines)

    def _to_lean_find_bounds(self) -> list[str]:
        """Generate Lean code for find_bounds operation."""
        lines = []
        expr_lean = self._expr_to_lean(self.expr_json)
        min_lo = self.result_json.get("min", {}).get("lo", {})
        min_hi = self.result_json.get("min", {}).get("hi", {})
        max_lo = self.result_json.get("max", {}).get("lo", {})
        max_hi = self.result_json.get("max", {}).get("hi", {})
        taylor_depth = self.metadata.get("taylor_depth", 10)

        is_multivariate = len(self.domain_json) > 1

        lines.append(f"-- Expression: {expr_lean}")
        lines.append(f"-- Domain: {self._domain_to_lean_comment(self.domain_json)}")
        lines.append("")
        # Show full intervals so users see both the proven bound and the tight estimate
        # min_lo is the proven lower bound, min_hi is the tight upper estimate of the minimum
        lines.append(
            f"-- Min ∈ [{self._rat_to_float(min_lo):.6f}, {self._rat_to_float(min_hi):.6f}]"
        )
        lines.append(
            f"-- Max ∈ [{self._rat_to_float(max_lo):.6f}, {self._rat_to_float(max_hi):.6f}]"
        )
        lines.append("")
        lines.append("theorem bounds_check :")

        if is_multivariate:
            # Generate proper nested forall syntax for multivariate
            quantifiers = self._domain_to_lean_quantifiers(self.domain_json)
            lines.append(f"    {quantifiers}")
            lines.append(
                f"    {self._rat_to_float(min_lo):.6f} ≤ {expr_lean} ∧ {expr_lean} ≤ {self._rat_to_float(max_hi):.6f} := by"
            )
            lines.append(f"  multivariate_bound")
        else:
            domain_lean = self._domain_to_lean(self.domain_json)
            lines.append(
                f"    ∀ x ∈ {domain_lean}, {self._rat_to_float(min_lo):.6f} ≤ {expr_lean} ∧ {expr_lean} ≤ {self._rat_to_float(max_hi):.6f} := by"
            )
            lines.append(f"  interval_bound {taylor_depth}")

        return lines

    def _to_lean_verify_bound(self) -> list[str]:
        """Generate Lean code for verify_bound operation."""
        lines = []
        expr_lean = self._expr_to_lean(self.expr_json)
        domain_lean = self._domain_to_lean(self.domain_json)
        taylor_depth = self.metadata.get("taylor_depth", 10)

        bound_type = self.result_json.get("bound_type", "unknown")
        bound_value = self.result_json.get("bound_value", 0)

        lines.append(f"-- Expression: {expr_lean}")
        lines.append(f"-- Domain: {domain_lean}")
        lines.append("")

        if bound_type == "upper":
            lines.append(
                f"theorem upper_bound_check : ∀ x ∈ {domain_lean}, {expr_lean} ≤ {bound_value} := by"
            )
        elif bound_type == "lower":
            lines.append(
                f"theorem lower_bound_check : ∀ x ∈ {domain_lean}, {bound_value} ≤ {expr_lean} := by"
            )
        else:
            lines.append(f"theorem bound_check : ∀ x ∈ {domain_lean}, ... := by")

        lines.append(f"  interval_bound {taylor_depth}")

        return lines

    def _to_lean_find_roots(self) -> list[str]:
        """Generate Lean code for find_roots operation."""
        lines = []
        expr_lean = self._expr_to_lean(self.expr_json)

        lines.append(f"-- Expression: {expr_lean}")
        lines.append("-- Root existence verified via IVT (sign change)")
        lines.append("")
        lines.append("-- Roots found:")

        roots = self.result_json.get("roots", [])
        for i, root in enumerate(roots):
            lo = self._rat_to_float(root.get("lo", {}))
            hi = self._rat_to_float(root.get("hi", {}))
            status = root.get("status", "unknown")
            lines.append(f"-- Root {i + 1}: [{lo:.6f}, {hi:.6f}] (status: {status})")

        lines.append("")
        lines.append("-- To verify existence, use:")
        lines.append("-- theorem root_exists : ∃ x ∈ I, f x = 0 := by")
        lines.append("--   interval_root <root_interval>")

        return lines

    def _to_lean_integrate(self) -> list[str]:
        """Generate Lean code for integrate operation."""
        lines = []
        expr_lean = self._expr_to_lean(self.expr_json)
        lo = self.result_json.get("lo", {})
        hi = self.result_json.get("hi", {})
        taylor_depth = self.metadata.get("taylor_depth", 10)

        lines.append(f"-- Expression: {expr_lean}")
        lines.append(
            f"-- Integral bounds: [{self._rat_to_float(lo):.6f}, {self._rat_to_float(hi):.6f}]"
        )
        lines.append("")
        lines.append(f"-- theorem integral_bound : ∫ x in I, {expr_lean} ∈ bounds := by")
        lines.append(f"--   interval_integrate {taylor_depth}")

        return lines

    def _expr_to_lean(self, expr: dict) -> str:
        """Convert expression JSON to Lean syntax (approximate)."""
        kind = expr.get("kind", "")

        if kind == "const":
            val = expr.get("val", {})
            n, d = val.get("n", 0), val.get("d", 1)
            if d == 1:
                return str(n)
            return f"({n}/{d})"
        elif kind == "var":
            idx = expr.get("idx", 0)
            return f"x{idx}" if idx > 0 else "x"
        elif kind == "add":
            e1 = self._expr_to_lean(expr.get("e1", {}))
            e2 = self._expr_to_lean(expr.get("e2", {}))
            return f"({e1} + {e2})"
        elif kind == "mul":
            e1 = self._expr_to_lean(expr.get("e1", {}))
            e2 = self._expr_to_lean(expr.get("e2", {}))
            return f"({e1} * {e2})"
        elif kind == "neg":
            e = self._expr_to_lean(expr.get("e", {}))
            return f"(-{e})"
        elif kind == "div":
            e1 = self._expr_to_lean(expr.get("e1", {}))
            e2 = self._expr_to_lean(expr.get("e2", {}))
            return f"({e1} / {e2})"
        elif kind == "pow":
            base = self._expr_to_lean(expr.get("base", {}))
            exp = expr.get("exp", 0)
            return f"({base}^{exp})"
        elif kind in (
            "sin",
            "cos",
            "exp",
            "log",
            "sqrt",
            "tan",
            "atan",
            "inv",
            "arsinh",
            "atanh",
            "sinc",
            "erf",
        ):
            e = self._expr_to_lean(expr.get("e", {}))
            return f"Real.{kind} {e}"
        else:
            return f"<{kind}?>"

    def _domain_to_lean(self, domain: list) -> str:
        """Convert domain JSON to Lean syntax for single variable."""
        if len(domain) == 1:
            lo = self._rat_to_float(domain[0].get("lo", {}))
            hi = self._rat_to_float(domain[0].get("hi", {}))
            return f"Set.Icc {lo} {hi}"
        else:
            # For multivariate, use first interval (caller should use _domain_to_lean_quantifiers)
            lo = self._rat_to_float(domain[0].get("lo", {}))
            hi = self._rat_to_float(domain[0].get("hi", {}))
            return f"Set.Icc {lo} {hi}"

    def _domain_to_lean_comment(self, domain: list) -> str:
        """Convert domain JSON to human-readable comment format."""
        if len(domain) == 1:
            lo = self._rat_to_float(domain[0].get("lo", {}))
            hi = self._rat_to_float(domain[0].get("hi", {}))
            return f"Set.Icc {lo} {hi}"
        else:
            intervals = []
            var_names = self._get_var_names(len(domain))
            for i, d in enumerate(domain):
                lo = self._rat_to_float(d.get("lo", {}))
                hi = self._rat_to_float(d.get("hi", {}))
                intervals.append(f"{var_names[i]} ∈ [{lo}, {hi}]")
            return " × ".join(intervals)

    def _domain_to_lean_quantifiers(self, domain: list) -> str:
        """Convert domain JSON to nested forall quantifiers for Lean."""
        var_names = self._get_var_names(len(domain))
        parts = []
        for i, d in enumerate(domain):
            lo = self._rat_to_float(d.get("lo", {}))
            hi = self._rat_to_float(d.get("hi", {}))
            parts.append(f"∀ {var_names[i]} ∈ Set.Icc {lo} {hi},")
        return " ".join(parts)

    def _get_var_names(self, count: int) -> list[str]:
        """Get variable names for the given count."""
        if count == 1:
            return ["x"]
        elif count == 2:
            return ["x", "y"]
        elif count == 3:
            return ["x", "y", "z"]
        else:
            return [f"x{i}" for i in range(count)]

    def _rat_to_float(self, rat: dict) -> float:
        """Convert rational JSON to float."""
        n = rat.get("n", 0)
        d = rat.get("d", 1)
        return n / d if d != 0 else 0.0

    def __repr__(self) -> str:
        status = "verified" if self.verified else "unverified"
        return f"Certificate({self.operation}, {status}, hash={self.hash()[:8]}...)"


@dataclass
class BoundsResult:
    """
    Result of finding global bounds.

    Contains intervals enclosing the minimum and maximum values,
    along with a verification certificate.

    Access Patterns:
        # Get the interval bounds (Interval objects)
        result.min_bound  # Interval containing true minimum
        result.max_bound  # Interval containing true maximum

        # Get exact Fraction endpoints
        result.min_bound.lo  # Lower bound of min interval (rigorous)
        result.max_bound.hi  # Upper bound of max interval (rigorous)

        # Get float approximations (for comparisons/display)
        result.min_lo  # float(min_bound.lo) - guaranteed lower bound
        result.min_hi  # float(min_bound.hi) - upper estimate of minimum
        result.max_lo  # float(max_bound.lo) - lower estimate of maximum
        result.max_hi  # float(max_bound.hi) - guaranteed upper bound

        # Get midpoint approximations
        result.min_value  # midpoint of min_bound (approximate)
        result.max_value  # midpoint of max_bound (approximate)
    """

    min_bound: Interval
    max_bound: Interval
    verified: bool
    certificate: Optional[Certificate] = None

    # --- Convenience float accessors for bounds ---

    @property
    def min_lo(self) -> float:
        """Guaranteed lower bound on minimum value."""
        return float(self.min_bound.lo)

    @property
    def min_hi(self) -> float:
        """Upper estimate of minimum value."""
        return float(self.min_bound.hi)

    @property
    def max_lo(self) -> float:
        """Lower estimate of maximum value."""
        return float(self.max_bound.lo)

    @property
    def max_hi(self) -> float:
        """Guaranteed upper bound on maximum value."""
        return float(self.max_bound.hi)

    @property
    def min_value(self) -> float:
        """Approximate minimum (midpoint of min_bound)."""
        return float(self.min_bound.midpoint())

    @property
    def max_value(self) -> float:
        """Approximate maximum (midpoint of max_bound)."""
        return float(self.max_bound.midpoint())

    def save(self, path: str) -> None:
        """Save the certificate to a file."""
        if self.certificate:
            self.certificate.save(path)
        else:
            raise ValueError("No certificate available to save")

    def __repr__(self) -> str:
        status = "verified" if self.verified else "unverified"
        return (
            f"BoundsResult(\n"
            f"  min_bound={self.min_bound},\n"
            f"  max_bound={self.max_bound},\n"
            f"  verified={self.verified}\n"
            f")"
        )


@dataclass
class RootInterval:
    """
    A single root interval with its status.

    Access Patterns:
        root.interval       # The Interval object
        root.status         # 'confirmed', 'possible', 'no_root', 'unique'
        root.lo             # float lower bound of interval
        root.hi             # float upper bound of interval
        root.value          # float midpoint (approximate root location)
        root.width          # float interval width (uncertainty)
    """

    interval: Interval
    status: str  # 'confirmed', 'possible', 'no_root', 'unique'

    @property
    def lo(self) -> float:
        """Lower bound of root interval."""
        return float(self.interval.lo)

    @property
    def hi(self) -> float:
        """Upper bound of root interval."""
        return float(self.interval.hi)

    @property
    def value(self) -> float:
        """Approximate root value (midpoint of interval)."""
        return float(self.interval.midpoint())

    @property
    def width(self) -> float:
        """Width of root interval (uncertainty measure)."""
        return float(self.interval.width())

    def __repr__(self) -> str:
        return f"RootInterval({self.interval}, status='{self.status}')"


@dataclass
class UniqueRootResult:
    """
    Result of unique root finding via Newton contraction.

    When Newton iteration contracts, it proves both existence AND uniqueness
    of a root in the interval. This is a mathematically stronger result
    than ordinary root finding (which only proves existence via sign change).

    Access Patterns:
        result.unique       # bool - True if unique root proven
        result.interval     # Interval object containing the root
        result.reason       # 'newton_contraction', 'no_contraction', 'newton_step_failed'
        result.lo           # float lower bound
        result.hi           # float upper bound
        result.root_value   # float midpoint (approximate root)
        result.width        # float interval width (uncertainty)
    """

    unique: bool  # True if unique root proven
    interval: Interval  # Refined interval containing the root
    reason: str  # 'newton_contraction', 'no_contraction', 'newton_step_failed'
    certificate: Optional[Certificate] = None

    @property
    def lo(self) -> float:
        """Lower bound of root interval."""
        return float(self.interval.lo)

    @property
    def hi(self) -> float:
        """Upper bound of root interval."""
        return float(self.interval.hi)

    @property
    def root_value(self) -> float:
        """Approximate root value (midpoint of interval)."""
        return float(self.interval.midpoint())

    @property
    def width(self) -> float:
        """Width of root interval (uncertainty measure)."""
        return float(self.interval.width())

    def __repr__(self) -> str:
        if self.unique:
            return f"UniqueRootResult(UNIQUE root in {self.interval})"
        return f"UniqueRootResult(not proven unique, {self.reason})"


@dataclass
class RootsResult:
    """
    Result of finding roots.

    Contains intervals that may contain roots, with status indicating
    the certainty level.
    """

    roots: list[RootInterval]
    iterations: int
    verified: bool
    certificate: Optional[Certificate] = None

    def confirmed_roots(self) -> list[RootInterval]:
        """Return only roots with confirmed sign change."""
        return [r for r in self.roots if r.status == "confirmed"]

    def possible_roots(self) -> list[RootInterval]:
        """Return roots that may exist but aren't confirmed."""
        return [r for r in self.roots if r.status == "possible"]

    def __repr__(self) -> str:
        confirmed = len(self.confirmed_roots())
        total = len(self.roots)
        return f"RootsResult({confirmed}/{total} confirmed, {self.iterations} iterations)"


@dataclass
class IntegralResult:
    """
    Result of numerical integration.

    Contains an interval enclosing the true integral value.

    Access Patterns:
        result.bounds       # Interval object enclosing true integral
        result.verified     # bool verification status
        result.lo           # float guaranteed lower bound
        result.hi           # float guaranteed upper bound
        result.value        # float midpoint (approximate integral)
        result.error        # float maximum error (interval width)
    """

    bounds: Interval
    verified: bool
    certificate: Optional[Certificate] = None

    @property
    def lo(self) -> float:
        """Guaranteed lower bound on integral."""
        return float(self.bounds.lo)

    @property
    def hi(self) -> float:
        """Guaranteed upper bound on integral."""
        return float(self.bounds.hi)

    @property
    def value(self) -> float:
        """Approximate integral value (midpoint)."""
        return float(self.bounds.midpoint())

    @property
    def error(self) -> float:
        """Maximum error (width of bounds interval)."""
        return float(self.bounds.width())

    def error_bound(self) -> Fraction:
        """Maximum error (width of the bounds interval). Returns exact Fraction."""
        return self.bounds.width()

    def __repr__(self) -> str:
        return f"IntegralResult(bounds={self.bounds}, error<={self.error:.2e})"


@dataclass
class VerifyResult:
    """
    Result of bound verification.

    Indicates whether a claimed bound was verified.

    Access Patterns:
        result.verified         # bool - True if bound verified
        result.computed_bound   # Interval object with actual computed bound
        result.lo               # float lower bound of computed interval
        result.hi               # float upper bound of computed interval
        result.value            # float midpoint of computed interval
    """

    verified: bool
    computed_bound: Interval
    certificate: Optional[Certificate] = None

    @property
    def lo(self) -> float:
        """Lower bound of computed interval."""
        return float(self.computed_bound.lo)

    @property
    def hi(self) -> float:
        """Upper bound of computed interval."""
        return float(self.computed_bound.hi)

    @property
    def value(self) -> float:
        """Midpoint of computed interval."""
        return float(self.computed_bound.midpoint())

    def __repr__(self) -> str:
        status = "VERIFIED" if self.verified else "FAILED"
        return f"VerifyResult({status}, computed={self.computed_bound})"


# =============================================================================
# Witness Synthesis Results
# =============================================================================
# These types support auto-witness synthesis for existential proof goals.
# Lean can delegate existential witness construction to Python, which finds
# witnesses via optimization/root-finding and returns certificate-checked results.


@dataclass
class WitnessPoint:
    """
    A concrete witness point with variable values and function value.

    This represents a specific point in the domain along with the function
    value at that point. Used for existential proofs where we need to
    exhibit a concrete witness.

    Attributes:
        values: Dictionary mapping variable names to their witness values (exact Fractions)
        function_value: The function value at the witness point (exact Fraction)
        interval: Dictionary mapping variable names to (lo, hi) tuples representing
                  the enclosing interval from which this witness was derived
    """

    values: dict[str, Fraction]
    function_value: Fraction
    interval: dict[str, tuple[Fraction, Fraction]]

    def value_at(self, var_name: str) -> float:
        """Get the float value of a variable at this witness point."""
        return float(self.values.get(var_name, 0))

    @property
    def function_value_float(self) -> float:
        """Get the function value as a float."""
        return float(self.function_value)

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "values": {k: {"n": v.numerator, "d": v.denominator} for k, v in self.values.items()},
            "function_value": {
                "n": self.function_value.numerator,
                "d": self.function_value.denominator,
            },
            "interval": {
                k: {
                    "lo": {"n": lo.numerator, "d": lo.denominator},
                    "hi": {"n": hi.numerator, "d": hi.denominator},
                }
                for k, (lo, hi) in self.interval.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WitnessPoint":
        """Create from JSON dictionary."""
        values = {k: Fraction(v["n"], v["d"]) for k, v in data["values"].items()}
        function_value = Fraction(data["function_value"]["n"], data["function_value"]["d"])
        interval = {
            k: (Fraction(v["lo"]["n"], v["lo"]["d"]), Fraction(v["hi"]["n"], v["hi"]["d"]))
            for k, v in data["interval"].items()
        }
        return cls(values=values, function_value=function_value, interval=interval)

    def __repr__(self) -> str:
        vals = ", ".join(f"{k}={float(v):.6f}" for k, v in self.values.items())
        return f"WitnessPoint({vals}, f={self.function_value_float:.6f})"


@dataclass
class WitnessResult:
    """Base class for witness synthesis results."""

    verified: bool
    certificate: Optional[Certificate] = None
    strategy_used: str = "dyadic"
    refinement_history: list[dict] = field(default_factory=list)


@dataclass
class MinWitnessResult(WitnessResult):
    """
    Result of synthesizing a minimum witness.

    Proves: ∃ m, ∀ x ∈ I, f(x) ≥ m

    Attributes:
        witness_value: The witness value m (exact Fraction)
        witness_point: The point where the minimum is achieved
        proven_bound: The rigorous lower bound from interval arithmetic
        verified: Whether the witness was verified
    """

    witness_value: Fraction = field(default_factory=lambda: Fraction(0))
    witness_point: Optional[WitnessPoint] = None
    proven_bound: Fraction = field(default_factory=lambda: Fraction(0))

    def to_lean_tactic(self) -> str:
        """Generate Lean tactic code for this minimum witness proof."""
        lines = []
        lines.append("-- Auto-synthesized minimum witness")
        lines.append(f"-- Witness value: {float(self.witness_value):.10f}")
        if self.witness_point:
            vals = ", ".join(f"{k} = {float(v):.6f}" for k, v in self.witness_point.values.items())
            lines.append(f"-- Achieved at: {vals}")
        lines.append(f"-- Proven bound: {float(self.proven_bound):.10f}")
        lines.append("")
        lines.append("-- Proof: ∃ m, ∀ x ∈ I, f(x) ≥ m")
        lines.append(f"use {self._fraction_to_lean(self.witness_value)}")
        lines.append("intro x hx")
        lines.append("interval_min_witness")
        return "\n".join(lines)

    def _fraction_to_lean(self, f: Fraction) -> str:
        """Convert fraction to Lean rational literal."""
        if f.denominator == 1:
            return str(f.numerator)
        return f"({f.numerator} / {f.denominator})"

    def __repr__(self) -> str:
        status = "VERIFIED" if self.verified else "UNVERIFIED"
        return f"MinWitnessResult({status}, m={float(self.witness_value):.6f})"


@dataclass
class MaxWitnessResult(WitnessResult):
    """
    Result of synthesizing a maximum witness.

    Proves: ∃ M, ∀ x ∈ I, f(x) ≤ M

    Attributes:
        witness_value: The witness value M (exact Fraction)
        witness_point: The point where the maximum is achieved
        proven_bound: The rigorous upper bound from interval arithmetic
        verified: Whether the witness was verified
    """

    witness_value: Fraction = field(default_factory=lambda: Fraction(0))
    witness_point: Optional[WitnessPoint] = None
    proven_bound: Fraction = field(default_factory=lambda: Fraction(0))

    def to_lean_tactic(self) -> str:
        """Generate Lean tactic code for this maximum witness proof."""
        lines = []
        lines.append("-- Auto-synthesized maximum witness")
        lines.append(f"-- Witness value: {float(self.witness_value):.10f}")
        if self.witness_point:
            vals = ", ".join(f"{k} = {float(v):.6f}" for k, v in self.witness_point.values.items())
            lines.append(f"-- Achieved at: {vals}")
        lines.append(f"-- Proven bound: {float(self.proven_bound):.10f}")
        lines.append("")
        lines.append("-- Proof: ∃ M, ∀ x ∈ I, f(x) ≤ M")
        lines.append(f"use {self._fraction_to_lean(self.witness_value)}")
        lines.append("intro x hx")
        lines.append("interval_max_witness")
        return "\n".join(lines)

    def _fraction_to_lean(self, f: Fraction) -> str:
        """Convert fraction to Lean rational literal."""
        if f.denominator == 1:
            return str(f.numerator)
        return f"({f.numerator} / {f.denominator})"

    def __repr__(self) -> str:
        status = "VERIFIED" if self.verified else "UNVERIFIED"
        return f"MaxWitnessResult({status}, M={float(self.witness_value):.6f})"


@dataclass
class RootWitnessResult(WitnessResult):
    """
    Result of synthesizing a root witness.

    Proves: ∃ x ∈ I, f(x) = 0

    Attributes:
        witness_point: The point where f(x) ≈ 0
        root_interval: The interval guaranteed to contain the root
        verified: Whether the witness was verified (via sign change or Newton)
    """

    witness_point: Optional[WitnessPoint] = None
    root_interval: Optional[Interval] = None
    proof_method: str = "sign_change"  # 'sign_change' or 'newton_contraction'

    def to_lean_tactic(self) -> str:
        """Generate Lean tactic code for this root witness proof."""
        lines = []
        lines.append("-- Auto-synthesized root witness")
        if self.witness_point:
            vals = ", ".join(f"{k} = {float(v):.6f}" for k, v in self.witness_point.values.items())
            lines.append(f"-- Witness point: {vals}")
        if self.root_interval:
            lines.append(
                f"-- Root interval: [{float(self.root_interval.lo):.10f}, {float(self.root_interval.hi):.10f}]"
            )
        lines.append(f"-- Proof method: {self.proof_method}")
        lines.append("")
        lines.append("-- Proof: ∃ x ∈ I, f(x) = 0")
        lines.append("interval_root_witness")
        return "\n".join(lines)

    def __repr__(self) -> str:
        status = "VERIFIED" if self.verified else "UNVERIFIED"
        if self.witness_point:
            x_val = list(self.witness_point.values.values())[0] if self.witness_point.values else 0
            return f"RootWitnessResult({status}, x≈{float(x_val):.6f})"
        return f"RootWitnessResult({status})"


@dataclass
class FailureDiagnosis:
    """
    Diagnosis of why a bound verification failed.

    Used for Counterexample-Guided Proof Refinement (CEGPR).

    Attributes:
        failure_type: Type of failure ('bound_too_tight', 'no_root', etc.)
        margin: How much the bound was missed by (negative = violated)
        worst_point: Dictionary of variable values at the worst point
        suggested_bound: A suggested bound that would succeed
    """

    failure_type: str
    margin: float
    worst_point: dict[str, float]
    suggested_bound: float

    def __repr__(self) -> str:
        return f"FailureDiagnosis({self.failure_type}, margin={self.margin:.6f}, suggested={self.suggested_bound:.6f})"


@dataclass
class LipschitzResult:
    """
    Result of Lipschitz bound computation.

    The Lipschitz constant L satisfies: |f(x) - f(y)| ≤ L * |x - y| for all x, y in the domain.
    This is computed by bounding the gradient: L = max_i sup_{x} |∂f/∂xᵢ(x)|.

    Attributes:
        lipschitz_bound: The verified Lipschitz constant L.
        gradient_bounds: Dict mapping variable names to derivative interval bounds.
        certificate: Verification certificate from the Lean kernel.

    Use case (ε-δ continuity):
        For any ε > 0, setting δ = ε/L guarantees:
        |x - a| < δ → |f(x) - f(a)| < ε

    Example:
        >>> result = solver.compute_lipschitz_bound(x**2, {'x': (0, 1)})
        >>> L = result.lipschitz_bound  # = 2 (max of |2x| on [0,1])
        >>> epsilon = 0.1
        >>> delta = epsilon / L  # = 0.05
        >>> # Now |x - a| < 0.05 guarantees |x² - a²| < 0.1
    """

    lipschitz_bound: Fraction
    gradient_bounds: dict[str, "Interval"]
    certificate: Optional[Certificate] = None

    def delta_for_epsilon(self, epsilon: float) -> float:
        """
        Compute δ such that |x - a| < δ → |f(x) - f(a)| < ε.

        Args:
            epsilon: The desired error bound ε > 0.

        Returns:
            δ = ε / L where L is the Lipschitz constant.
        """
        L = float(self.lipschitz_bound)
        if L <= 0:
            return float("inf")  # Constant function
        return epsilon / L

    def to_lean_tactic(self) -> str:
        """Generate Lean tactic proof for Lipschitz continuity."""
        L = self.lipschitz_bound
        lines = [
            "-- Lipschitz bound computed via gradient interval arithmetic",
            f"-- L = {float(L):.10f} = {L.numerator}/{L.denominator}",
            "--",
            "-- Proof: |f(x) - f(y)| ≤ L * |x - y| by Mean Value Theorem",
            "-- where L bounds |∇f| over the domain.",
            "",
            "-- Gradient bounds:",
        ]
        for var, interval in self.gradient_bounds.items():
            lines.append(f"--   ∂f/∂{var} ∈ [{float(interval.lo):.6f}, {float(interval.hi):.6f}]")

        lines.extend(
            [
                "",
                f"use ({L.numerator} / {L.denominator})",
                "intro x y hx hy",
                "-- Apply MVT: |f(x) - f(y)| ≤ sup|f'| * |x - y|",
                "apply lipschitz_of_deriv_bound",
                "· -- Derivative bound",
                "  interval_deriv_bound",
            ]
        )

        return "\n".join(lines)

    def __repr__(self) -> str:
        L = float(self.lipschitz_bound)
        return f"LipschitzResult(L={L:.6f}, vars={list(self.gradient_bounds.keys())})"
