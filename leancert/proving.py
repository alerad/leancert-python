"""Unified checked proving front door for semantic AST claims."""

from __future__ import annotations

import atexit
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from fractions import Fraction
from math import isfinite
from numbers import Real

from . import ast
from .client import LeanClient
from .operations.bounds import execute_bound_plan, try_plan_bound_claim, unsupported_result
from .operations.eventual import (
    execute_eventual_plan,
    try_plan_eventual_claim,
    unsupported_eventual,
)
from .operations.integrals import (
    contains_integral,
    execute_integral_plan,
    try_plan_integral_claim,
)
from .operations.scalar_roots import execute_scalar_root_claim
from .operations.system_roots import (
    SystemRootPlan,
    execute_system_root_plan,
)
from .result import (
    IncompleteConjunction,
    NormalizedFalse,
    NormalizedTrue,
    ProofResult,
    Verified,
    VerifiedConjunction,
    VerifiedEventualBound,
    VerifiedIntegralBound,
    VerifiedIntegralEquality,
    VerifiedRootExclusion,
    VerifiedRootExistence,
    VerifiedSystemRoot,
    VerifiedUniqueRoot,
)

_DEFAULT_PROVE_CLIENT: LeanClient | None = None
_DEFAULT_PROVE_CLIENT_LOCK = threading.Lock()


def _default_prove_client() -> LeanClient:
    """Lazily create the process-wide client used by the convenience API."""
    global _DEFAULT_PROVE_CLIENT
    with _DEFAULT_PROVE_CLIENT_LOCK:
        if _DEFAULT_PROVE_CLIENT is None:
            _DEFAULT_PROVE_CLIENT = LeanClient()
        return _DEFAULT_PROVE_CLIENT


def close_default_prove_client() -> None:
    """Close and forget the client retained by module-level :func:`prove`."""
    global _DEFAULT_PROVE_CLIENT
    with _DEFAULT_PROVE_CLIENT_LOCK:
        client, _DEFAULT_PROVE_CLIENT = _DEFAULT_PROVE_CLIENT, None
    if client is not None:
        client.close()


atexit.register(close_default_prove_client)


def _candidate_fraction(value: object, maximum_denominator: int) -> Fraction:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError("Krawczyk candidate values must be real numbers")
    if isinstance(value, Fraction):
        result = value
    elif isinstance(value, int):
        result = Fraction(value)
    else:
        numeric = float(value)
        if not isfinite(numeric):
            raise ValueError("Krawczyk candidate values must be finite")
        result = Fraction(str(numeric))
    return result.limit_denominator(maximum_denominator)


@dataclass(frozen=True, slots=True)
class KrawczykCandidate:
    """Untrusted rationalized center and approximate inverse Jacobian."""

    center: tuple[Fraction, ...]
    preconditioner: tuple[tuple[Fraction, ...], ...]

    @classmethod
    def from_arrays(
        cls,
        center,
        preconditioner,
        *,
        maximum_denominator: int = 2**20,
    ) -> KrawczykCandidate:
        if (
            isinstance(maximum_denominator, bool)
            or not isinstance(maximum_denominator, int)
            or maximum_denominator <= 0
        ):
            raise ValueError("maximum_denominator must be a positive integer")
        center_values = tuple(_candidate_fraction(value, maximum_denominator) for value in center)
        matrix = tuple(
            tuple(_candidate_fraction(value, maximum_denominator) for value in row)
            for row in preconditioner
        )
        dimension = len(center_values)
        if (
            dimension == 0
            or len(matrix) != dimension
            or any(len(row) != dimension for row in matrix)
        ):
            raise ValueError("Krawczyk center and preconditioner must have square dimensions")
        return cls(center_values, matrix)

    def to_wire(self) -> dict[str, object]:
        def rat(value: Fraction) -> dict[str, int]:
            return {"n": value.numerator, "d": value.denominator}

        return {
            "center": [rat(value) for value in self.center],
            "preconditioner": [[rat(value) for value in row] for row in self.preconditioner],
        }


@dataclass(frozen=True, slots=True)
class SystemRootConfig:
    max_iterations: int = 8
    max_dimension: int = 4
    precision_bits: int = 20
    candidate: KrawczykCandidate | None = None

    def __post_init__(self) -> None:
        for name, value, positive in (
            ("max_iterations", self.max_iterations, False),
            ("max_dimension", self.max_dimension, True),
            ("precision_bits", self.precision_bits, False),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < (1 if positive else 0)
            ):
                qualifier = "positive" if positive else "non-negative"
                raise ValueError(f"{name} must be a {qualifier} integer")
        if self.candidate is not None and not isinstance(self.candidate, KrawczykCandidate):
            raise TypeError("candidate must be a KrawczykCandidate")


@dataclass(frozen=True, slots=True)
class EventualConfig:
    max_checks: int = 1000

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_checks, bool)
            or not isinstance(self.max_checks, int)
            or self.max_checks <= 0
        ):
            raise ValueError("max_checks must be a positive integer")


@dataclass(frozen=True, slots=True)
class RefutationConfig:
    """Bounded search budget for checked rational point-box refutations."""

    enabled: bool = False
    max_candidates: int = 27

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled must be a boolean")
        if (
            isinstance(self.max_candidates, bool)
            or not isinstance(self.max_candidates, int)
            or self.max_candidates <= 0
        ):
            raise ValueError("max_candidates must be a positive integer")


@dataclass(frozen=True, slots=True)
class IntegralConfig:
    """Effort controls for untrusted uniform-partition discovery."""

    start_partitions: int = 32
    max_partitions: int = 4096

    def __post_init__(self) -> None:
        for name, value in (
            ("start_partitions", self.start_partitions),
            ("max_partitions", self.max_partitions),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_partitions < self.start_partitions:
            raise ValueError("max_partitions must be at least start_partitions")


@dataclass(frozen=True, slots=True)
class RegisteredEnclosureConfig:
    """Effort controls accepted by Contract 2.8 registered enclosures."""

    precision: int = -53
    max_depth: int = 4

    def __post_init__(self) -> None:
        if isinstance(self.precision, bool) or not isinstance(self.precision, int):
            raise TypeError("precision must be an integer")
        if (
            isinstance(self.max_depth, bool)
            or not isinstance(self.max_depth, int)
            or self.max_depth < 0
        ):
            raise ValueError("max_depth must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class ProveConfig:
    """Effort controls for checked claim execution.

    Contract 2.0's checked bound capability selects its own advertised
    numerical backend and verification route. The Python caller controls only
    checker effort that the request schema actually accepts.
    """

    taylor_depth: int = 10
    system_root: SystemRootConfig = field(default_factory=SystemRootConfig)
    eventual: EventualConfig = field(default_factory=EventualConfig)
    integral: IntegralConfig = field(default_factory=IntegralConfig)
    refutation: RefutationConfig = field(default_factory=RefutationConfig)
    registered_enclosure: RegisteredEnclosureConfig = field(
        default_factory=RegisteredEnclosureConfig
    )

    def __post_init__(self) -> None:
        if (
            isinstance(self.taylor_depth, bool)
            or not isinstance(self.taylor_depth, int)
            or self.taylor_depth < 0
        ):
            raise ValueError("taylor_depth must be a non-negative integer")
        if not isinstance(self.system_root, SystemRootConfig):
            raise TypeError("system_root must be a SystemRootConfig")
        if not isinstance(self.eventual, EventualConfig):
            raise TypeError("eventual must be an EventualConfig")
        if not isinstance(self.integral, IntegralConfig):
            raise TypeError("integral must be an IntegralConfig")
        if not isinstance(self.refutation, RefutationConfig):
            raise TypeError("refutation must be a RefutationConfig")
        if not isinstance(self.registered_enclosure, RegisteredEnclosureConfig):
            raise TypeError("registered_enclosure must be a RegisteredEnclosureConfig")


def prove(
    claim: ast.Claim,
    *,
    where: Mapping[ast.Variable, ast.Domain | tuple[object, object]] | None = None,
    config: ProveConfig | None = None,
    client: LeanClient | None = None,
) -> ProofResult:
    """Check a semantic claim through an explicitly negotiated bridge capability.

    The first public route supports exact one- and two-sided real bounds. Other
    valid claim families return :class:`Unsupported`; malformed or open claims
    raise AST validation errors before any bridge request is sent.
    """
    if not isinstance(claim, ast.Claim):
        raise TypeError("prove expects a leancert.ast.Claim")
    config = ProveConfig() if config is None else config
    if not isinstance(config, ProveConfig):
        raise TypeError("config must be a ProveConfig")

    normalized_claim = ast.close_claim(claim, where)
    logical = _logical_constant(normalized_claim)
    if logical is True:
        return NormalizedTrue(claim, normalized_claim, ast.semantic_digest(normalized_claim))
    if logical is False:
        return NormalizedFalse(claim, normalized_claim, ast.semantic_digest(normalized_claim))

    active_client = _default_prove_client() if client is None else client
    return _prove_normalized(claim, normalized_claim, config, active_client)


def _bounded_conjunction_children(claim: ast.Claim) -> tuple[ast.Claim, ...] | None:
    binders: list[ast.Binder] = []
    body = claim
    while isinstance(body, ast.BoundedForAllClaim):
        binders.append(body.binder)
        body = body.body
    if not isinstance(body, ast.ConjunctionClaim):
        return None

    children: list[ast.Claim] = []
    for item in body.claims:
        child: ast.Claim = item
        for binder in reversed(binders):
            child = ast.BoundedForAllClaim(binder, child)
        children.append(ast.normalize(child))
    return tuple(children)


def _bounded_equality_children(claim: ast.Claim) -> tuple[ast.Claim, ...] | None:
    binders: list[ast.Binder] = []
    body = claim
    while isinstance(body, ast.BoundedForAllClaim):
        binders.append(body.binder)
        body = body.body
    if not isinstance(body, ast.ComparisonClaim) or body.relation is not ast.Relation.EQ:
        return None

    comparisons = (
        ast.ComparisonClaim(body.lhs, ast.Relation.LE, body.rhs),
        ast.ComparisonClaim(body.rhs, ast.Relation.LE, body.lhs),
    )
    children: list[ast.Claim] = []
    for comparison in comparisons:
        child: ast.Claim = comparison
        for binder in reversed(binders):
            child = ast.BoundedForAllClaim(binder, child)
        children.append(ast.normalize(child))
    return tuple(children)


def _logical_constant(claim: ast.Claim) -> bool | None:
    body = claim
    has_empty_domain = False
    has_unknown_domain = False
    while isinstance(body, ast.BoundedForAllClaim):
        domain = body.binder.domain
        if isinstance(domain, ast.Interval):
            lower = ast.normalize(domain.lower)
            upper = ast.normalize(domain.upper)
            if not isinstance(lower, ast.RationalConstant) or not isinstance(
                upper, ast.RationalConstant
            ):
                has_unknown_domain = True
            elif lower.value > upper.value or (
                lower.value == upper.value and not (domain.lower_closed and domain.upper_closed)
            ):
                has_empty_domain = True
        else:
            has_unknown_domain = True
        body = body.body
    if isinstance(body, ast.TrueClaim):
        return True
    if isinstance(body, ast.FalseClaim):
        if has_empty_domain:
            return True
        if not has_unknown_domain:
            return False
    return None


def _established(result: ProofResult) -> bool:
    return isinstance(
        result,
        (
            Verified,
            VerifiedSystemRoot,
            VerifiedEventualBound,
            VerifiedIntegralBound,
            VerifiedIntegralEquality,
            VerifiedRootExistence,
            VerifiedUniqueRoot,
            VerifiedRootExclusion,
            VerifiedConjunction,
            NormalizedTrue,
        ),
    )


def _prove_normalized(
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    config: ProveConfig,
    client: LeanClient,
) -> ProofResult:
    claim_id = ast.semantic_digest(normalized_claim)
    assert isinstance(claim_id, ast.ClaimDigest)
    logical = _logical_constant(normalized_claim)
    if logical is True:
        return NormalizedTrue(original_claim, normalized_claim, claim_id)
    if logical is False:
        return NormalizedFalse(original_claim, normalized_claim, claim_id)

    if isinstance(normalized_claim, ast.SystemRootClaim):
        return execute_system_root_plan(
            SystemRootPlan(normalized_claim),
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            client=client,
            config=config.system_root,
            taylor_depth=config.taylor_depth,
        )
    if isinstance(normalized_claim, ast.RootExistsClaim):
        return execute_scalar_root_claim(
            normalized_claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            client=client,
            taylor_depth=config.taylor_depth,
        )
    if isinstance(normalized_claim, ast.EventualClaim):
        plan, unsupported_reason = try_plan_eventual_claim(normalized_claim)
        if plan is None:
            assert unsupported_reason is not None
            return unsupported_eventual(
                normalized_claim,
                original_claim=original_claim,
                normalized_claim=normalized_claim,
                claim_id=claim_id,
                reason=unsupported_reason,
            )
        return execute_eventual_plan(
            plan,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            client=client,
            max_checks=config.eventual.max_checks,
        )
    if contains_integral(normalized_claim):
        integral_plan, integral_reason = try_plan_integral_claim(normalized_claim)
        if integral_plan is None:
            assert integral_reason is not None
            return unsupported_result(original_claim, normalized_claim, claim_id, integral_reason)
        return execute_integral_plan(
            integral_plan,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            client=client,
            start_partitions=config.integral.start_partitions,
            max_partitions=config.integral.max_partitions,
        )
    plan, unsupported_reason = try_plan_bound_claim(normalized_claim)
    if plan is not None:
        if ast.collect_external_functions(plan.expression):
            from .operations.enclosures import execute_registered_enclosure_plan

            return execute_registered_enclosure_plan(
                plan,
                original_claim=original_claim,
                normalized_claim=normalized_claim,
                claim_id=claim_id,
                client=client,
                precision=config.registered_enclosure.precision,
                taylor_depth=config.taylor_depth,
                max_depth=config.registered_enclosure.max_depth,
            )
        return execute_bound_plan(
            plan,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            client=client,
            taylor_depth=config.taylor_depth,
            refutation_config=config.refutation,
        )

    aggregate_children = _bounded_conjunction_children(normalized_claim)
    if aggregate_children is None:
        aggregate_children = _bounded_equality_children(normalized_claim)
    if aggregate_children is not None:
        children = tuple(
            _prove_normalized(child, child, config, client) for child in aggregate_children
        )
        result_type = (
            VerifiedConjunction
            if all(_established(child) for child in children)
            else IncompleteConjunction
        )
        return result_type(children, original_claim, normalized_claim, claim_id)

    assert unsupported_reason is not None
    return unsupported_result(original_claim, normalized_claim, claim_id, unsupported_reason)


__all__ = [
    "EventualConfig",
    "IntegralConfig",
    "KrawczykCandidate",
    "ProveConfig",
    "RefutationConfig",
    "RegisteredEnclosureConfig",
    "SystemRootConfig",
    "prove",
]
