"""Unified checked proving front door for semantic AST claims."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from fractions import Fraction
from math import isfinite
from numbers import Real

from . import ast
from .client import LeanClient
from .operations.bounds import execute_bound_plan, try_plan_bound_claim, unsupported_result
from .operations.system_roots import (
    SystemRootPlan,
    execute_system_root_plan,
    unsupported_system_root,
)
from .result import ProofResult


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
        center_values = tuple(
            _candidate_fraction(value, maximum_denominator) for value in center
        )
        matrix = tuple(
            tuple(_candidate_fraction(value, maximum_denominator) for value in row)
            for row in preconditioner
        )
        dimension = len(center_values)
        if dimension == 0 or len(matrix) != dimension or any(
            len(row) != dimension for row in matrix
        ):
            raise ValueError("Krawczyk center and preconditioner must have square dimensions")
        return cls(center_values, matrix)

    def to_wire(self) -> dict[str, object]:
        def rat(value: Fraction) -> dict[str, int]:
            return {"n": value.numerator, "d": value.denominator}

        return {
            "center": [rat(value) for value in self.center],
            "preconditioner": [
                [rat(value) for value in row] for row in self.preconditioner
            ],
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
class ProveConfig:
    """Effort controls for checked claim execution.

    Contract 2.0's checked bound capability selects its own advertised
    numerical backend and verification route. The Python caller controls only
    checker effort that the request schema actually accepts.
    """

    taylor_depth: int = 10
    system_root: SystemRootConfig = field(default_factory=SystemRootConfig)

    def __post_init__(self) -> None:
        if (
            isinstance(self.taylor_depth, bool)
            or not isinstance(self.taylor_depth, int)
            or self.taylor_depth < 0
        ):
            raise ValueError("taylor_depth must be a non-negative integer")
        if not isinstance(self.system_root, SystemRootConfig):
            raise TypeError("system_root must be a SystemRootConfig")


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
    claim_id = ast.semantic_digest(normalized_claim)
    assert isinstance(claim_id, ast.ClaimDigest)
    if isinstance(normalized_claim, ast.SystemRootClaim):
        if not normalized_claim.uniqueness:
            return unsupported_system_root(
                normalized_claim,
                original_claim=claim,
                normalized_claim=normalized_claim,
                claim_id=claim_id,
                reason="the initial checked system-root route certifies uniqueness",
            )
        owns_client = client is None
        active_client = LeanClient() if client is None else client
        try:
            return execute_system_root_plan(
                SystemRootPlan(normalized_claim),
                original_claim=claim,
                normalized_claim=normalized_claim,
                claim_id=claim_id,
                client=active_client,
                config=config.system_root,
                taylor_depth=config.taylor_depth,
            )
        finally:
            if owns_client:
                active_client.close()
    plan, unsupported_reason = try_plan_bound_claim(normalized_claim)
    if plan is None:
        assert unsupported_reason is not None
        return unsupported_result(claim, normalized_claim, claim_id, unsupported_reason)

    owns_client = client is None
    active_client = LeanClient() if client is None else client
    try:
        return execute_bound_plan(
            plan,
            original_claim=claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            client=active_client,
            taylor_depth=config.taylor_depth,
        )
    finally:
        if owns_client:
            active_client.close()


__all__ = ["KrawczykCandidate", "ProveConfig", "SystemRootConfig", "prove"]
