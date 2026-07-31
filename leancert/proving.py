"""Unified checked proving front door for semantic AST claims."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from . import ast
from .client import LeanClient
from .operations.bounds import execute_bound_plan, try_plan_bound_claim, unsupported_result
from .result import ProofResult


@dataclass(frozen=True, slots=True)
class ProveConfig:
    """Effort controls for checked claim execution.

    Contract 2.0's checked bound capability selects its own advertised
    numerical backend and verification route. The Python caller controls only
    checker effort that the request schema actually accepts.
    """

    taylor_depth: int = 10

    def __post_init__(self) -> None:
        if (
            isinstance(self.taylor_depth, bool)
            or not isinstance(self.taylor_depth, int)
            or self.taylor_depth < 0
        ):
            raise ValueError("taylor_depth must be a non-negative integer")


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


__all__ = ["ProveConfig", "prove"]
