"""Checked reciprocal-power eventual bounds through Bridge Contract 2.4."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .. import ast
from ..exceptions import ProtocolViolation
from ..protocol import OutcomeStatus
from ..result import (
    BridgeProvenance,
    EventualCandidateRejected,
    EventualSearchEvidence,
    InconclusiveEventualBound,
    ProofResult,
    ReplayableEventualCertificate,
    UnsupportedEventualBound,
    VerifiedEventualBound,
)
from .bounds import bridge_provenance


class _UnsupportedEventual(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class EventualPlan:
    claim: ast.EventualClaim
    coefficient: Fraction
    bound: Fraction
    exponent: int
    cutoff: int | None


def _strip_casts(expression: ast.Expr) -> ast.Expr:
    while isinstance(expression, ast.Cast):
        expression = expression.expression
    return expression


def _constant(expression: ast.Expr, role: str) -> Fraction:
    expression = ast.normalize(expression)
    if not isinstance(expression, ast.RationalConstant):
        raise _UnsupportedEventual(f"{role} must be an exact rational constant")
    return expression.value


def plan_eventual_claim(claim: ast.EventualClaim) -> EventualPlan:
    body = claim.body
    if not isinstance(body, ast.ComparisonClaim) or body.relation is not ast.Relation.LE:
        raise _UnsupportedEventual("eventual bounds currently require an upper-bound comparison")
    bound = _constant(body.rhs, "eventual upper bound")
    lhs = _strip_casts(body.lhs)
    if not isinstance(lhs, ast.Div):
        raise _UnsupportedEventual("eventual bounds currently require q / n^k")
    coefficient = _constant(lhs.numerator, "reciprocal-power coefficient")
    denominator = _strip_casts(lhs.denominator)
    exponent = 1
    base = denominator
    if isinstance(denominator, ast.Pow):
        base = _strip_casts(denominator.base)
        exponent_value = _constant(denominator.exponent, "reciprocal-power exponent")
        if exponent_value.denominator != 1 or exponent_value < 0:
            raise _UnsupportedEventual("reciprocal-power exponent must be a natural-number literal")
        exponent = int(exponent_value)
    if not isinstance(base, ast.Variable) or (
        base.symbol.identifier != claim.variable.symbol.identifier
    ):
        raise _UnsupportedEventual("reciprocal-power denominator must be the eventual variable")
    cutoff = None
    if claim.explicit_cutoff is not None:
        cutoff_value = _constant(claim.explicit_cutoff, "eventual cutoff")
        if cutoff_value.denominator != 1 or cutoff_value < 0:
            raise _UnsupportedEventual("eventual cutoff must be a natural-number literal")
        cutoff = int(cutoff_value)
    return EventualPlan(claim, coefficient, bound, exponent, cutoff)


def try_plan_eventual_claim(
    claim: ast.EventualClaim,
) -> tuple[EventualPlan | None, str | None]:
    try:
        return plan_eventual_claim(claim), None
    except _UnsupportedEventual as exc:
        return None, str(exc)


def _empty_search(cutoff: int | None) -> EventualSearchEvidence:
    return EventualSearchEvidence("provided" if cutoff is not None else "automatic")


def _common(
    plan: EventualPlan,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    provenance: BridgeProvenance,
    search: EventualSearchEvidence,
    cutoff: int | None,
) -> dict[str, Any]:
    return {
        "variable": plan.claim.variable,
        "coefficient": plan.coefficient,
        "bound": plan.bound,
        "exponent": plan.exponent,
        "cutoff": cutoff,
        "provenance": provenance,
        "search": search,
        "original_claim": original_claim,
        "normalized_claim": normalized_claim,
        "claim_id": claim_id,
    }


def unsupported_eventual(
    claim: ast.EventualClaim,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    reason: str,
    provenance: BridgeProvenance | None = None,
) -> UnsupportedEventualBound:
    plan, _ = try_plan_eventual_claim(claim)
    if plan is None:
        return UnsupportedEventualBound(
            variable=claim.variable,
            coefficient=None,
            bound=None,
            exponent=None,
            cutoff=None,
            provenance=provenance or BridgeProvenance(),
            search=_empty_search(None),
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason=reason,
        )
    return UnsupportedEventualBound(
        **_common(
            plan,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            provenance=provenance or BridgeProvenance(),
            search=_empty_search(plan.cutoff),
            cutoff=plan.cutoff,
        ),
        reason=reason,
    )


def _search_evidence(outcome) -> EventualSearchEvidence:
    search = outcome.search
    return EventualSearchEvidence(
        search.source,
        search.checks,
        search.configured_limit,
        search.exponential_steps,
        search.refinement_steps,
        search.lower_bracket,
        search.upper_bracket,
        search.refinement_complete,
        search.last_cutoff,
    )


def execute_eventual_plan(
    plan: EventualPlan,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    client: Any,
    max_checks: int,
) -> ProofResult:
    contract = client.bridge_contract
    provenance = bridge_provenance(client)
    capability = contract.capability("check_eventual_bound")
    if capability is None:
        return unsupported_eventual(
            plan.claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason="bridge does not advertise check_eventual_bound",
            provenance=provenance,
        )
    if (
        capability.request_schema != "check-eventual-bound-request/1"
        or capability.result_schema != "eventual-bound-outcome/1"
        or "eventual-bound-check/1" not in capability.certificate_schemas
    ):
        return unsupported_eventual(
            plan.claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason="bridge eventual-bound schemas are not supported by this SDK",
            provenance=provenance,
        )
    response = client.check_eventual_bound(
        plan.coefficient,
        plan.bound,
        plan.exponent,
        cutoff=plan.cutoff,
        max_checks=max_checks,
    )
    outcome = contract.parse_eventual_outcome(response)
    search = _search_evidence(outcome)
    common = _common(
        plan,
        original_claim=original_claim,
        normalized_claim=normalized_claim,
        claim_id=claim_id,
        provenance=provenance,
        search=search,
        cutoff=outcome.cutoff,
    )
    if outcome.status is OutcomeStatus.VERIFIED:
        descriptor = outcome.certificate
        if descriptor is None:
            raise ProtocolViolation("verified eventual bound lacks a certificate")
        payload = descriptor.payload
        certificate = ReplayableEventualCertificate(
            schema_version=descriptor.schema_version,
            payload_schema="checked-eventual-bound/1",
            checker=descriptor.checker,
            verifier=descriptor.verifier,
            verification_route=descriptor.verification_route,
            payload_digest=payload.digest,
            coefficient=payload.coefficient.fraction,
            bound=payload.bound.fraction,
            exponent=payload.exponent,
            cutoff=payload.cutoff,
            canonical_payload=payload.canonical,
        )
        return VerifiedEventualBound(**common, certificate=certificate)
    failure_kind = None if outcome.failure is None else outcome.failure.get("kind")
    failure_detail = None if outcome.failure is None else outcome.failure.get("detail")
    reason = str(failure_detail or failure_kind or "eventual-bound check did not succeed")
    if outcome.status is OutcomeStatus.UNSUPPORTED:
        return UnsupportedEventualBound(**common, reason=reason)
    if outcome.status is OutcomeStatus.INCONCLUSIVE:
        return InconclusiveEventualBound(**common, reason=reason)
    return EventualCandidateRejected(**common, reason=reason)


__all__ = [
    "EventualPlan",
    "execute_eventual_plan",
    "try_plan_eventual_claim",
    "unsupported_eventual",
]
