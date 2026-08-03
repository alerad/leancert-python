"""Checked definite-integral claims through Bridge Contract 2.6."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Literal

from .. import ast
from ..domain import Interval as ResultInterval
from ..protocol import OutcomeStatus
from ..result import (
    BridgeProvenance,
    InconclusiveIntegral,
    IntegralCandidateRejected,
    IntegralDomainObstruction,
    IntegralSearchEvidence,
    ProofResult,
    ReplayableIntegralCertificate,
    UnsupportedIntegral,
    VerifiedIntegralBound,
    VerifiedIntegralEquality,
)
from .bounds import _compile_expression, _rat, _rational, _UnsupportedBound, bridge_provenance


class _UnsupportedIntegral(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IntegralPlan:
    claim: ast.ComparisonClaim
    integral: ast.Integral
    relation: Literal["eq", "lower", "upper"]
    bound: Fraction


def contains_integral(claim: ast.Claim) -> bool:
    return any(isinstance(node, ast.Integral) for node in ast.walk(claim))


def plan_integral_claim(claim: ast.Claim) -> IntegralPlan:
    if not isinstance(claim, ast.ComparisonClaim):
        raise _UnsupportedIntegral("checked integrals require one equality or inequality")
    if claim.relation is ast.Relation.LT:
        raise _UnsupportedIntegral("strict integral inequalities require a margin certificate")
    if claim.relation not in {ast.Relation.EQ, ast.Relation.LE}:
        raise _UnsupportedIntegral("integral comparison was not normalized to equality or ≤")

    left = isinstance(claim.lhs, ast.Integral)
    right = isinstance(claim.rhs, ast.Integral)
    if left == right:
        raise _UnsupportedIntegral(
            "checked integrals require exactly one integral and one exact rational constant"
        )
    integral = claim.lhs if left else claim.rhs
    other = claim.rhs if left else claim.lhs
    assert isinstance(integral, ast.Integral)
    try:
        bound = _rational(other, "integral comparison bound")
        lower = _rational(integral.domain.lower, "integral lower endpoint")
        upper = _rational(integral.domain.upper, "integral upper endpoint")
    except _UnsupportedBound as exc:
        raise _UnsupportedIntegral(str(exc)) from exc
    if not integral.domain.lower_closed or not integral.domain.upper_closed:
        raise _UnsupportedIntegral("checked integrals require a closed interval")
    if lower > upper:
        raise _UnsupportedIntegral(
            "checked integral claims currently require lower endpoint ≤ upper endpoint"
        )
    relation: Literal["eq", "lower", "upper"]
    if claim.relation is ast.Relation.EQ:
        relation = "eq"
    elif left:
        relation = "upper"
    else:
        relation = "lower"
    return IntegralPlan(claim, integral, relation, bound)


def try_plan_integral_claim(
    claim: ast.Claim,
) -> tuple[IntegralPlan | None, str | None]:
    try:
        return plan_integral_claim(claim), None
    except _UnsupportedIntegral as exc:
        return None, str(exc)


def _empty_search(relation: str) -> IntegralSearchEvidence:
    return IntegralSearchEvidence("exact" if relation == "eq" else "automatic")


def _common(
    plan: IntegralPlan,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    provenance: BridgeProvenance,
    search: IntegralSearchEvidence,
    enclosure: ResultInterval | None,
) -> dict[str, Any]:
    return {
        "integrand": plan.integral.integrand,
        "variable": plan.integral.variable,
        "domain": plan.integral.domain,
        "relation": plan.relation,
        "bound": plan.bound,
        "enclosure": enclosure,
        "provenance": provenance,
        "search": search,
        "original_claim": original_claim,
        "normalized_claim": normalized_claim,
        "claim_id": claim_id,
    }


def unsupported_integral(
    plan: IntegralPlan,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    reason: str,
    provenance: BridgeProvenance | None = None,
) -> UnsupportedIntegral:
    return UnsupportedIntegral(
        **_common(
            plan,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            provenance=provenance or BridgeProvenance(),
            search=_empty_search(plan.relation),
            enclosure=None,
        ),
        reason=reason,
    )


def _search_evidence(outcome) -> IntegralSearchEvidence:
    search = outcome.search
    return IntegralSearchEvidence(
        search.source,
        search.start_partitions,
        search.max_partitions,
        search.chosen_partitions,
        search.attempts,
        search.failure,
    )


def execute_integral_plan(
    plan: IntegralPlan,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    client: Any,
    start_partitions: int,
    max_partitions: int,
) -> ProofResult:
    contract = client.bridge_contract
    provenance = bridge_provenance(client)
    capability = contract.capability("check_integral")
    if capability is None:
        return unsupported_integral(
            plan,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason="bridge does not advertise check_integral",
            provenance=provenance,
        )
    if (
        capability.request_schema != "check-integral-request/1"
        or capability.result_schema != "integral-outcome/1"
        or "integral-check/1" not in capability.certificate_schemas
    ):
        return unsupported_integral(
            plan,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason="bridge integral schemas are not supported by this SDK",
            provenance=provenance,
        )
    integral = plan.integral
    try:
        expression = _compile_expression(
            integral.integrand,
            {integral.variable.symbol.identifier: 0},
            contract.expression_nodes,
        )
        lower = _rational(integral.domain.lower, "integral lower endpoint")
        upper = _rational(integral.domain.upper, "integral upper endpoint")
    except _UnsupportedBound as exc:
        return unsupported_integral(
            plan,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason=str(exc),
            provenance=provenance,
        )
    interval = {"lo": _rat(lower), "hi": _rat(upper)}
    response = client.check_integral(
        expression,
        interval,
        plan.relation,
        plan.bound,
        start_partitions=start_partitions,
        max_partitions=max_partitions,
    )
    outcome = contract.parse_integral_outcome(response, expected_relation=plan.relation)
    search = _search_evidence(outcome)
    enclosure = (
        None
        if outcome.enclosure is None
        else ResultInterval(
            outcome.enclosure.lower.fraction,
            outcome.enclosure.upper.fraction,
        )
    )
    common = _common(
        plan,
        original_claim=original_claim,
        normalized_claim=normalized_claim,
        claim_id=claim_id,
        provenance=provenance,
        search=search,
        enclosure=enclosure,
    )
    if outcome.status is OutcomeStatus.VERIFIED:
        assert outcome.certificate is not None
        descriptor = outcome.certificate
        payload = descriptor.payload
        replay = ReplayableIntegralCertificate(
            descriptor.schema_version,
            "checked-integral/1",
            descriptor.checker,
            descriptor.verifier,
            descriptor.verification_route,
            payload.digest,
            payload.expression,
            ResultInterval(payload.interval.lower.fraction, payload.interval.upper.fraction),
            plan.relation,
            payload.bound.fraction,
            payload.partitions,
            payload.canonical,
        )
        result_type = VerifiedIntegralEquality if plan.relation == "eq" else VerifiedIntegralBound
        return result_type(**common, certificate=replay)

    reasons = {
        OutcomeStatus.CANDIDATE_REJECTED: "the fixed integral checker rejected the candidate",
        OutcomeStatus.INCONCLUSIVE: "partition discovery did not establish the requested bound",
        OutcomeStatus.DOMAIN_OBSTRUCTION: "the integrand could not be evaluated on a partition cell",
        OutcomeStatus.UNSUPPORTED: "the checked integral fragment does not support this expression",
    }
    result_types = {
        OutcomeStatus.CANDIDATE_REJECTED: IntegralCandidateRejected,
        OutcomeStatus.INCONCLUSIVE: InconclusiveIntegral,
        OutcomeStatus.DOMAIN_OBSTRUCTION: IntegralDomainObstruction,
        OutcomeStatus.UNSUPPORTED: UnsupportedIntegral,
    }
    return result_types[outcome.status](**common, reason=reasons[outcome.status])


__all__ = [
    "IntegralPlan",
    "contains_integral",
    "execute_integral_plan",
    "plan_integral_claim",
    "try_plan_integral_claim",
    "unsupported_integral",
]
