"""Compilation and execution of semantic AST bound claims.

This module is intentionally narrow. It accepts only closed, universally
quantified real comparisons that the bridge advertises through its checked
``check_bound`` capability. Search and sampling never contribute to success.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from itertools import product
from typing import Any

from .. import ast
from ..client import _parse_rat
from ..domain import Interval as ResultInterval
from ..exceptions import ProtocolViolation
from ..expression_codec import (
    UnsupportedSemanticExpression,
    compile_semantic_expression,
    lower_bridge_expression,
)
from ..result import (
    BoundCheckEvidence,
    BoundComparisonLowering,
    BridgeProvenance,
    CheckedCounterexample,
    DomainObstruction,
    Inconclusive,
    ProofResult,
    Rejected,
    ReplayableBoundCertificate,
    ReplayBoundConfig,
    Unsupported,
    Verified,
)

_UnsupportedBound = UnsupportedSemanticExpression


@dataclass(frozen=True, slots=True)
class BoundPlan:
    expression: ast.Expr
    axes: tuple[ast.AxisDomain, ...]
    lower: Fraction | None
    upper: Fraction | None
    lowerings: tuple[BoundComparisonLowering, ...]

    @property
    def domain(self) -> ast.Box | None:
        return ast.Box(self.axes) if self.axes else None


def _rational(expression: ast.Expr, role: str) -> Fraction:
    expression = ast.normalize(expression)
    if not isinstance(expression, ast.RationalConstant):
        raise _UnsupportedBound(f"{role} must be an exact rational constant")
    return expression.value


def _comparison_bound(
    claim: ast.ComparisonClaim,
) -> tuple[ast.Expr, str, Fraction, BoundComparisonLowering]:
    if claim.relation is not ast.Relation.LE:
        if claim.relation is ast.Relation.LT:
            raise _UnsupportedBound("strict inequalities are not supported by check_bound/1")
        raise _UnsupportedBound(
            f"comparison relation {claim.relation.value!r} is not a checked bound"
        )
    if isinstance(claim.rhs, ast.RationalConstant):
        return (
            claim.lhs,
            "upper",
            claim.rhs.value,
            BoundComparisonLowering(
                claim.lhs,
                claim.rhs,
                claim.lhs,
                "upper",
                claim.rhs.value,
                "lhs_le_constant",
            ),
        )
    if isinstance(claim.lhs, ast.RationalConstant):
        return (
            claim.rhs,
            "lower",
            claim.lhs.value,
            BoundComparisonLowering(
                claim.lhs,
                claim.rhs,
                claim.rhs,
                "lower",
                claim.lhs.value,
                "constant_le_rhs",
            ),
        )
    difference = ast.normalize(claim.lhs - claim.rhs)
    return (
        difference,
        "upper",
        Fraction(0),
        BoundComparisonLowering(
            claim.lhs,
            claim.rhs,
            difference,
            "upper",
            Fraction(0),
            "subtract_rhs_le_zero",
        ),
    )


def plan_bound_claim(claim: ast.Claim) -> BoundPlan:
    """Extract one checked bound operation from a normalized, closed claim."""
    axes: list[ast.AxisDomain] = []
    body = claim
    while isinstance(body, ast.BoundedForAllClaim):
        binder = body.binder
        if binder.variable.sort != ast.REAL:
            raise _UnsupportedBound("checked bounds currently quantify only real variables")
        if not isinstance(binder.domain, ast.Interval):
            raise _UnsupportedBound("checked bounds currently require interval domains")
        if not binder.domain.lower_closed or not binder.domain.upper_closed:
            raise _UnsupportedBound("checked bounds currently require closed intervals")
        _rational(binder.domain.lower, "domain lower endpoint")
        _rational(binder.domain.upper, "domain upper endpoint")
        axes.append(ast.AxisDomain(binder.variable, binder.domain))
        body = body.body

    claims = body.claims if isinstance(body, ast.ConjunctionClaim) else (body,)
    if not claims or any(not isinstance(item, ast.ComparisonClaim) for item in claims):
        raise _UnsupportedBound(
            "the initial prove route supports a comparison or conjunction of bounds"
        )

    expression: ast.Expr | None = None
    lower: Fraction | None = None
    upper: Fraction | None = None
    lowerings: list[BoundComparisonLowering] = []
    for item in claims:
        assert isinstance(item, ast.ComparisonClaim)
        candidate, direction, bound, lowering = _comparison_bound(item)
        candidate = ast.normalize(candidate)
        if expression is None:
            expression = candidate
        elif expression != candidate:
            raise _UnsupportedBound(
                "two-sided checked bounds must constrain the same normalized expression"
            )
        if direction == "lower":
            if lower is not None:
                raise _UnsupportedBound("a claim may contain at most one lower bound")
            lower = bound
        else:
            if upper is not None:
                raise _UnsupportedBound("a claim may contain at most one upper bound")
            upper = bound
        lowerings.append(lowering)

    assert expression is not None
    return BoundPlan(expression, tuple(axes), lower, upper, tuple(lowerings))


def _rat(value: Fraction) -> dict[str, int]:
    return {"n": value.numerator, "d": value.denominator}


def _compile_expression(
    expression: ast.Expr,
    indices: dict[ast.SymbolId, int],
    advertised_nodes: frozenset[str],
) -> dict[str, Any]:
    return compile_semantic_expression(expression, indices, advertised_nodes)


def bridge_provenance(client: Any) -> BridgeProvenance:
    info = client.bridge_info
    build = info.get("build") if isinstance(info.get("build"), dict) else {}
    contract = client.bridge_contract
    dependencies = contract.dependencies
    return BridgeProvenance(
        bridge_api_version=info.get("bridge_api_version"),
        protocol_version=info.get("protocol_version"),
        bridge_version=info.get("bridge_version"),
        lean_version=info.get("lean_version"),
        leancert_version=info.get("leancert_version"),
        source_revision=build.get("source_revision"),
        source_digest=build.get("source_digest"),
        environment_digest=build.get("environment_digest"),
        build_profile=build.get("profile"),
        capability_digest=contract.capability_digest,
        lean_toolchain=None if dependencies is None else dependencies.lean_toolchain,
        leancert_source=None if dependencies is None else dependencies.leancert_source,
        leancert_input_revision=(
            None if dependencies is None else dependencies.leancert_input_revision
        ),
        leancert_resolved_revision=(
            None if dependencies is None else dependencies.leancert_resolved_revision
        ),
    )


def _lower_checked_expression(expression: dict[str, Any]) -> dict[str, Any]:
    """Mirror bridge request decoding into the canonical LeanCert core AST."""
    return lower_bridge_expression(expression)


def _replay_certificate(
    response: dict[str, Any],
    *,
    contract: Any,
    expression_json: dict[str, Any],
    box_json: list[dict[str, Any]],
    bound: Fraction,
    direction: str,
    taylor_depth: int,
) -> ReplayableBoundCertificate | None:
    outcome = contract.parse_bound_outcome(response, expected_direction=direction)
    descriptor = outcome.certificate
    if descriptor is None or descriptor.payload is None:
        return None
    payload = descriptor.payload
    expected_bound = _rat(bound)
    expected_expression = _lower_checked_expression(expression_json)
    if dict(payload.expression) != expected_expression:
        raise ProtocolViolation("bridge replay expression does not match the checked request")
    if list(payload.canonical["box"]) != box_json:
        raise ProtocolViolation("bridge replay box does not match the checked request")
    if dict(payload.canonical["bound"]) != expected_bound:
        raise ProtocolViolation("bridge replay bound does not match the checked request")
    if payload.direction != direction or payload.config.taylor_depth != taylor_depth:
        raise ProtocolViolation(
            "bridge replay direction or Taylor depth does not match the request"
        )
    return ReplayableBoundCertificate(
        schema_version=descriptor.schema_version,
        payload_schema="global-opt-bound-replay/1",
        checker=descriptor.checker,
        verifier=descriptor.verifier,
        verification_route=descriptor.verification_route,
        payload_digest=payload.digest,
        expression=payload.expression,
        box=tuple(ResultInterval(item.lower.fraction, item.upper.fraction) for item in payload.box),
        bound=payload.bound.fraction,
        direction=payload.direction,
        config=ReplayBoundConfig(
            payload.config.max_iterations,
            payload.config.tolerance.fraction,
            payload.config.use_monotonicity,
            payload.config.taylor_depth,
        ),
        canonical_payload=payload.canonical,
    )


def unsupported_result(
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    reason: str,
    *,
    provenance: BridgeProvenance | None = None,
    plan: BoundPlan | None = None,
) -> Unsupported:
    return Unsupported(
        expression=None if plan is None else plan.expression,
        domain=None if plan is None else plan.domain,
        lower=None if plan is None else plan.lower,
        upper=None if plan is None else plan.upper,
        lowerings=() if plan is None else plan.lowerings,
        checks=(),
        provenance=provenance or BridgeProvenance(),
        original_claim=original_claim,
        normalized_claim=normalized_claim,
        claim_id=claim_id,
        reason=reason,
    )


def execute_bound_plan(
    plan: BoundPlan,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    client: Any,
    taylor_depth: int,
    refutation_config: Any | None = None,
) -> ProofResult:
    contract = client.bridge_contract
    provenance = bridge_provenance(client)
    capability = contract.capability("check_bound")
    if capability is None:
        return unsupported_result(
            original_claim,
            normalized_claim,
            claim_id,
            "bridge does not advertise the checked check_bound capability",
            provenance=provenance,
            plan=plan,
        )
    if (
        capability.request_schema != "check-bound-request/1"
        or capability.result_schema != "bound-outcome/1"
        or not capability.certificate_schemas.intersection({"bound-check/1", "bound-check/2"})
    ):
        return unsupported_result(
            original_claim,
            normalized_claim,
            claim_id,
            "bridge check_bound schemas are not supported by this SDK",
            provenance=provenance,
            plan=plan,
        )

    indices = {axis.variable.symbol.identifier: index for index, axis in enumerate(plan.axes)}
    try:
        expression_json = _compile_expression(plan.expression, indices, contract.expression_nodes)
    except _UnsupportedBound as exc:
        return unsupported_result(
            original_claim,
            normalized_claim,
            claim_id,
            str(exc),
            provenance=provenance,
            plan=plan,
        )

    box_json = [
        {
            "lo": _rat(_rational(axis.interval.lower, "domain lower endpoint")),
            "hi": _rat(_rational(axis.interval.upper, "domain upper endpoint")),
        }
        for axis in plan.axes
    ]
    checks: list[BoundCheckEvidence] = []
    for direction, bound in (("lower", plan.lower), ("upper", plan.upper)):
        if bound is None:
            continue
        response = client.check_bound(
            expression_json,
            box_json,
            _rat(bound),
            is_upper_bound=direction == "upper",
            taylor_depth=taylor_depth,
        )
        enclosure_json = response.get("enclosure") or {
            "lo": response["computed_lo"],
            "hi": response["computed_hi"],
        }
        enclosure = ResultInterval(
            _parse_rat(enclosure_json["lo"]), _parse_rat(enclosure_json["hi"])
        )
        status = response.get("status", "verified" if response["verified"] else "inconclusive")
        replay = _replay_certificate(
            response,
            contract=contract,
            expression_json=expression_json,
            box_json=box_json,
            bound=bound,
            direction=direction,
            taylor_depth=taylor_depth,
        )
        checks.append(
            BoundCheckEvidence(
                direction=direction,
                requested_bound=bound,
                enclosure=enclosure,
                status=status,
                operation="check_bound",
                backend=response.get("backend"),
                taylor_depth=taylor_depth,
                certificate=response.get("certificate"),
                replay_certificate=replay,
                raw_response=dict(response),
            )
        )

    common = dict(
        expression=plan.expression,
        domain=plan.domain,
        lower=plan.lower,
        upper=plan.upper,
        checks=tuple(checks),
        provenance=provenance,
        lowerings=plan.lowerings,
        original_claim=original_claim,
        normalized_claim=normalized_claim,
        claim_id=claim_id,
    )
    if all(check.status == "verified" for check in checks):
        return Verified(**common)
    if any(check.status == "domain_obstruction" for check in checks):
        return DomainObstruction(
            **common,
            reason="The checked evaluator could not establish domain validity.",
        )
    if any(check.status == "unsupported" for check in checks):
        return Unsupported(
            **common,
            reason="The bridge rejected this expression as unsupported by check_bound/1.",
        )
    if refutation_config is not None and refutation_config.enabled:
        rejected = _search_checked_refutation(
            plan,
            expression_json=expression_json,
            client=client,
            contract=contract,
            taylor_depth=taylor_depth,
            max_candidates=refutation_config.max_candidates,
        )
        if rejected is not None:
            counterexample, refutation_check = rejected
            return Rejected(
                **common,
                counterexample=counterexample,
                refutation_check=refutation_check,
            )
    return Inconclusive(
        **common,
        reason="The checked enclosure was insufficient for the normalized claim.",
    )


def _search_checked_refutation(
    plan: BoundPlan,
    *,
    expression_json: dict[str, Any],
    client: Any,
    contract: Any,
    taylor_depth: int,
    max_candidates: int,
) -> tuple[CheckedCounterexample, BoundCheckEvidence] | None:
    """Search exact grid points; accept only an opposite checked bound."""

    coordinates: list[tuple[Fraction, ...]] = []
    for axis in plan.axes:
        lower = _rational(axis.interval.lower, "domain lower endpoint")
        upper = _rational(axis.interval.upper, "domain upper endpoint")
        midpoint = (lower + upper) / 2
        coordinates.append(tuple(dict.fromkeys((midpoint, lower, upper))))
    candidates = product(*coordinates) if coordinates else ((),)

    for candidate_index, point in enumerate(candidates):
        if candidate_index >= max_candidates:
            break
        point_box = [{"lo": _rat(value), "hi": _rat(value)} for value in point]
        for original_direction, original_bound in (
            ("lower", plan.lower),
            ("upper", plan.upper),
        ):
            if original_bound is None:
                continue
            probe = client.check_bound(
                expression_json,
                point_box,
                _rat(original_bound),
                is_upper_bound=original_direction == "upper",
                taylor_depth=taylor_depth,
            )
            enclosure_json = probe.get("enclosure") or {
                "lo": probe["computed_lo"],
                "hi": probe["computed_hi"],
            }
            enclosure = ResultInterval(
                _parse_rat(enclosure_json["lo"]),
                _parse_rat(enclosure_json["hi"]),
            )
            if original_direction == "upper" and enclosure.lo > original_bound:
                opposite_direction = "lower"
                opposite_bound = (original_bound + enclosure.lo) / 2
            elif original_direction == "lower" and enclosure.hi < original_bound:
                opposite_direction = "upper"
                opposite_bound = (original_bound + enclosure.hi) / 2
            else:
                continue

            checked = client.check_bound(
                expression_json,
                point_box,
                _rat(opposite_bound),
                is_upper_bound=opposite_direction == "upper",
                taylor_depth=taylor_depth,
            )
            checked_status = checked.get(
                "status", "verified" if checked.get("verified") else "inconclusive"
            )
            if checked_status != "verified":
                continue
            checked_enclosure_json = checked.get("enclosure") or {
                "lo": checked["computed_lo"],
                "hi": checked["computed_hi"],
            }
            checked_enclosure = ResultInterval(
                _parse_rat(checked_enclosure_json["lo"]),
                _parse_rat(checked_enclosure_json["hi"]),
            )
            replay = _replay_certificate(
                checked,
                contract=contract,
                expression_json=expression_json,
                box_json=point_box,
                bound=opposite_bound,
                direction=opposite_direction,
                taylor_depth=taylor_depth,
            )
            evidence = BoundCheckEvidence(
                direction=opposite_direction,
                requested_bound=opposite_bound,
                enclosure=checked_enclosure,
                status="verified",
                operation="check_bound_refutation",
                backend=checked.get("backend"),
                taylor_depth=taylor_depth,
                certificate=checked.get("certificate"),
                replay_certificate=replay,
                raw_response=dict(checked),
            )
            values = {
                f"{axis.variable.symbol.identifier.namespace}:"
                f"{axis.variable.symbol.identifier.name}": value
                for axis, value in zip(plan.axes, point, strict=True)
            }
            return CheckedCounterexample(values, enclosure), evidence
    return None


def try_plan_bound_claim(claim: ast.Claim) -> tuple[BoundPlan | None, str | None]:
    try:
        return plan_bound_claim(claim), None
    except _UnsupportedBound as exc:
        return None, str(exc)
