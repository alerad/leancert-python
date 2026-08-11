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
from ..client import DEFAULT_BRIDGE_SOURCE_REVISION, _parse_rat
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
    ReplayableStrictBoundCertificate,
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
    lower_strict: bool = False
    upper_strict: bool = False

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
) -> tuple[ast.Expr, str, Fraction, bool, BoundComparisonLowering]:
    if claim.relation not in {ast.Relation.LE, ast.Relation.LT}:
        raise _UnsupportedBound(
            f"comparison relation {claim.relation.value!r} is not a checked bound"
        )
    strict = claim.relation is ast.Relation.LT
    if isinstance(claim.rhs, ast.RationalConstant):
        return (
            claim.lhs,
            "upper",
            claim.rhs.value,
            strict,
            BoundComparisonLowering(
                claim.lhs,
                claim.rhs,
                claim.lhs,
                "upper",
                claim.rhs.value,
                "lhs_le_constant",
                strict,
            ),
        )
    if isinstance(claim.lhs, ast.RationalConstant):
        return (
            claim.rhs,
            "lower",
            claim.lhs.value,
            strict,
            BoundComparisonLowering(
                claim.lhs,
                claim.rhs,
                claim.rhs,
                "lower",
                claim.lhs.value,
                "constant_le_rhs",
                strict,
            ),
        )
    difference = ast.normalize(claim.lhs - claim.rhs)
    return (
        difference,
        "upper",
        Fraction(0),
        strict,
        BoundComparisonLowering(
            claim.lhs,
            claim.rhs,
            difference,
            "upper",
            Fraction(0),
            "subtract_rhs_le_zero",
            strict,
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
    lower_strict = False
    upper_strict = False
    for item in claims:
        assert isinstance(item, ast.ComparisonClaim)
        candidate, direction, bound, strict, lowering = _comparison_bound(item)
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
            lower_strict = strict
        else:
            if upper is not None:
                raise _UnsupportedBound("a claim may contain at most one upper bound")
            upper = bound
            upper_strict = strict
        lowerings.append(lowering)

    assert expression is not None
    return BoundPlan(
        expression,
        tuple(axes),
        lower,
        upper,
        tuple(lowerings),
        lower_strict,
        upper_strict,
    )


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
    contract = client.bridge_contract
    dependencies = contract.dependencies
    environment = getattr(client, "_environment", None)
    if environment is None:
        # Structural test/dry-run clients may expose a plain environment field;
        # avoid touching LeanClient.environment because that property hydrates.
        environment = vars(client).get("environment")
    program = getattr(client, "_program", None)
    program_profile = (
        getattr(getattr(program, "description", None), "provenance", {})
        if program is not None
        else {}
    )
    lock = getattr(environment, "lock", None)
    packages = () if lock is None else lock.packages
    program_toolchain = getattr(getattr(program, "description", None), "toolchain", None)
    resolved_toolchain = (
        dependencies.lean_toolchain
        if lock is None and dependencies is not None
        else lock.toolchain
        if lock is not None
        else None
    )

    def package_named(name: str):
        return next((package for package in packages if package.name.lower() == name), None)

    leancert = package_named("leancert")
    bridge = package_named("leancertbridge")
    return BridgeProvenance(
        environment_id=getattr(environment, "id", None),
        execution_id=getattr(client, "execution_id", None),
        execution_route="program" if program is not None else "environment",
        program_id=getattr(program, "id", None),
        program_copy_id=getattr(program, "copy_id", None),
        runtime_package_ref=getattr(client, "package_ref", None),
        environment_lock_id=None if lock is None else lock.lock_id,
        bridge_api_version=info.get("bridge_api_version"),
        protocol_version=info.get("protocol_version"),
        bridge_version=info.get("bridge_version"),
        lean_version=info.get("lean_version"),
        leancert_version=info.get("leancert_version"),
        capability_digest=contract.capability_digest,
        lean_toolchain=(program_profile.get("lean.toolchain") if program_profile else None)
        or program_toolchain
        or resolved_toolchain,
        leancert_source=(
            dependencies.leancert_source
            if leancert is None and dependencies is not None
            else leancert.url
        )
        if leancert is not None or dependencies is not None
        else "https://github.com/alerad/leancert.git",
        leancert_input_revision=(
            dependencies.leancert_input_revision
            if leancert is None and dependencies is not None
            else leancert.requested_revision
        )
        if leancert is not None or dependencies is not None
        else info.get("leancert_version"),
        leancert_resolved_revision=(
            program_profile.get("leancert.core.revision") if program_profile else None
        )
        or (
            (
                dependencies.leancert_resolved_revision
                if leancert is None and dependencies is not None
                else leancert.revision
            )
            if leancert is not None or dependencies is not None
            else info.get("leancert_version")
        ),
        leancert_tree_hash=None if leancert is None else leancert.tree_hash,
        bridge_source=(
            "https://github.com/alerad/leancert-bridge.git" if bridge is None else bridge.url
        ),
        bridge_resolved_revision=(
            program_profile.get("leancert.bridge.revision") if program_profile else None
        )
        or (DEFAULT_BRIDGE_SOURCE_REVISION if bridge is None else bridge.revision),
        bridge_tree_hash=None if bridge is None else bridge.tree_hash,
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


def _strict_replay_certificate(
    response: dict[str, Any],
    *,
    contract: Any,
    expression_json: dict[str, Any],
    box_json: list[dict[str, Any]],
    bound: Fraction,
    relation: str,
    taylor_depth: int,
) -> ReplayableStrictBoundCertificate | None:
    outcome = contract.parse_strict_bound_outcome(response, expected_relation=relation)
    descriptor = outcome.certificate
    if descriptor is None or descriptor.payload is None:
        return None
    payload = descriptor.payload
    expected_bound = _rat(bound)
    expected_expression = _lower_checked_expression(expression_json)
    if dict(payload.expression) != expected_expression:
        raise ProtocolViolation("bridge strict replay expression does not match the request")
    if list(payload.canonical["box"]) != box_json:
        raise ProtocolViolation("bridge strict replay box does not match the request")
    if dict(payload.canonical["target_bound"]) != expected_bound:
        raise ProtocolViolation("bridge strict replay target does not match the request")
    if payload.relation != relation or payload.config.taylor_depth != taylor_depth:
        raise ProtocolViolation(
            "bridge strict replay relation or Taylor depth does not match the request"
        )
    return ReplayableStrictBoundCertificate(
        schema_version=descriptor.schema_version,
        payload_schema="checked-strict-bound/1",
        checker=descriptor.checker,
        verifier=descriptor.verifier,
        verification_route=descriptor.verification_route,
        payload_digest=payload.digest,
        expression=payload.expression,
        box=tuple(ResultInterval(item.lower.fraction, item.upper.fraction) for item in payload.box),
        relation=payload.relation,
        target_bound=payload.target_bound.fraction,
        certified_bound=payload.certified_bound.fraction,
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
    needs_nonstrict = (plan.lower is not None and not plan.lower_strict) or (
        plan.upper is not None and not plan.upper_strict
    )
    needs_strict = plan.lower_strict or plan.upper_strict
    if needs_nonstrict and capability is None:
        return unsupported_result(
            original_claim,
            normalized_claim,
            claim_id,
            "bridge does not advertise the checked check_bound capability",
            provenance=provenance,
            plan=plan,
        )
    if needs_nonstrict and (
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
    strict_capability = contract.capability("check_strict_bound")
    if needs_strict and strict_capability is None:
        return unsupported_result(
            original_claim,
            normalized_claim,
            claim_id,
            "bridge does not advertise the checked check_strict_bound capability",
            provenance=provenance,
            plan=plan,
        )
    if needs_strict and (
        strict_capability.request_schema != "check-strict-bound-request/1"
        or strict_capability.result_schema != "strict-bound-outcome/1"
        or "strict-bound-check/1" not in strict_capability.certificate_schemas
    ):
        return unsupported_result(
            original_claim,
            normalized_claim,
            claim_id,
            "bridge check_strict_bound schemas are not supported by this SDK",
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
    for direction, bound, strict in (
        ("lower", plan.lower, plan.lower_strict),
        ("upper", plan.upper, plan.upper_strict),
    ):
        if bound is None:
            continue
        relation = "lt" if direction == "upper" else "gt"
        if strict:
            response = client.check_strict_bound(
                expression_json,
                box_json,
                _rat(bound),
                relation=relation,
                taylor_depth=taylor_depth,
            )
        else:
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
        replay = (
            _strict_replay_certificate(
                response,
                contract=contract,
                expression_json=expression_json,
                box_json=box_json,
                bound=bound,
                relation=relation,
                taylor_depth=taylor_depth,
            )
            if strict
            else _replay_certificate(
                response,
                contract=contract,
                expression_json=expression_json,
                box_json=box_json,
                bound=bound,
                direction=direction,
                taylor_depth=taylor_depth,
            )
        )
        checks.append(
            BoundCheckEvidence(
                direction=direction,
                requested_bound=bound,
                enclosure=enclosure,
                status=status,
                operation="check_strict_bound" if strict else "check_bound",
                backend=response.get("backend"),
                taylor_depth=taylor_depth,
                certificate=response.get("certificate"),
                replay_certificate=replay,
                raw_response=dict(response),
                strict=strict,
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
            reason="The bridge rejected this expression as unsupported by its checked bound route.",
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
        for original_direction, original_bound, original_strict in (
            ("lower", plan.lower, plan.lower_strict),
            ("upper", plan.upper, plan.upper_strict),
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
            if original_direction == "upper" and original_strict and enclosure.lo >= original_bound:
                opposite_direction = "lower"
                opposite_bound = original_bound
            elif original_direction == "upper" and enclosure.lo > original_bound:
                opposite_direction = "lower"
                opposite_bound = (original_bound + enclosure.lo) / 2
            elif (
                original_direction == "lower" and original_strict and enclosure.hi <= original_bound
            ):
                opposite_direction = "upper"
                opposite_bound = original_bound
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
