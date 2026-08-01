"""Compilation and execution of semantic AST bound claims.

This module is intentionally narrow. It accepts only closed, universally
quantified real comparisons that the bridge advertises through its checked
``check_bound`` capability. Search and sampling never contribute to success.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .. import ast
from ..client import _parse_rat
from ..domain import Interval as ResultInterval
from ..exceptions import ProtocolViolation
from ..result import (
    BoundCheckEvidence,
    BridgeProvenance,
    DomainObstruction,
    Inconclusive,
    ProofResult,
    ReplayableBoundCertificate,
    ReplayBoundConfig,
    Unsupported,
    Verified,
)


class _UnsupportedBound(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class BoundPlan:
    expression: ast.Expr
    axes: tuple[ast.AxisDomain, ...]
    lower: Fraction | None
    upper: Fraction | None

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
) -> tuple[ast.Expr, str, Fraction]:
    if claim.relation is not ast.Relation.LE:
        if claim.relation is ast.Relation.LT:
            raise _UnsupportedBound(
                "strict inequalities are not supported by check_bound/1"
            )
        raise _UnsupportedBound(
            f"comparison relation {claim.relation.value!r} is not a checked bound"
        )
    if isinstance(claim.rhs, ast.RationalConstant):
        return claim.lhs, "upper", claim.rhs.value
    if isinstance(claim.lhs, ast.RationalConstant):
        return claim.rhs, "lower", claim.lhs.value
    raise _UnsupportedBound("one side of each checked bound must be an exact rational constant")


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
    for item in claims:
        assert isinstance(item, ast.ComparisonClaim)
        candidate, direction, bound = _comparison_bound(item)
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

    assert expression is not None
    return BoundPlan(expression, tuple(axes), lower, upper)


def _rat(value: Fraction) -> dict[str, int]:
    return {"n": value.numerator, "d": value.denominator}


def _fold(kind: str, values: tuple[ast.Expr, ...], compile_one) -> dict[str, Any]:
    compiled = compile_one(values[0])
    for value in values[1:]:
        compiled = {"kind": kind, "e1": compiled, "e2": compile_one(value)}
    return compiled


def _compile_expression(
    expression: ast.Expr,
    indices: dict[ast.SymbolId, int],
    advertised_nodes: frozenset[str],
) -> dict[str, Any]:
    def compile_one(node: ast.Expr) -> dict[str, Any]:
        if isinstance(node, ast.RationalConstant):
            result = {"kind": "const", "val": _rat(node.value)}
        elif isinstance(node, ast.Variable):
            try:
                index = indices[node.symbol.identifier]
            except KeyError as exc:
                raise _UnsupportedBound(
                    f"expression variable {node.name!r} is not bound by the claim domain"
                ) from exc
            result = {"kind": "var", "idx": index}
        elif isinstance(node, ast.Cast):
            return compile_one(node.expression)
        elif isinstance(node, ast.Neg):
            result = {"kind": "neg", "e": compile_one(node.expression)}
        elif isinstance(node, ast.Add):
            result = _fold("add", node.terms, compile_one)
        elif isinstance(node, ast.Mul):
            result = _fold("mul", node.factors, compile_one)
        elif isinstance(node, ast.Div):
            result = {
                "kind": "div",
                "e1": compile_one(node.numerator),
                "e2": compile_one(node.denominator),
            }
        elif isinstance(node, ast.Pow):
            exponent = node.exponent.value
            if exponent.denominator != 1 or exponent < 0:
                raise _UnsupportedBound(
                    "the checked bridge expression schema requires a non-negative integer power"
                )
            result = {"kind": "pow", "base": compile_one(node.base), "exp": int(exponent)}
        elif isinstance(node, ast.FunctionCall):
            if not isinstance(node.function, ast.BuiltinFunctionRef):
                raise _UnsupportedBound(
                    "external functions require a negotiated extension capability"
                )
            name = node.function.name
            arguments = tuple(compile_one(value) for value in node.arguments)
            if len(arguments) == 1:
                result = {"kind": name, "e": arguments[0]}
            elif len(arguments) == 2 and name in {"min", "max"}:
                result = {"kind": name, "e1": arguments[0], "e2": arguments[1]}
            else:
                raise _UnsupportedBound(f"builtin function {name!r} has no bridge encoding")
        else:
            raise _UnsupportedBound(
                f"expression node {type(node).__name__} is not supported by check_bound/1"
            )
        if result["kind"] not in advertised_nodes:
            raise _UnsupportedBound(
                f"bridge did not advertise expression node {result['kind']!r}"
            )
        return result

    return compile_one(expression)


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
    kind = expression["kind"]
    if kind in {"const", "var"}:
        return dict(expression)
    if kind in {"add", "mul"}:
        return {
            "kind": kind,
            "e1": _lower_checked_expression(expression["e1"]),
            "e2": _lower_checked_expression(expression["e2"]),
        }
    if kind == "sub":
        return {
            "kind": "add",
            "e1": _lower_checked_expression(expression["e1"]),
            "e2": {"kind": "neg", "e": _lower_checked_expression(expression["e2"])},
        }
    if kind == "div":
        return {
            "kind": "mul",
            "e1": _lower_checked_expression(expression["e1"]),
            "e2": {"kind": "inv", "e": _lower_checked_expression(expression["e2"])},
        }
    if kind == "pow":
        base = _lower_checked_expression(expression["base"])

        def power(exponent: int) -> dict[str, Any]:
            if exponent == 0:
                return {"kind": "const", "val": {"n": 1, "d": 1}}
            return {"kind": "mul", "e1": base, "e2": power(exponent - 1)}

        return power(expression["exp"])
    if kind in {
        "neg", "inv", "exp", "sin", "cos", "log", "atan", "arsinh",
        "atanh", "sinc", "erf", "sinh", "cosh", "tanh",
    }:
        return {"kind": kind, "e": _lower_checked_expression(expression["e"])}
    if kind == "sqrt":
        argument = _lower_checked_expression(expression["e"])
        return {
            "kind": "exp",
            "e": {
                "kind": "mul",
                "e1": {"kind": "log", "e": argument},
                "e2": {"kind": "inv", "e": {"kind": "const", "val": {"n": 2, "d": 1}}},
            },
        }
    raise _UnsupportedBound(f"cannot validate replay lowering for expression kind {kind!r}")


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
        box=tuple(
            ResultInterval(item.lower.fraction, item.upper.fraction) for item in payload.box
        ),
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
        expression_json = _compile_expression(
            plan.expression, indices, contract.expression_nodes
        )
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
        {"lo": _rat(_rational(axis.interval.lower, "domain lower endpoint")),
         "hi": _rat(_rational(axis.interval.upper, "domain upper endpoint"))}
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
    return Inconclusive(
        **common,
        reason="The checked enclosure was insufficient for the normalized claim.",
    )


def try_plan_bound_claim(claim: ast.Claim) -> tuple[BoundPlan | None, str | None]:
    try:
        return plan_bound_claim(claim), None
    except _UnsupportedBound as exc:
        return None, str(exc)
