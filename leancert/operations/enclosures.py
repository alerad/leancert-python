"""Contract 2.8 registered downstream enclosure proving and fixed replay."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from fractions import Fraction
from types import MappingProxyType
from typing import Any

from .. import ast
from ..client import _parse_rat
from ..domain import Interval as ResultInterval
from ..exceptions import BridgeError, ProtocolViolation
from ..protocol import OutcomeStatus
from ..result import (
    BoundCheckEvidence,
    DomainObstruction,
    Inconclusive,
    ReplayableRegisteredEnclosureCertificate,
    Unsupported,
    VerifiedRegisteredEnclosure,
)
from .bounds import BoundPlan, bridge_provenance, unsupported_result


def _rat(value: Fraction) -> dict[str, int]:
    return {"n": value.numerator, "d": value.denominator}


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(value: Any) -> str:
    encoded = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


_BUILTINS = {
    "sin", "cos", "exp", "log", "sqrt", "atan", "arsinh", "atanh", "sinc",
    "erf", "abs", "sinh", "cosh", "tanh",
}


def _compile_registered(expression: ast.Expr, variable: ast.Variable, environment: Any) -> dict:
    def go(node: ast.Expr) -> dict:
        if isinstance(node, ast.RationalConstant):
            return {"kind": "const", "val": _rat(node.value)}
        if isinstance(node, ast.Variable):
            if node != variable:
                raise ValueError("registered enclosures currently support one bound variable")
            return {"kind": "var", "idx": 0}
        if isinstance(node, ast.Cast):
            return go(node.expression)
        if isinstance(node, ast.Neg):
            return {"kind": "neg", "e": go(node.expression)}
        if isinstance(node, ast.Add):
            values = tuple(node.terms)
            result = go(values[0])
            for value in values[1:]:
                result = {"kind": "add", "e1": result, "e2": go(value)}
            return result
        if isinstance(node, ast.Mul):
            values = tuple(node.factors)
            result = go(values[0])
            for value in values[1:]:
                result = {"kind": "mul", "e1": result, "e2": go(value)}
            return result
        if isinstance(node, ast.Div):
            return {"kind": "div", "e1": go(node.numerator), "e2": go(node.denominator)}
        if isinstance(node, ast.Pow):
            exponent = node.exponent.value
            if exponent.denominator != 1 or exponent < 0:
                raise ValueError("registered enclosure powers require non-negative integers")
            return {"kind": "pow", "base": go(node.base), "exp": int(exponent)}
        if isinstance(node, ast.FunctionCall):
            if isinstance(node.function, ast.ExternalFunctionRef):
                if len(node.arguments) != 1 or not environment.validates(node.function):
                    raise ValueError(
                        "external function is not a handle issued by this enclosure profile"
                    )
                return {
                    "kind": "registered",
                    "function": node.function.lean_name,
                    "argument": go(node.arguments[0]),
                }
            name = node.function.name
            if name not in _BUILTINS or len(node.arguments) != 1:
                raise ValueError(f"builtin {name!r} is outside the registered enclosure fragment")
            return {"kind": name, "e": go(node.arguments[0])}
        raise ValueError(f"{type(node).__name__} is outside the registered enclosure fragment")

    return go(expression)


def _profile_matches(certificate: Mapping[str, Any], environment: Any) -> None:
    profile = certificate.get("profile")
    if not isinstance(profile, Mapping):
        raise ProtocolViolation("registered enclosure certificate lacks profile identity")
    expected = environment.identity
    expected_registry = [
        {
            "function": rule.function,
            "candidate": rule.candidate,
            "checker": rule.checker,
            "theorem": rule.theorem,
            "priority": rule.priority,
        }
        for rule in expected.registry
    ]
    if any(
        (
            profile.get("schema_version") != expected.schema_version,
            profile.get("name") != expected.name,
            profile.get("modules") != list(expected.modules),
            profile.get("allowed_functions") != list(expected.allowed_functions),
            profile.get("leancert_revision") != expected.leancert_revision,
            profile.get("environment_digest") != expected.environment_digest,
            profile.get("registry") != expected_registry,
        )
    ):
        raise ProtocolViolation("registered enclosure certificate profile identity mismatch")


def _interval(value: Any, name: str) -> None:
    if not isinstance(value, Mapping) or set(value) != {"lo", "hi"}:
        raise ProtocolViolation(f"{name} must contain exactly lo and hi")
    endpoints = []
    for endpoint in ("lo", "hi"):
        rational = value[endpoint]
        if not isinstance(rational, Mapping) or set(rational) != {"n", "d"}:
            raise ProtocolViolation(f"{name}.{endpoint} must be an exact rational")
        numerator, denominator = rational["n"], rational["d"]
        if (
            isinstance(numerator, bool)
            or not isinstance(numerator, int)
            or isinstance(denominator, bool)
            or not isinstance(denominator, int)
            or denominator <= 0
        ):
            raise ProtocolViolation(f"{name}.{endpoint} is not a canonical rational")
        endpoints.append(Fraction(numerator, denominator))
    if endpoints[0] > endpoints[1]:
        raise ProtocolViolation(f"{name} is inverted")


def _tree(value: Any, name: str = "certificate.tree") -> None:
    if not isinstance(value, Mapping):
        raise ProtocolViolation(f"{name} must be an object")
    kind = value.get("kind")
    if kind == "bisect":
        if set(value) != {"kind", "input", "left", "right"}:
            raise ProtocolViolation(f"{name} bisect fields do not match Contract 2.8")
        _interval(value["input"], f"{name}.input")
        _tree(value["left"], f"{name}.left")
        _tree(value["right"], f"{name}.right")
        return
    if kind != "leaf" or set(value) != {
        "kind", "input", "output", "entries", "composition_steps",
    }:
        raise ProtocolViolation(f"{name} is not a Contract 2.8 certificate node")
    _interval(value["input"], f"{name}.input")
    _interval(value["output"], f"{name}.output")
    steps = value["composition_steps"]
    if isinstance(steps, bool) or not isinstance(steps, int) or steps < 0:
        raise ProtocolViolation(f"{name}.composition_steps must be non-negative")
    entries = value["entries"]
    if not isinstance(entries, (list, tuple)):
        raise ProtocolViolation(f"{name}.entries must be an array")
    for index, entry in enumerate(entries):
        entry_name = f"{name}.entries[{index}]"
        if not isinstance(entry, Mapping) or set(entry) != {"rule", "request", "output"}:
            raise ProtocolViolation(f"{entry_name} fields do not match Contract 2.8")
        rule = entry["rule"]
        if not isinstance(rule, Mapping) or set(rule) != {
            "function", "candidate", "checker", "theorem", "priority",
        }:
            raise ProtocolViolation(f"{entry_name}.rule is malformed")
        if any(
            not isinstance(rule[field], str) or not rule[field]
            for field in ("function", "candidate", "checker", "theorem")
        ):
            raise ProtocolViolation(f"{entry_name}.rule names must be non-empty")
        priority = rule["priority"]
        if isinstance(priority, bool) or not isinstance(priority, int) or priority < 0:
            raise ProtocolViolation(f"{entry_name}.rule priority must be non-negative")
        request = entry["request"]
        if not isinstance(request, Mapping) or set(request) != {
            "input", "precision", "taylor_depth",
        }:
            raise ProtocolViolation(f"{entry_name}.request is malformed")
        _interval(request["input"], f"{entry_name}.request.input")
        if isinstance(request["precision"], bool) or not isinstance(request["precision"], int):
            raise ProtocolViolation(f"{entry_name}.request.precision must be an integer")
        depth = request["taylor_depth"]
        if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
            raise ProtocolViolation(f"{entry_name}.request.taylor_depth must be non-negative")
        _interval(entry["output"], f"{entry_name}.output")


def _certificate(
    response: Mapping[str, Any], claim: dict[str, Any], environment: Any
) -> ReplayableRegisteredEnclosureCertificate:
    retained = response.get("certificate")
    if not isinstance(retained, Mapping):
        raise ProtocolViolation("verified registered enclosure response requires a certificate")
    if retained.get("schema") != "registered-enclosure-check/1":
        raise ProtocolViolation("unsupported registered enclosure certificate schema")
    if retained.get("replay_payload_schema") != "checked-registered-enclosure/1":
        raise ProtocolViolation("unsupported registered enclosure replay payload schema")
    _profile_matches(retained, environment)
    if retained.get("precision") != claim["precision"]:
        raise ProtocolViolation("certificate precision differs from the checked request")
    if retained.get("taylor_depth") != claim["taylor_depth"]:
        raise ProtocolViolation("certificate Taylor depth differs from the checked request")
    if retained.get("configured_max_depth") != claim["max_depth"]:
        raise ProtocolViolation("certificate subdivision depth differs from the checked request")
    _tree(retained.get("tree"))
    if _jsonable(retained["tree"]["input"]) != claim["domain"]:
        raise ProtocolViolation("certificate root domain differs from the checked request")
    frozen_claim = _freeze(json.loads(json.dumps(claim)))
    frozen_retained = _freeze(json.loads(json.dumps(_jsonable(retained))))
    payload = {"claim": frozen_claim, "certificate": frozen_retained}
    return ReplayableRegisteredEnclosureCertificate(
        "registered-enclosure-check/1",
        "checked-registered-enclosure/1",
        _digest(payload),
        environment.profile.name,
        environment.profile.leancert_revision,
        environment.profile.environment_digest,
        frozen_claim,
        frozen_retained,
    )


def execute_registered_enclosure_plan(
    plan: BoundPlan,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    client: Any,
    precision: int,
    taylor_depth: int,
    max_depth: int,
):
    provenance = bridge_provenance(client)
    capability = client.bridge_contract.capability("check_registered_enclosure")
    if capability is None or capability.request_schema != "check-registered-enclosure-request/1":
        return unsupported_result(
            original_claim, normalized_claim, claim_id,
            "bridge does not advertise the Contract 2.8 registered enclosure capability",
            provenance=provenance, plan=plan,
        )
    if len(plan.axes) != 1:
        return unsupported_result(
            original_claim, normalized_claim, claim_id,
            "registered enclosures currently require exactly one real interval variable",
            provenance=provenance, plan=plan,
        )
    try:
        environment = client.enclosures
    except (AttributeError, BridgeError):
        return unsupported_result(
            original_claim,
            normalized_claim,
            claim_id,
            "registered enclosure claims require a profile-configured Solver",
            provenance=provenance,
            plan=plan,
        )
    try:
        expression = _compile_registered(plan.expression, plan.axes[0].variable, environment)
    except ValueError as exc:
        return unsupported_result(
            original_claim, normalized_claim, claim_id, str(exc),
            provenance=provenance, plan=plan,
        )
    interval = plan.axes[0].interval
    lo = interval.lower.value
    hi = interval.upper.value
    domain = {"lo": _rat(lo), "hi": _rat(hi)}
    checks = []
    failures: list[tuple[str, str]] = []
    for direction, bound, strict in (
        ("lower", plan.lower, plan.lower_strict),
        ("upper", plan.upper, plan.upper_strict),
    ):
        if bound is None:
            continue
        relation = ("gt" if strict else "ge") if direction == "lower" else (
            "lt" if strict else "le"
        )
        request = {
            "expression": expression,
            "domain": domain,
            "relation": relation,
            "bound": _rat(bound),
            "precision": precision,
            "taylor_depth": taylor_depth,
            "max_depth": max_depth,
        }
        response = client.check_registered_enclosure(request)
        try:
            status = OutcomeStatus(response.get("status"))
        except ValueError as exc:
            raise ProtocolViolation("registered enclosure response has an unknown status") from exc
        if status not in capability.outcomes:
            raise ProtocolViolation("registered enclosure status was not advertised")
        status_text = status.value
        if status is not OutcomeStatus.VERIFIED:
            failures.append((status_text, str(response.get("detail", ""))))
            continue
        enclosure_json = response.get("enclosure")
        if not isinstance(enclosure_json, Mapping):
            raise ProtocolViolation("verified registered enclosure response lacks enclosure")
        for field_name in ("registered_checks", "composition_steps"):
            count = response.get(field_name)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ProtocolViolation(
                    f"verified registered enclosure {field_name} must be non-negative"
                )
        certificate = _certificate(response, request, environment)
        checks.append(
            BoundCheckEvidence(
                direction=direction,
                requested_bound=bound,
                enclosure=ResultInterval(
                    _parse_rat(enclosure_json["lo"]), _parse_rat(enclosure_json["hi"])
                ),
                status="verified",
                operation="check_registered_enclosure",
                backend="registered_enclosure_kernel_proof",
                taylor_depth=taylor_depth,
                certificate=response.get("certificate"),
                replay_certificate=certificate,
                raw_response=dict(response),
                strict=strict,
            )
        )
    common = dict(
        expression=plan.expression, domain=plan.domain, lower=plan.lower, upper=plan.upper,
        checks=tuple(checks), provenance=provenance, lowerings=plan.lowerings,
        original_claim=original_claim, normalized_claim=normalized_claim, claim_id=claim_id,
    )
    if not failures:
        return VerifiedRegisteredEnclosure(**common)
    statuses = {status for status, _ in failures}
    reason = "; ".join(detail or status for status, detail in failures)
    if "domain_obstruction" in statuses:
        return DomainObstruction(**common, reason=reason)
    if "unsupported" in statuses:
        return Unsupported(**common, reason=reason)
    return Inconclusive(**common, reason=reason)


def replay_registered_certificate(
    certificate: ReplayableRegisteredEnclosureCertificate, client: Any
) -> Mapping[str, Any]:
    if hasattr(client, "_ensure_client"):
        client = client._ensure_client()
    environment = client.enclosures
    if (
        certificate.profile_name != environment.profile.name
        or certificate.leancert_revision != environment.profile.leancert_revision
        or certificate.environment_digest != environment.profile.environment_digest
    ):
        raise ProtocolViolation("replay client profile differs from the retained certificate")
    payload = {"claim": certificate.claim, "certificate": certificate.retained}
    if _digest(payload) != certificate.payload_digest:
        raise ProtocolViolation("registered enclosure replay payload digest mismatch")
    response = client.replay_registered_enclosure(
        _jsonable(certificate.claim), _jsonable(certificate.retained)
    )
    if response.get("status") != "verified" or response.get("replayed") is not True:
        raise ProtocolViolation(
            "fixed registered enclosure replay failed: " + str(response.get("detail", "unknown"))
        )
    if _jsonable(response.get("certificate")) != _jsonable(certificate.retained):
        raise ProtocolViolation("fixed replay returned a different retained certificate")
    return MappingProxyType(dict(response))


__all__ = ["execute_registered_enclosure_plan", "replay_registered_certificate"]
