"""Contract 2.7 strict global bounds and standalone replay."""

from __future__ import annotations

import json
from copy import deepcopy
from fractions import Fraction
from pathlib import Path

import pytest

import leancert as lc
from leancert import ast
from leancert.exceptions import ProtocolViolation
from leancert.protocol import BridgeHandshake, StrictBoundOperationOutcome

FIXTURES = Path(__file__).parent / "fixtures" / "bridge-contract-2.1"


def strict_handshake() -> dict:
    info = json.loads((FIXTURES / "handshake.json").read_text())
    info["bridge_api_version"] = info["protocol_version"] = "2.7.0"
    info["bridge_version"] = "0.8.0"
    info["expression_nodes"].extend(["sin", "cos", "exp", "pow"])
    info["operations"].append("check_strict_bound")
    info["certificate_schemas"].append("strict-bound-check/1")
    info["capabilities"]["check_strict_bound"] = {
        "schema_version": "2.7",
        "request_schema": "check-strict-bound-request/1",
        "result_schema": "strict-bound-outcome/1",
        "outcomes": ["verified", "inconclusive", "unsupported", "domain_obstruction"],
        "backends": ["rational_global_optimization"],
        "certificate_schemas": ["strict-bound-check/1"],
        "verification_routes": ["compiled_checker"],
    }
    return info


def strict_response(
    *, relation: str = "lt", target: Fraction = Fraction(2), certified: Fraction = Fraction(1)
) -> dict:
    checker = (
        "LeanCert.Validity.GlobalOpt.checkGlobalUpperBound"
        if relation == "lt"
        else "LeanCert.Validity.GlobalOpt.checkGlobalLowerBound"
    )
    verifier = (
        "LeanCert.Validity.GlobalOpt.verify_global_upper_bound"
        if relation == "lt"
        else "LeanCert.Validity.GlobalOpt.verify_global_lower_bound"
    )

    def rat(value: Fraction) -> dict[str, int]:
        return {"n": value.numerator, "d": value.denominator}

    enclosure = (
        {"lo": rat(min(Fraction(0), certified)), "hi": rat(certified)}
        if relation == "lt"
        else {"lo": rat(certified), "hi": rat(max(Fraction(1), certified))}
    )
    return {
        "verified": True,
        "status": "verified",
        "relation": relation,
        "target_bound": rat(target),
        "certified_bound": rat(certified),
        "enclosure": enclosure,
        "backend": "rational_global_optimization",
        "certificate": {
            "schema_version": "strict-bound-check/1",
            "checker": checker,
            "verifier": verifier,
            "verification_route": "compiled_checker",
            "payload": {
                "schema_version": "checked-strict-bound/1",
                "expression": {"kind": "var", "idx": 0},
                "box": [{"lo": {"n": 0, "d": 1}, "hi": {"n": 1, "d": 1}}],
                "relation": relation,
                "target_bound": rat(target),
                "certified_bound": rat(certified),
                "config": {
                    "max_iterations": 1000,
                    "tolerance": {"n": 1, "d": 1000},
                    "use_monotonicity": True,
                    "taylor_depth": 10,
                },
            },
        },
    }


class StrictClient:
    def __init__(self, responses: tuple[dict, ...], normal_responses: tuple[dict, ...] = ()):
        info = strict_handshake()
        self.bridge_contract = BridgeHandshake.parse(info)
        self.bridge_info = info
        self.responses = list(responses)
        self.normal_responses = list(normal_responses)
        self.calls: list[dict] = []

    def check_strict_bound(self, expr_json, box_json, bound, relation, taylor_depth=10):
        self.calls.append(
            {
                "expr": expr_json,
                "box": box_json,
                "bound": bound,
                "relation": relation,
                "taylor_depth": taylor_depth,
            }
        )
        response = deepcopy(self.responses.pop(0))
        if response.get("certificate") is not None:
            response["certificate"]["payload"]["expression"] = deepcopy(expr_json)
            response["certificate"]["payload"]["box"] = deepcopy(box_json)
        return response

    def check_bound(self, expr_json, box_json, bound, is_upper_bound, taylor_depth=10):
        response = deepcopy(self.normal_responses.pop(0))
        direction = "upper" if is_upper_bound else "lower"
        response["direction"] = direction
        payload = response["certificate"]["payload"]
        payload["expression"] = deepcopy(expr_json)
        payload["box"] = deepcopy(box_json)
        payload["bound"] = deepcopy(bound)
        payload["direction"] = direction
        return response


def test_strict_upper_and_lower_claims_use_contract_27():
    x = ast.var("x")
    upper_client = StrictClient((strict_response(),))
    upper = lc.prove(x < 2, where={x: (0, 1)}, client=upper_client)
    assert isinstance(upper, lc.Verified)
    assert upper.checks[0].strict
    assert isinstance(upper.checks[0].replay_certificate, lc.ReplayableStrictBoundCertificate)
    assert upper_client.calls[0]["relation"] == "lt"

    lower_client = StrictClient(
        (strict_response(relation="gt", target=Fraction(-1), certified=Fraction(0)),)
    )
    lower = lc.prove(x > -1, where={x: (0, 1)}, client=lower_client)
    assert isinstance(lower, lc.Verified)
    assert lower_client.calls[0]["relation"] == "gt"


def test_touching_strict_boundary_is_inconclusive_without_certificate():
    x = ast.var("x")
    response = strict_response(target=Fraction(1), certified=Fraction(1))
    response.update(verified=False, status="inconclusive", certificate=None)
    result = lc.prove(x < 1, where={x: (0, 1)}, client=StrictClient((response,)))
    assert isinstance(result, lc.Inconclusive)


def test_expression_to_expression_strict_comparison_is_lowered():
    x = ast.var("x")
    response = strict_response(target=Fraction(0), certified=Fraction(-1, 10))
    client = StrictClient((response,))
    result = lc.prove(ast.sin(x) < x, where={x: (0, 1)}, client=client)
    assert isinstance(result, lc.Verified)
    assert result.lowerings[0].strict
    assert result.lowerings[0].rule == "subtract_rhs_le_zero"
    assert client.calls[0]["relation"] == "lt"


def test_mixed_strict_and_nonstrict_two_sided_claim():
    x = ast.var("x")
    normal = json.loads((FIXTURES / "verified-bound.json").read_text())
    client = StrictClient(
        (strict_response(relation="gt", target=Fraction(0), certified=Fraction(1, 2)),),
        (normal,),
    )
    result = lc.prove(
        ast.all_of(x > 0, x <= 1),
        where={x: (Fraction(1, 2), 1)},
        client=client,
    )
    assert isinstance(result, lc.Verified)
    assert [(check.direction, check.strict) for check in result.checks] == [
        ("lower", True),
        ("upper", False),
    ]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["certificate"]["payload"].update(
                relation="gt", target_bound={"n": 0, "d": 1}
            ),
            "contradicts",
        ),
        (
            lambda value: value["certificate"]["payload"].update(target_bound={"n": 3, "d": 1}),
            "contradicts",
        ),
        (
            lambda value: value["certificate"]["payload"].update(certified_bound={"n": 3, "d": 1}),
            "margin",
        ),
        (lambda value: value["certificate"].update(verifier="Untrusted.claim"), "authority"),
    ],
)
def test_strict_protocol_rejects_tampered_certificates(mutate, message):
    value = strict_response()
    mutate(value)
    with pytest.raises(ProtocolViolation, match=message):
        StrictBoundOperationOutcome.parse(value, expected_relation="lt")


def test_strict_result_exports_fixed_bound_and_exact_margin(tmp_path):
    x = ast.var("x")
    result = lc.prove(x < 2, where={x: (0, 1)}, client=StrictClient((strict_response(),)))
    exported = result.export_lean_project(tmp_path / "strict-proof", verify=False)
    assert isinstance(exported, lc.ExportPrepared)
    source = (tmp_path / "strict-proof" / "LeanCertExport.lean").read_text()
    assert "checkGlobalUpperBound expression_0 domain_0 (1 : ℚ)" in source
    assert "lt_of_le_of_lt" in source
    assert "Expr.eval ρ semantic_lhs_0 < Expr.eval ρ semantic_rhs_0" in source
    assert "#assert_trust kernel strict_claim_0" in source
