"""Checked integral equalities and bounds through the unified proving API."""

from __future__ import annotations

import copy
import json
from fractions import Fraction
from pathlib import Path

import pytest

import leancert as lc
from leancert import ast
from leancert.client import _bridge_core_expression
from leancert.exceptions import ProtocolViolation
from leancert.protocol import BridgeHandshake

FIXTURES = Path(__file__).parent / "fixtures" / "bridge-contract-2.1"


def rat(value: Fraction | int) -> dict[str, int]:
    value = Fraction(value)
    return {"n": value.numerator, "d": value.denominator}


def contract_26() -> tuple[dict, BridgeHandshake]:
    info = json.loads((FIXTURES / "handshake.json").read_text(encoding="utf-8"))
    info["bridge_api_version"] = info["protocol_version"] = "2.6.0"
    info["operations"].append("check_integral")
    if "pow" not in info["expression_nodes"]:
        info["expression_nodes"].append("pow")
    info["certificate_schemas"].append("integral-check/1")
    info["capabilities"]["check_integral"] = {
        "schema_version": "2.6",
        "request_schema": "check-integral-request/1",
        "result_schema": "integral-outcome/1",
        "outcomes": [
            "verified",
            "candidate_rejected",
            "inconclusive",
            "unsupported",
            "domain_obstruction",
        ],
        "backends": ["rational_exact_polynomial", "rational_checked_partitions"],
        "certificate_schemas": ["integral-check/1"],
        "verification_routes": ["compiled_checker"],
    }
    return info, BridgeHandshake.parse(info)


AUTHORITIES = {
    "eq": (
        "LeanCert.Engine.QPoly.checkExactIntegral",
        "LeanCert.Engine.QPoly.integral_eq_of_check",
    ),
    "lower": (
        "LeanCert.Validity.Integration.checkIntegralPartitionLowerBound",
        "LeanCert.Validity.Integration.integral_partition_lower_of_check",
    ),
    "upper": (
        "LeanCert.Validity.Integration.checkIntegralPartitionUpperBound",
        "LeanCert.Validity.Integration.integral_partition_upper_of_check",
    ),
}


class FakeIntegralClient:
    def __init__(self, status: str = "verified"):
        self.bridge_info, self.bridge_contract = contract_26()
        self.status = status
        self.calls: list[dict] = []

    def check_integral(
        self,
        expression,
        interval,
        relation,
        bound,
        *,
        start_partitions=32,
        max_partitions=4096,
    ):
        self.calls.append(
            {
                "expression": expression,
                "interval": interval,
                "relation": relation,
                "bound": bound,
                "start_partitions": start_partitions,
                "max_partitions": max_partitions,
            }
        )
        exact = relation == "eq"
        partitions = None if exact else start_partitions
        lowered = _bridge_core_expression(expression)
        checker, verifier = AUTHORITIES[relation]
        response = {
            "verified": True,
            "status": "verified",
            "relation": relation,
            "route": "exact_polynomial" if exact else "checked_partitions",
            "backend": ("rational_exact_polynomial" if exact else "rational_checked_partitions"),
            "interval": copy.deepcopy(interval),
            "bound": rat(bound),
            "enclosure": {"lo": rat(bound), "hi": rat(bound)},
            "search": {
                "source": "exact" if exact else "automatic",
                "start_partitions": None if exact else start_partitions,
                "max_partitions": None if exact else max_partitions,
                "chosen_partitions": partitions,
                "attempts": 0 if exact else 1,
                "failure": None,
            },
            "certificate": {
                "schema_version": "integral-check/1",
                "checker": checker,
                "verifier": verifier,
                "verification_route": "compiled_checker",
                "payload": {
                    "schema_version": "checked-integral/1",
                    "expression": lowered,
                    "interval": copy.deepcopy(interval),
                    "relation": relation,
                    "bound": rat(bound),
                    "partitions": partitions,
                },
            },
        }
        if self.status != "verified":
            response["verified"] = False
            response["status"] = self.status
            response["certificate"] = None
            response["search"]["failure"] = {
                "kind": self.status,
                "detail": "test non-success",
            }
        return response


def integral_expression():
    x = ast.var("x")
    return x, ast.integral(x**2, x, 0, 1)


def test_prove_exact_polynomial_integral_equality():
    _, integral = integral_expression()
    client = FakeIntegralClient()
    result = lc.prove(ast.eq(integral, Fraction(1, 3)), client=client)

    assert isinstance(result, lc.VerifiedIntegralEquality)
    assert result.relation == "eq"
    assert result.bound == Fraction(1, 3)
    assert result.enclosure == lc.Interval(Fraction(1, 3), Fraction(1, 3))
    assert result.search.source == "exact"
    assert result.certificate.partitions is None
    assert result.certificate.payload_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("claim_builder", "relation"),
    [
        (lambda integral: integral <= Fraction(1, 2), "upper"),
        (lambda integral: Fraction(1, 4) <= integral, "lower"),
    ],
)
def test_prove_one_sided_integral_bounds(claim_builder, relation):
    _, integral = integral_expression()
    client = FakeIntegralClient()
    config = lc.ProveConfig(integral=lc.IntegralConfig(16, 256))
    result = lc.prove(claim_builder(integral), config=config, client=client)

    assert isinstance(result, lc.VerifiedIntegralBound)
    assert result.relation == relation
    assert result.search.chosen_partitions == 16
    assert result.certificate.partitions == 16
    assert client.calls[0]["max_partitions"] == 256


@pytest.mark.parametrize(
    ("status", "result_type"),
    [
        ("candidate_rejected", lc.IntegralCandidateRejected),
        ("inconclusive", lc.InconclusiveIntegral),
        ("domain_obstruction", lc.IntegralDomainObstruction),
        ("unsupported", lc.UnsupportedIntegral),
    ],
)
def test_integral_non_successes_are_typed(status, result_type):
    _, integral = integral_expression()
    result = lc.prove(
        integral <= Fraction(1, 2),
        client=FakeIntegralClient(status),
    )
    assert isinstance(result, result_type)


def test_strict_integral_bound_is_not_silently_weakened():
    _, integral = integral_expression()
    client = FakeIntegralClient()
    result = lc.prove(integral < Fraction(1, 2), client=client)
    assert isinstance(result, lc.Unsupported)
    assert "strict integral" in result.reason
    assert client.calls == []


def test_integral_protocol_rejects_mutated_fixed_payload():
    _, contract = contract_26()
    _, integral = integral_expression()
    client = FakeIntegralClient()
    lc.prove(ast.eq(integral, Fraction(1, 3)), client=client)
    call = client.calls[0]
    response = client.check_integral(
        call["expression"],
        call["interval"],
        call["relation"],
        call["bound"],
    )
    response["certificate"]["payload"]["bound"] = rat(Fraction(1, 2))
    with pytest.raises(ProtocolViolation):
        contract.parse_integral_outcome(response, expected_relation="eq")


def test_integral_results_export_fixed_kernel_projects(tmp_path):
    _, integral = integral_expression()
    claims = {
        "exact": ast.eq(integral, Fraction(1, 3)),
        "upper": integral <= Fraction(1, 2),
    }
    for name, claim in claims.items():
        result = lc.prove(claim, client=FakeIntegralClient())
        exported = result.export_lean_project(str(tmp_path / name), verify=False)
        assert isinstance(exported, lc.ExportPrepared)
        source = (tmp_path / name / "LeanCertExport.lean").read_text(encoding="utf-8")
        assert "#assert_trust kernel exported_claim" in source
        assert result.certificate.checker.rsplit(".", 1)[-1] in source
