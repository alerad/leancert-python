"""Checked reciprocal-power eventual bounds through the unified API."""

from __future__ import annotations

import copy
import json
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import pytest

import leancert as lc
from leancert import ast
from leancert.exceptions import ProtocolViolation
from leancert.protocol import BridgeHandshake

FIXTURES = Path(__file__).parent / "fixtures" / "bridge-contract-2.1"


def rat(value: Fraction | int) -> dict[str, int]:
    value = Fraction(value)
    return {"n": value.numerator, "d": value.denominator}


def contract_24() -> tuple[dict, BridgeHandshake]:
    info = json.loads((FIXTURES / "handshake.json").read_text(encoding="utf-8"))
    info["bridge_api_version"] = info["protocol_version"] = "2.4.0"
    info["operations"].append("check_eventual_bound")
    info["certificate_schemas"].append("eventual-bound-check/1")
    info["capabilities"]["check_eventual_bound"] = {
        "schema_version": "2.4",
        "request_schema": "check-eventual-bound-request/1",
        "result_schema": "eventual-bound-outcome/1",
        "outcomes": ["verified", "candidate_rejected", "inconclusive", "unsupported"],
        "backends": ["rational_reciprocal_power"],
        "certificate_schemas": ["eventual-bound-check/1"],
        "verification_routes": ["compiled_checker"],
    }
    return info, BridgeHandshake.parse(info)


def verified_response(
    coefficient: Fraction,
    bound: Fraction,
    exponent: int,
    cutoff: int,
) -> dict:
    return {
        "verified": True,
        "status": "verified",
        "backend": "rational_reciprocal_power",
        "cutoff": cutoff,
        "search": {
            "source": "automatic",
            "checks": 11,
            "configured_limit": 1000,
            "exponential_steps": 6,
            "refinement_steps": 5,
            "lower_bracket": cutoff - 1,
            "upper_bracket": cutoff,
            "refinement_complete": True,
        },
        "failure": None,
        "certificate": {
            "schema_version": "eventual-bound-check/1",
            "checker": "LeanCert.Validity.checkReciprocalPowerUpper",
            "verifier": "LeanCert.Validity.verify_reciprocal_power_upper",
            "verification_route": "compiled_checker",
            "payload": {
                "schema_version": "checked-eventual-bound/1",
                "coefficient": rat(coefficient),
                "bound": rat(bound),
                "exponent": exponent,
                "cutoff": cutoff,
            },
        },
    }


class FakeEventualClient:
    def __init__(self, status: str = "verified"):
        self.bridge_info, self.bridge_contract = contract_24()
        self.environment = SimpleNamespace(id="env_" + "a" * 64)
        self.execution_id = "execution_" + "b" * 64
        self.status = status
        self.calls: list[dict] = []

    def check_eventual_bound(self, coefficient, bound, exponent, *, cutoff=None, max_checks=1000):
        self.calls.append(
            {
                "coefficient": coefficient,
                "bound": bound,
                "exponent": exponent,
                "cutoff": cutoff,
                "max_checks": max_checks,
            }
        )
        selected = 55 if cutoff is None else cutoff
        response = verified_response(coefficient, bound, exponent, selected)
        response["search"] = {"source": "provided"} if cutoff is not None else response["search"]
        if self.status != "verified":
            response["verified"] = False
            response["status"] = self.status
            response["certificate"] = None
            response["failure"] = {
                "kind": "search_exhausted" if self.status == "inconclusive" else "rejected_cutoff",
                "detail": "test non-success",
            }
            if self.status == "inconclusive":
                response["cutoff"] = None
        return response


def reciprocal_claim(*, cutoff=None):
    n = ast.var("n", sort=ast.NATURAL)
    return ast.eventually(3 / n**2 <= Fraction(1, 1000), variable=n, cutoff=cutoff)


def test_prove_discovers_and_retains_fixed_eventual_certificate():
    client = FakeEventualClient()
    result = lc.prove(reciprocal_claim(), client=client)

    assert isinstance(result, lc.VerifiedEventualBound)
    assert isinstance(result, lc.ProofResult)
    assert result.cutoff == 55
    assert result.coefficient == 3
    assert result.exponent == 2
    assert result.bound == Fraction(1, 1000)
    assert result.search.source == "automatic"
    assert result.search.refinement_complete is True
    assert result.certificate.cutoff == 55
    assert result.claim_id == ast.semantic_digest(result.normalized_claim)


def test_explicit_cutoff_and_search_budget_are_sent_exactly():
    client = FakeEventualClient()
    result = lc.prove(
        reciprocal_claim(cutoff=100),
        config=lc.ProveConfig(eventual=lc.EventualConfig(max_checks=17)),
        client=client,
    )
    assert isinstance(result, lc.VerifiedEventualBound)
    assert result.cutoff == 100
    assert result.search.source == "provided"
    assert client.calls == [
        {
            "coefficient": Fraction(3),
            "bound": Fraction(1, 1000),
            "exponent": 2,
            "cutoff": 100,
            "max_checks": 17,
        }
    ]


@pytest.mark.parametrize(
    ("status", "result_type"),
    [
        ("candidate_rejected", lc.EventualCandidateRejected),
        ("inconclusive", lc.InconclusiveEventualBound),
        ("unsupported", lc.UnsupportedEventualBound),
    ],
)
def test_eventual_non_successes_remain_typed(status, result_type):
    result = lc.prove(reciprocal_claim(), client=FakeEventualClient(status))
    assert isinstance(result, result_type)
    assert not isinstance(result, lc.VerifiedEventualBound)


def test_unsupported_tail_shape_does_not_call_bridge():
    n = ast.var("n", sort=ast.NATURAL)
    client = FakeEventualClient()
    result = lc.prove(ast.eventually(n <= 10, variable=n), client=client)
    assert isinstance(result, lc.UnsupportedEventualBound)
    assert client.calls == []


def test_tampered_eventual_authority_and_payload_are_rejected():
    _, contract = contract_24()
    response = verified_response(Fraction(3), Fraction(1, 1000), 2, 55)

    wrong_checker = copy.deepcopy(response)
    wrong_checker["certificate"]["checker"] = "Untrusted.accept"
    with pytest.raises(ProtocolViolation, match="authority"):
        contract.parse_eventual_outcome(wrong_checker)

    wrong_cutoff = copy.deepcopy(response)
    wrong_cutoff["certificate"]["payload"]["cutoff"] = 56
    with pytest.raises(ProtocolViolation, match="contradicts"):
        contract.parse_eventual_outcome(wrong_cutoff)

    rejected_with_certificate = copy.deepcopy(response)
    rejected_with_certificate["verified"] = False
    rejected_with_certificate["status"] = "candidate_rejected"
    rejected_with_certificate["failure"] = {
        "kind": "rejected_cutoff",
        "detail": "rejected",
    }
    with pytest.raises(ProtocolViolation, match="only verified"):
        contract.parse_eventual_outcome(rejected_with_certificate)


def test_verified_eventual_bound_exports_fixed_kernel_project(tmp_path):
    result = lc.prove(reciprocal_claim(), client=FakeEventualClient())
    exported = result.export_lean_project(tmp_path / "eventual-proof", verify=False)
    assert isinstance(exported, lc.ExportPrepared)
    source = (tmp_path / "eventual-proof" / "LeanCertExport.lean").read_text(encoding="utf-8")
    assert "checkReciprocalPowerUpper" in source
    assert "verify_reciprocal_power_upper" in source
    assert "#assert_trust kernel exported_claim" in source
    manifest = json.loads(
        (tmp_path / "eventual-proof" / "certificate.json").read_text(encoding="utf-8")
    )
    assert manifest["schema_version"] == "eventual-bound-check/1"
    assert manifest["payload"]["cutoff"] == 55


def test_eventual_config_rejects_invalid_budget():
    with pytest.raises(ValueError, match="positive"):
        lc.EventualConfig(max_checks=0)
