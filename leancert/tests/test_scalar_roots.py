"""Checked scalar-root claims through the unified proving API."""

from __future__ import annotations

import copy
import json
from fractions import Fraction
from pathlib import Path

import leancert as lc
from leancert import ast
from leancert.client import _bridge_core_expression
from leancert.protocol import BridgeHandshake

FIXTURES = Path(__file__).parent / "fixtures" / "bridge-contract-2.1"


def rat(value: Fraction | int) -> dict[str, int]:
    value = Fraction(value)
    return {"n": value.numerator, "d": value.denominator}


def contract_25() -> tuple[dict, BridgeHandshake]:
    info = json.loads((FIXTURES / "handshake.json").read_text(encoding="utf-8"))
    info["bridge_api_version"] = info["protocol_version"] = "2.5.0"
    info["operations"].append("check_scalar_root")
    info["certificate_schemas"].append("scalar-root-check/1")
    info["capabilities"]["check_scalar_root"] = {
        "schema_version": "2.5",
        "request_schema": "check-scalar-root-request/1",
        "result_schema": "scalar-root-outcome/1",
        "outcomes": ["verified", "candidate_rejected", "unsupported"],
        "backends": ["rational_scalar_root"],
        "certificate_schemas": ["scalar-root-check/1"],
        "verification_routes": ["compiled_checker"],
    }
    return info, BridgeHandshake.parse(info)


AUTHORITIES = {
    "exists": (
        "LeanCert.Validity.RootFinding.checkSignChange",
        "LeanCert.Validity.RootFinding.verify_sign_change",
    ),
    "unique": (
        "LeanCert.Validity.RootFinding.checkNewtonContractsCore",
        "LeanCert.Validity.RootFinding.verify_unique_root_computable",
    ),
    "excluded": (
        "LeanCert.Validity.RootFinding.checkNoRoot",
        "LeanCert.Validity.RootFinding.verify_no_root",
    ),
}


class FakeScalarRootClient:
    def __init__(self, status: str = "verified"):
        self.bridge_info, self.bridge_contract = contract_25()
        self.status = status
        self.calls: list[dict] = []

    def check_scalar_root(self, expression, interval, claim, *, taylor_depth=10):
        self.calls.append(
            {
                "expression": expression,
                "interval": interval,
                "claim": claim,
                "taylor_depth": taylor_depth,
            }
        )
        checker, verifier = AUTHORITIES[claim]
        lowered = _bridge_core_expression(expression)
        response = {
            "verified": True,
            "status": "verified",
            "claim": claim,
            "backend": "rational_scalar_root",
            "interval": copy.deepcopy(interval),
            "certificate": {
                "schema_version": "scalar-root-check/1",
                "checker": checker,
                "verifier": verifier,
                "verification_route": "compiled_checker",
                "payload": {
                    "schema_version": "checked-scalar-root/1",
                    "expression": lowered,
                    "interval": copy.deepcopy(interval),
                    "claim": claim,
                    "config": {"taylor_depth": taylor_depth},
                },
            },
        }
        if self.status != "verified":
            response["verified"] = False
            response["status"] = self.status
            response["certificate"] = None
        return response


def test_prove_routes_all_three_scalar_root_claims():
    x = ast.var("x")
    claims = (
        (ast.root_exists(x, variable=x, within=(-1, 1)), lc.VerifiedRootExistence),
        (ast.unique_root(x, variable=x, within=(-1, 1)), lc.VerifiedUniqueRoot),
        (ast.root_excluded(x + 2, variable=x, within=(-1, 1)), lc.VerifiedRootExclusion),
    )
    for claim, result_type in claims:
        client = FakeScalarRootClient()
        result = lc.prove(claim, client=client)
        assert isinstance(result, result_type)
        assert result.claim_id == ast.semantic_digest(result.normalized_claim)
        assert result.certificate.payload_schema == "checked-scalar-root/1"
        assert result.certificate.payload_digest.startswith("sha256:")
        assert client.calls[0]["taylor_depth"] == 10


def test_rejected_interval_is_not_misreported_as_a_refutation():
    x = ast.var("x")
    result = lc.prove(
        ast.root_exists(x, variable=x, within=(1, 2)),
        client=FakeScalarRootClient("candidate_rejected"),
    )
    assert isinstance(result, lc.ScalarRootCandidateRejected)
    assert not isinstance(result, lc.VerifiedRootExistence)


def test_unsupported_expression_is_typed():
    x = ast.var("x")
    result = lc.prove(
        ast.unique_root(ast.sqrt(x), variable=x, within=(1, 2)),
        client=FakeScalarRootClient("unsupported"),
    )
    assert isinstance(result, lc.UnsupportedScalarRoot)


def test_open_or_nonrational_root_domains_are_not_sent_to_bridge():
    x = ast.var("x")
    client = FakeScalarRootClient()
    claim = ast.RootExistsClaim(x, x, ast.interval(-1, 1, lower_closed=False))
    result = lc.prove(claim, client=client)
    assert isinstance(result, lc.UnsupportedScalarRoot)
    assert client.calls == []


def test_scalar_root_response_claim_must_match_request():
    _, contract = contract_25()
    response = FakeScalarRootClient().check_scalar_root(
        {"kind": "var", "idx": 0},
        {"lo": rat(-1), "hi": rat(1)},
        "exists",
    )
    try:
        contract.parse_scalar_root_outcome(response, expected_claim="unique")
    except lc.BridgeError:
        pass
    else:
        raise AssertionError("mismatched scalar-root claim was accepted")


def test_all_scalar_root_outcomes_export_fixed_kernel_projects(tmp_path):
    x = ast.var("x")
    claims = {
        "exists": ast.root_exists(x, variable=x, within=(-1, 1)),
        "unique": ast.unique_root(x, variable=x, within=(-1, 1)),
        "excluded": ast.root_excluded(x + 2, variable=x, within=(-1, 1)),
    }
    for name, claim in claims.items():
        result = lc.prove(claim, client=FakeScalarRootClient())
        exported = result.export_lean_project(str(tmp_path / name), verify=False)
        assert isinstance(exported, lc.ExportPrepared)
        source = (tmp_path / name / "LeanCertExport.lean").read_text(encoding="utf-8")
        assert "#assert_trust kernel exported_claim" in source
        assert AUTHORITIES[name][0].rsplit(".", 1)[-1] in source
