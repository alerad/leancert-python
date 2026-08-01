"""Checked Krawczyk system roots through the unified proving API."""

from __future__ import annotations

import copy
import json
from fractions import Fraction
from pathlib import Path

import numpy as np
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


def contract_23() -> tuple[dict, BridgeHandshake]:
    info = json.loads((FIXTURES / "handshake.json").read_text(encoding="utf-8"))
    info["bridge_api_version"] = info["protocol_version"] = "2.3.0"
    info["bridge_version"] = "0.5.0"
    info["operations"].append("check_unique_system_root")
    info["certificate_schemas"].append("krawczyk-check/1")
    info["expression_nodes"].extend(["exp", "pow"])
    info["capabilities"]["check_unique_system_root"] = {
        "schema_version": "2.3",
        "request_schema": "check-unique-system-root-request/1",
        "result_schema": "unique-system-root-outcome/1",
        "outcomes": ["verified", "candidate_rejected", "unsupported"],
        "backends": ["rational_krawczyk"],
        "certificate_schemas": ["krawczyk-check/1"],
        "verification_routes": ["compiled_checker"],
    }
    return info, BridgeHandshake.parse(info)


def verified_response(system: list[dict], box: list[dict]) -> dict:
    payload = {
        "schema_version": "checked-unique-system-root/1",
        "system": [_bridge_core_expression(item) for item in system],
        "box": box,
        "center": [rat(1), rat(1)],
        "preconditioner": [[rat(Fraction(2, 3)), rat(Fraction(-1, 3))],
                           [rat(Fraction(-1, 3)), rat(Fraction(2, 3))]],
        "config": {"taylor_depth": 10},
    }
    return {
        "verified": True,
        "status": "verified",
        "backend": "rational_krawczyk",
        "root_box": copy.deepcopy(box),
        "search": {
            "source": "automatic",
            "attempts": 1,
            "refinements": 0,
            "contraction_bound": rat(Fraction(1, 5)),
            "failure": None,
        },
        "certificate": {
            "schema_version": "krawczyk-check/1",
            "checker": "LeanCert.Engine.krawczykCheck",
            "verifier": "LeanCert.Validity.verify_unique_system_root",
            "verification_route": "compiled_checker",
            "payload": payload,
        },
    }


class FakeSystemRootClient:
    def __init__(self, status: str = "verified"):
        self.bridge_info, self.bridge_contract = contract_23()
        self.status = status
        self.calls: list[dict] = []

    def check_unique_system_root(self, system_json, box_json, **config):
        self.calls.append({"system": system_json, "box": box_json, **config})
        response = verified_response(system_json, box_json)
        if self.status != "verified":
            response["verified"] = False
            response["status"] = self.status
            response["certificate"] = None
            response["search"]["failure"] = {"kind": "exhausted", "attempts": 2}
        return response


def coupled_claim():
    x, y = ast.var("x"), ast.var("y")
    domain = ast.box(
        {
            x: (Fraction(9, 10), Fraction(11, 10)),
            y: (Fraction(9, 10), Fraction(11, 10)),
        }
    )
    return ast.unique_system_root(
        (x**2 + y - 2, x + y**2 - 2), variables=(x, y), within=domain
    )


def test_prove_unique_system_root_retains_checked_evidence():
    client = FakeSystemRootClient()
    claim = coupled_claim()
    result = lc.prove(claim, client=client)

    assert isinstance(result, lc.VerifiedSystemRoot)
    assert isinstance(result, lc.ProofResult)
    assert result.claim_id == ast.semantic_digest(result.normalized_claim)
    assert result.search.attempts == 1
    assert result.search.contraction_bound == Fraction(1, 5)
    assert result.certificate.checker == "LeanCert.Engine.krawczykCheck"
    assert result.certificate.verifier == "LeanCert.Validity.verify_unique_system_root"
    assert result.certificate.center == (Fraction(1), Fraction(1))
    assert len(client.calls) == 1


def test_numpy_candidate_is_rationalized_and_sent_as_untrusted_input():
    candidate = lc.KrawczykCandidate.from_arrays(
        np.array([1.0, 1.0]),
        np.array([[2 / 3, -1 / 3], [-1 / 3, 2 / 3]]),
        maximum_denominator=100,
    )
    client = FakeSystemRootClient()
    result = lc.prove(
        coupled_claim(),
        config=lc.ProveConfig(system_root=lc.SystemRootConfig(candidate=candidate)),
        client=client,
    )
    assert isinstance(result, lc.VerifiedSystemRoot)
    assert client.calls[0]["candidate"] == candidate.to_wire()
    assert candidate.preconditioner[0][0] == Fraction(2, 3)


def test_candidate_rejection_is_not_verification_or_refutation():
    result = lc.prove(coupled_claim(), client=FakeSystemRootClient("candidate_rejected"))
    assert isinstance(result, lc.CandidateRejected)
    assert not isinstance(result, lc.VerifiedSystemRoot)
    assert "exhausted" in result.reason


def test_existence_only_system_claim_is_typed_unsupported_without_bridge_call():
    unique = coupled_claim()
    claim = ast.system_root_exists(
        unique.equations, variables=unique.variables, within=unique.domain
    )
    client = FakeSystemRootClient()
    result = lc.prove(claim, client=client)
    assert isinstance(result, lc.UnsupportedSystemRoot)
    assert client.calls == []


def test_tampered_krawczyk_authority_and_payload_are_rejected():
    _, contract = contract_23()
    client = FakeSystemRootClient()
    lc.prove(coupled_claim(), client=client)
    call = client.calls[0]
    response = verified_response(call["system"], call["box"])

    wrong_checker = copy.deepcopy(response)
    wrong_checker["certificate"]["checker"] = "Untrusted.accept"
    with pytest.raises(ProtocolViolation, match="authority"):
        contract.parse_system_root_outcome(wrong_checker)

    wrong_box = copy.deepcopy(response)
    wrong_box["certificate"]["payload"]["box"][0]["hi"] = rat(2)
    with pytest.raises(ProtocolViolation, match="contradicts"):
        contract.parse_system_root_outcome(wrong_box)

    rejected_with_certificate = copy.deepcopy(response)
    rejected_with_certificate["verified"] = False
    rejected_with_certificate["status"] = "candidate_rejected"
    with pytest.raises(ProtocolViolation, match="only verified"):
        contract.parse_system_root_outcome(rejected_with_certificate)


def test_verified_system_root_exports_fixed_kernel_project(tmp_path):
    result = lc.prove(coupled_claim(), client=FakeSystemRootClient())
    exported = result.export_lean_project(tmp_path / "root-proof", verify=False)
    assert isinstance(exported, lc.ExportPrepared)
    source = (tmp_path / "root-proof" / "LeanCertExport.lean").read_text(
        encoding="utf-8"
    )
    assert "krawczykCheck system box certificate config = true" in source
    assert "verify_unique_system_root" in source
    assert "#assert_trust kernel exported_claim" in source
    manifest = json.loads(
        (tmp_path / "root-proof" / "certificate.json").read_text(encoding="utf-8")
    )
    assert manifest["schema_version"] == "krawczyk-check/1"


def test_candidate_shapes_and_numbers_are_validated_locally():
    with pytest.raises(ValueError, match="square"):
        lc.KrawczykCandidate.from_arrays([1, 1], [[1]])
    with pytest.raises(ValueError, match="finite"):
        lc.KrawczykCandidate.from_arrays([float("nan")], [[1]])
