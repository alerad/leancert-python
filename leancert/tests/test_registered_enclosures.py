"""Profile binding, semantic routing, and fixed replay for Contract 2.8."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

import leancert as lc
from leancert import ast
from leancert.enclosures import EnclosureEnvironment, EnclosureProfile
from leancert.exceptions import ProtocolViolation
from leancert.protocol import BridgeHandshake

FUNCTION = "Example.Enclosures.shifted"


def profile_file(tmp_path: Path, *, digest: str = "sha256:test-environment") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "profile.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "leancert-enclosure-profile/1",
                "name": "example-profile",
                "modules": ["Example.Enclosures"],
                "allowed_functions": [FUNCTION],
                "leancert_revision": "abc123",
                "environment_digest": digest,
            }
        )
    )
    return path


def handshake(path: Path) -> dict:
    fixture = Path(__file__).parent / "fixtures" / "bridge-contract-2.1" / "handshake.json"
    value = json.loads(fixture.read_text())
    value["bridge_api_version"] = value["protocol_version"] = "2.8.0"
    value["bridge_version"] = "0.9.0"
    value["operations"].extend(
        ["check_registered_enclosure", "replay_registered_enclosure"]
    )
    value["certificate_schemas"].append("registered-enclosure-check/1")
    value["capabilities"]["check_registered_enclosure"] = {
        "schema_version": "2.8",
        "request_schema": "check-registered-enclosure-request/1",
        "result_schema": "registered-enclosure-outcome/1",
        "certificate_schemas": ["registered-enclosure-check/1"],
        "replay_payload_schema": "checked-registered-enclosure/1",
        "verification_routes": ["kernel_proof", "fixed_checker_replay"],
        "outcomes": [
            "verified", "candidate_rejected", "inconclusive", "unsupported",
            "domain_obstruction",
        ],
        "relations": ["le", "lt", "ge", "gt"],
        "profile_required": True,
        "profile_loaded": True,
    }
    value["capabilities"]["replay_registered_enclosure"] = {
        "schema_version": "2.8",
        "request_schema": "replay-registered-enclosure-request/1",
        "result_schema": "registered-enclosure-outcome/1",
        "certificate_schemas": ["registered-enclosure-check/1"],
        "verification_routes": ["fixed_checker_replay"],
        "candidate_execution": False,
        "profile_required": True,
        "profile_loaded": True,
    }
    value["enclosure_profile"] = {
        "schema_version": "leancert-enclosure-profile/1",
        "name": "example-profile",
        "path": str(path),
        "modules": ["Example.Enclosures"],
        "allowed_functions": [FUNCTION],
        "leancert_revision": "abc123",
        "environment_digest": "sha256:test-environment",
        "registry": [
            {
                "function": FUNCTION,
                "candidate": "Example.Enclosures.candidate",
                "checker": "Example.Enclosures.check",
                "theorem": "Example.Enclosures.check_sound",
                "priority": 100,
            }
        ],
    }
    return value


def verified_response(request: dict) -> dict:
    profile = {
        "schema_version": "leancert-enclosure-profile/1",
        "name": "example-profile",
        "path": "profile.json",
        "modules": ["Example.Enclosures"],
        "allowed_functions": [FUNCTION],
        "leancert_revision": "abc123",
        "environment_digest": "sha256:test-environment",
        "registry": [
            {
                "function": FUNCTION,
                "candidate": "Example.Enclosures.candidate",
                "checker": "Example.Enclosures.check",
                "theorem": "Example.Enclosures.check_sound",
                "priority": 100,
            }
        ],
    }
    return {
        "status": "verified",
        "enclosure": {"lo": {"n": 1, "d": 1}, "hi": {"n": 2, "d": 1}},
        "registered_checks": 1,
        "composition_steps": 1,
        "certificate": {
            "schema": "registered-enclosure-check/1",
            "replay_payload_schema": "checked-registered-enclosure/1",
            "profile": profile,
            "precision": request["precision"],
            "taylor_depth": request["taylor_depth"],
            "configured_max_depth": request["max_depth"],
            "tree": {
                "kind": "leaf",
                "input": request["domain"],
                "output": {"lo": {"n": 1, "d": 1}, "hi": {"n": 2, "d": 1}},
                "entries": [],
                "composition_steps": 1,
            },
        },
    }


class FakeClient:
    def __init__(self, profile: EnclosureProfile, info: dict):
        self.bridge_info = info
        self.bridge_contract = BridgeHandshake.parse(info)
        assert self.bridge_contract.enclosure_profile is not None
        self.enclosures = EnclosureEnvironment(profile, self.bridge_contract.enclosure_profile)
        self.check_calls = []
        self.replay_calls = []

    def check_registered_enclosure(self, request):
        self.check_calls.append(deepcopy(request))
        return verified_response(request)

    def replay_registered_enclosure(self, claim, certificate):
        self.replay_calls.append((deepcopy(claim), deepcopy(certificate)))
        return {
            **verified_response(claim),
            "replayed": True,
            "certificate": certificate,
        }


def test_profile_issues_bound_function_handles_and_routes_prove(tmp_path):
    path = profile_file(tmp_path)
    profile = EnclosureProfile.load(path)
    client = FakeClient(profile, handshake(path))
    shifted = client.enclosures.function(FUNCTION)
    x = ast.var("x")

    result = lc.prove(shifted(x) < 3, where={x: (0, 1)}, client=client)

    assert isinstance(result, lc.VerifiedRegisteredEnclosure)
    assert isinstance(result, lc.Verified)
    assert client.check_calls[0]["relation"] == "lt"
    assert client.check_calls[0]["expression"] == {
        "kind": "registered",
        "function": FUNCTION,
        "argument": {"kind": "var", "idx": 0},
    }
    certificate = result.checks[0].replay_certificate
    assert isinstance(certificate, lc.ReplayableRegisteredEnclosureCertificate)
    assert certificate.payload_digest.startswith("sha256:")
    replay = result.replay(client)
    assert replay[0]["replayed"] is True
    assert isinstance(result.export_lean_project(tmp_path / "export"), lc.ExportUnsupported)


def test_handle_from_another_profile_is_rejected_before_bridge_call(tmp_path):
    path = profile_file(tmp_path)
    profile = EnclosureProfile.load(path)
    client = FakeClient(profile, handshake(path))
    other_path = profile_file(tmp_path / "other", digest="sha256:other")
    other_info = handshake(other_path)
    other_info["enclosure_profile"]["environment_digest"] = "sha256:other"
    other = FakeClient(EnclosureProfile.load(other_path), other_info)
    x = ast.var("x")

    result = lc.prove(
        other.enclosures.function(FUNCTION)(x) <= 2,
        where={x: (0, 1)},
        client=client,
    )

    assert isinstance(result, lc.Unsupported)
    assert "not a handle issued" in result.reason
    assert client.check_calls == []


def test_replay_detects_local_payload_corruption(tmp_path):
    path = profile_file(tmp_path)
    profile = EnclosureProfile.load(path)
    client = FakeClient(profile, handshake(path))
    x = ast.var("x")
    result = lc.prove(
        client.enclosures.function(FUNCTION)(x) <= 2,
        where={x: (0, 1)},
        client=client,
    )
    certificate = result.checks[0].replay_certificate
    assert isinstance(certificate, lc.ReplayableRegisteredEnclosureCertificate)
    corrupted = replace(certificate, payload_digest="sha256:corrupted")
    with pytest.raises(ProtocolViolation, match="digest mismatch"):
        corrupted.replay(client)
    assert client.replay_calls == []

    evidence_path = tmp_path / "evidence.json"
    certificate.save(str(evidence_path))
    loaded = lc.ReplayableRegisteredEnclosureCertificate.load(str(evidence_path))
    assert loaded.payload_digest == certificate.payload_digest
    assert loaded.replay(client)["replayed"] is True


def test_local_profile_must_match_bridge_handshake(tmp_path):
    path = profile_file(tmp_path)
    profile = EnclosureProfile.load(path)
    info = handshake(path)
    info["enclosure_profile"]["leancert_revision"] = "different"
    remote = BridgeHandshake.parse(info).enclosure_profile
    with pytest.raises(ProtocolViolation, match="differs"):
        profile.validate_handshake(remote)


def test_multiple_priority_ordered_rules_share_one_function_handle(tmp_path):
    path = profile_file(tmp_path)
    info = handshake(path)
    second = deepcopy(info["enclosure_profile"]["registry"][0])
    second.update(
        candidate="Example.Enclosures.fallbackCandidate",
        checker="Example.Enclosures.fallbackCheck",
        theorem="Example.Enclosures.fallbackSound",
        priority=50,
    )
    info["enclosure_profile"]["registry"].append(second)
    client = FakeClient(EnclosureProfile.load(path), info)
    handle = client.enclosures.function(FUNCTION)
    assert [rule.priority for rule in handle.rules] == [100, 50]
