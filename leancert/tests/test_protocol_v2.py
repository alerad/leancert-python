"""Executable fixtures for Python's typed bridge-contract model."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from leancert.exceptions import ProtocolViolation
from leancert.protocol import (
    AdaptiveOperationOutcome,
    BoundOperationOutcome,
    BridgeHandshake,
    OutcomeStatus,
    ProtocolVersion,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str, contract: str = "bridge-contract-2.0") -> dict:
    return json.loads((FIXTURES / contract / name).read_text())


def typed_handshake() -> dict:
    return _fixture("handshake.json")


def verified_bound() -> dict:
    return _fixture("verified-bound.json")


def replay_handshake() -> dict:
    return _fixture("handshake.json", "bridge-contract-2.1")


def replay_bound() -> dict:
    return _fixture("verified-bound.json", "bridge-contract-2.1")


def adaptive_bound() -> dict:
    return {
        "verified": True,
        "status": "verified",
        "direction": "upper",
        "backend": "rational_checked_global_optimization",
        "enclosure": {"lo": {"n": 0, "d": 1}, "hi": {"n": 1, "d": 4}},
        "certificate": {
            "schema_version": "adaptive-bound-check/1",
            "checker": "LeanCert.Engine.Optimization.globalMaximizeRationalChecked",
            "verifier": (
                "LeanCert.Engine.Optimization.globalMaximizeRationalChecked_hi_correct"
            ),
            "verification_route": "compiled_checker",
            "payload": {
                "schema_version": "checked-global-opt-bound/1",
                "direction": "upper",
                "candidate_enclosure": {
                    "lo": {"n": 0, "d": 1}, "hi": {"n": 1, "d": 4}
                },
            },
        },
    }


def test_semantic_versions_are_canonical_and_major_checked():
    assert ProtocolVersion.parse("1.1.0") == ProtocolVersion(1, 1, 0)
    with pytest.raises(ProtocolViolation, match="semantic versioning"):
        ProtocolVersion.parse("1.1")
    with pytest.raises(ProtocolViolation, match="canonical"):
        ProtocolVersion.parse("01.1.0")
    handshake = typed_handshake()
    handshake["bridge_api_version"] = handshake["protocol_version"] = "3.0.0"
    with pytest.raises(ProtocolViolation, match="supports major"):
        BridgeHandshake.parse(handshake)


def test_typed_handshake_retains_capability_identity():
    handshake = BridgeHandshake.parse(typed_handshake())
    assert handshake.typed_contract
    assert handshake.protocol_name == "leancert-line-json"
    assert handshake.framing == "ndjson"
    assert handshake.build is not None and handshake.build.release_ready
    assert handshake.supports("check_bound")
    assert not handshake.supports("integrate")
    capability = handshake.capability("check_bound")
    assert capability is not None
    assert capability.outcomes == frozenset(
        {
            OutcomeStatus.VERIFIED,
            OutcomeStatus.INCONCLUSIVE,
            OutcomeStatus.UNSUPPORTED,
            OutcomeStatus.DOMAIN_OBSTRUCTION,
        }
    )
    assert capability.backends == frozenset({"rational_global_optimization"})
    assert capability.request_schema == "check-bound-request/1"
    assert capability.result_schema == "bound-outcome/1"
    assert handshake.capability_digest.startswith("sha256:")
    assert handshake.capability_digest == BridgeHandshake.parse(typed_handshake()).capability_digest


def test_contract_1_1_remains_supported_during_binary_rollout():
    handshake = BridgeHandshake.parse(_fixture("handshake.json", "bridge-contract-1.1"))
    assert handshake.api_version == ProtocolVersion(1, 1, 0)
    assert handshake.build is None


def test_legacy_handshake_remains_explicit_compatibility_mode():
    handshake = BridgeHandshake.parse(
        {
            "bridge_api_version": "1.0.0",
            "bridge_version": "bridge-v4.31.0",
            "lean_version": "4.31.0",
        }
    )
    assert not handshake.typed_contract
    assert handshake.supports("unknown_legacy_operation")


def test_handshake_rejects_capability_for_unadvertised_operation():
    handshake = typed_handshake()
    handshake["operations"].remove("check_bound")
    with pytest.raises(ProtocolViolation, match="unadvertised"):
        BridgeHandshake.parse(handshake)


def test_verified_bound_descriptor_is_typed():
    outcome = BoundOperationOutcome.parse(
        verified_bound(), typed_contract=True, expected_direction="upper"
    )
    assert outcome.status is OutcomeStatus.VERIFIED
    assert outcome.enclosure.upper.fraction == 1
    assert outcome.certificate is not None
    assert outcome.certificate.schema_version == "bound-check/1"


def test_contract_2_1_retains_resolved_dependencies_and_replay_payload():
    handshake = BridgeHandshake.parse(replay_handshake())
    assert handshake.dependencies is not None
    assert handshake.dependencies.lean_toolchain == "leanprover/lean4:v4.32.2"
    assert handshake.dependencies.leancert_resolved_revision == (
        "6f0c9ae5bcd5e40463d9771f06b33ef145c242f6"
    )
    outcome = handshake.parse_bound_outcome(replay_bound(), expected_direction="upper")
    assert outcome.certificate is not None and outcome.certificate.payload is not None
    assert outcome.certificate.payload.bound.fraction == 1
    assert outcome.certificate.payload.box[0].lower.fraction == 0
    assert outcome.certificate.payload.config.max_iterations == 1000
    assert outcome.certificate.payload.digest.startswith("sha256:")
    nested = replay_bound()
    nested["certificate"]["payload"]["expression"] = {
        "kind": "neg",
        "e": {"kind": "var", "idx": 0},
    }
    nested_outcome = handshake.parse_bound_outcome(nested, expected_direction="upper")
    assert nested_outcome.certificate is not None
    nested_payload = nested_outcome.certificate.payload
    assert nested_payload is not None
    with pytest.raises(TypeError):
        nested_payload.expression["e"]["idx"] = 1


def test_adaptive_outcome_requires_checked_optimizer_authority():
    outcome = AdaptiveOperationOutcome.parse(
        adaptive_bound(), expected_direction="upper"
    )
    assert outcome.status is OutcomeStatus.VERIFIED
    tampered = adaptive_bound()
    tampered["certificate"]["verifier"] = "Untrusted.claim"
    with pytest.raises(ProtocolViolation, match="authority"):
        AdaptiveOperationOutcome.parse(tampered, expected_direction="upper")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value["certificate"]["payload"].update(direction="lower"), "direction"),
        (
            lambda value: value["certificate"]["payload"]["bound"].update(n=2, d=2),
            "reduced",
        ),
        (
            lambda value: value["certificate"]["payload"]["config"].pop("taylor_depth"),
            "configuration",
        ),
    ],
)
def test_replay_payload_mutations_are_protocol_violations(mutation, message):
    handshake = BridgeHandshake.parse(replay_handshake())
    response = deepcopy(replay_bound())
    mutation(response)
    with pytest.raises(ProtocolViolation, match=message):
        handshake.parse_bound_outcome(response, expected_direction="upper")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(backend="unadvertised"), "backend was not advertised"),
        (
            lambda value: value["certificate"].update(verification_route="native"),
            "verification route was not advertised",
        ),
        (
            lambda value: value["certificate"].update(schema_version="bound-check/9"),
            "certificate schema was not advertised",
        ),
    ],
)
def test_bound_response_must_match_negotiated_capability(mutation, message):
    handshake = BridgeHandshake.parse(typed_handshake())
    response = deepcopy(verified_bound())
    mutation(response)
    with pytest.raises(ProtocolViolation, match=message):
        handshake.parse_bound_outcome(response, expected_direction="upper")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(status="inconclusive"), "contradicts status"),
        (lambda value: value.update(certificate=None), "retain a certificate"),
        (lambda value: value.update(direction="lower"), "contradicts the request"),
        (
            lambda value: value["enclosure"].update(hi={"n": 2, "d": 1}),
            "enclosures disagree",
        ),
        (lambda value: value["computed_hi"].update(d=0), "must be positive"),
    ],
)
def test_bound_response_contradictions_are_protocol_violations(mutation, message):
    response = deepcopy(verified_bound())
    mutation(response)
    with pytest.raises(ProtocolViolation, match=message):
        BoundOperationOutcome.parse(response, typed_contract=True, expected_direction="upper")
