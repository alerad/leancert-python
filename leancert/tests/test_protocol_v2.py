"""Executable fixtures for Python's typed bridge-contract model."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from leancert.exceptions import ProtocolViolation
from leancert.protocol import (
    BoundOperationOutcome,
    BridgeHandshake,
    OutcomeStatus,
    ProtocolVersion,
)

FIXTURES = Path(__file__).parent / "fixtures" / "bridge-contract-1.1"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def typed_handshake() -> dict:
    return _fixture("handshake.json")


def verified_bound() -> dict:
    return _fixture("verified-bound.json")


def test_semantic_versions_are_canonical_and_major_checked():
    assert ProtocolVersion.parse("1.1.0") == ProtocolVersion(1, 1, 0)
    with pytest.raises(ProtocolViolation, match="semantic versioning"):
        ProtocolVersion.parse("1.1")
    with pytest.raises(ProtocolViolation, match="canonical"):
        ProtocolVersion.parse("01.1.0")
    handshake = typed_handshake()
    handshake["bridge_api_version"] = handshake["protocol_version"] = "2.0.0"
    with pytest.raises(ProtocolViolation, match="supports major"):
        BridgeHandshake.parse(handshake)


def test_typed_handshake_retains_capability_identity():
    handshake = BridgeHandshake.parse(typed_handshake())
    assert handshake.typed_contract
    assert handshake.supports("check_bound")
    assert not handshake.supports("integrate")
    capability = handshake.capability("check_bound")
    assert capability is not None
    assert capability.outcomes == frozenset(OutcomeStatus)
    assert capability.backends == frozenset({"rational_global_optimization"})


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
