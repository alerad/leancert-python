"""Checked scalar-root claims through fixed LeanCert root checkers."""

from __future__ import annotations

from typing import Any, Literal

from .. import ast
from ..domain import Interval as ResultInterval
from ..protocol import OutcomeStatus
from ..result import (
    BridgeProvenance,
    ProofResult,
    ReplayableScalarRootCertificate,
    ScalarRootCandidateRejected,
    UnsupportedScalarRoot,
    VerifiedRootExclusion,
    VerifiedRootExistence,
    VerifiedUniqueRoot,
)
from .bounds import _compile_expression, _rat, _rational, _UnsupportedBound, bridge_provenance


def _claim_kind(claim: ast.RootExistsClaim) -> Literal["exists", "unique", "excluded"]:
    if isinstance(claim, ast.UniqueRootClaim):
        return "unique"
    if isinstance(claim, ast.RootExcludedClaim):
        return "excluded"
    return "exists"


def _common(
    claim: ast.RootExistsClaim,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    provenance: BridgeProvenance,
) -> dict[str, Any]:
    return {
        "expression": claim.expression,
        "variable": claim.variable,
        "domain": claim.domain,
        "requested_claim": _claim_kind(claim),
        "provenance": provenance,
        "original_claim": original_claim,
        "normalized_claim": normalized_claim,
        "claim_id": claim_id,
    }


def unsupported_scalar_root(
    claim: ast.RootExistsClaim,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    reason: str,
    provenance: BridgeProvenance | None = None,
) -> UnsupportedScalarRoot:
    return UnsupportedScalarRoot(
        **_common(
            claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            provenance=provenance or BridgeProvenance(),
        ),
        reason=reason,
    )


def execute_scalar_root_claim(
    claim: ast.RootExistsClaim,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    client: Any,
    taylor_depth: int,
) -> ProofResult:
    contract = client.bridge_contract
    provenance = bridge_provenance(client)
    capability = contract.capability("check_scalar_root")
    if capability is None:
        return unsupported_scalar_root(
            claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason="bridge does not advertise check_scalar_root",
            provenance=provenance,
        )
    if (
        capability.request_schema != "check-scalar-root-request/1"
        or capability.result_schema != "scalar-root-outcome/1"
        or "scalar-root-check/1" not in capability.certificate_schemas
    ):
        return unsupported_scalar_root(
            claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason="bridge scalar-root schemas are not supported by this SDK",
            provenance=provenance,
        )
    if not claim.domain.lower_closed or not claim.domain.upper_closed:
        return unsupported_scalar_root(
            claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason="checked scalar roots require a closed rational interval",
            provenance=provenance,
        )
    try:
        expression = _compile_expression(
            claim.expression,
            {claim.variable.symbol.identifier: 0},
            contract.expression_nodes,
        )
        lower = _rational(claim.domain.lower, "root interval lower endpoint")
        upper = _rational(claim.domain.upper, "root interval upper endpoint")
    except _UnsupportedBound as exc:
        return unsupported_scalar_root(
            claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason=str(exc),
            provenance=provenance,
        )
    interval = {"lo": _rat(lower), "hi": _rat(upper)}
    kind = _claim_kind(claim)
    response = client.check_scalar_root(expression, interval, kind, taylor_depth=taylor_depth)
    outcome = contract.parse_scalar_root_outcome(response, expected_claim=kind)
    common = _common(
        claim,
        original_claim=original_claim,
        normalized_claim=normalized_claim,
        claim_id=claim_id,
        provenance=provenance,
    )
    if outcome.status is OutcomeStatus.VERIFIED:
        assert outcome.certificate is not None
        descriptor = outcome.certificate
        payload = descriptor.payload
        replay = ReplayableScalarRootCertificate(
            descriptor.schema_version,
            "checked-scalar-root/1",
            descriptor.checker,
            descriptor.verifier,
            descriptor.verification_route,
            payload.digest,
            payload.expression,
            ResultInterval(payload.interval.lower.fraction, payload.interval.upper.fraction),
            kind,
            payload.taylor_depth,
            payload.canonical,
        )
        result_type = {
            "exists": VerifiedRootExistence,
            "unique": VerifiedUniqueRoot,
            "excluded": VerifiedRootExclusion,
        }[kind]
        return result_type(**common, certificate=replay)
    reason = (
        "the fixed scalar-root checker rejected the supplied interval"
        if outcome.status is OutcomeStatus.CANDIDATE_REJECTED
        else "the checked scalar-root fragment does not support this expression"
    )
    result_type = (
        ScalarRootCandidateRejected
        if outcome.status is OutcomeStatus.CANDIDATE_REJECTED
        else UnsupportedScalarRoot
    )
    return result_type(**common, reason=reason)


__all__ = ["execute_scalar_root_claim", "unsupported_scalar_root"]
