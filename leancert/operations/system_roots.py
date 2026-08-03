"""Checked nonlinear-system roots through rational Krawczyk certificates."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .. import ast
from ..domain import Interval as ResultInterval
from ..exceptions import ProtocolViolation
from ..protocol import OutcomeStatus
from ..result import (
    BridgeProvenance,
    CandidateRejected,
    KrawczykSearchEvidence,
    ProofResult,
    ReplayableKrawczykCertificate,
    UnsupportedSystemRoot,
    VerifiedSystemRoot,
)
from .bounds import _compile_expression, _rat, _rational, _UnsupportedBound, bridge_provenance


@dataclass(frozen=True, slots=True)
class SystemRootPlan:
    claim: ast.SystemRootClaim


def _empty_search() -> KrawczykSearchEvidence:
    return KrawczykSearchEvidence("automatic", 0, 0, Fraction(0), None)


def _common(
    plan: SystemRootPlan,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    provenance: BridgeProvenance,
    search: KrawczykSearchEvidence,
) -> dict[str, Any]:
    return {
        "equations": plan.claim.equations,
        "variables": plan.claim.variables,
        "domain": plan.claim.domain,
        "provenance": provenance,
        "search": search,
        "requested_uniqueness": plan.claim.uniqueness,
        "established_uniqueness": False,
        "original_claim": original_claim,
        "normalized_claim": normalized_claim,
        "claim_id": claim_id,
    }


def unsupported_system_root(
    claim: ast.SystemRootClaim,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    reason: str,
    provenance: BridgeProvenance | None = None,
) -> UnsupportedSystemRoot:
    plan = SystemRootPlan(claim)
    return UnsupportedSystemRoot(
        **_common(
            plan,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            provenance=provenance or BridgeProvenance(),
            search=_empty_search(),
        ),
        reason=reason,
    )


def execute_system_root_plan(
    plan: SystemRootPlan,
    *,
    original_claim: ast.Claim,
    normalized_claim: ast.Claim,
    claim_id: ast.ClaimDigest,
    client: Any,
    config: Any,
    taylor_depth: int,
) -> ProofResult:
    contract = client.bridge_contract
    provenance = bridge_provenance(client)
    capability = contract.capability("check_unique_system_root")
    if capability is None:
        return unsupported_system_root(
            plan.claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason="bridge does not advertise check_unique_system_root",
            provenance=provenance,
        )
    if (
        capability.request_schema != "check-unique-system-root-request/1"
        or capability.result_schema != "unique-system-root-outcome/1"
        or "krawczyk-check/1" not in capability.certificate_schemas
    ):
        return unsupported_system_root(
            plan.claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason="bridge Krawczyk schemas are not supported by this SDK",
            provenance=provenance,
        )

    indices = {
        variable.symbol.identifier: index for index, variable in enumerate(plan.claim.variables)
    }
    try:
        system_json = [
            _compile_expression(expression, indices, contract.expression_nodes)
            for expression in plan.claim.equations
        ]
        box_json = [
            {
                "lo": _rat(_rational(axis.interval.lower, "box lower endpoint")),
                "hi": _rat(_rational(axis.interval.upper, "box upper endpoint")),
            }
            for axis in plan.claim.domain.axes
        ]
    except _UnsupportedBound as exc:
        return unsupported_system_root(
            plan.claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason=str(exc),
            provenance=provenance,
        )
    if any(
        not axis.interval.lower_closed or not axis.interval.upper_closed
        for axis in plan.claim.domain.axes
    ):
        return unsupported_system_root(
            plan.claim,
            original_claim=original_claim,
            normalized_claim=normalized_claim,
            claim_id=claim_id,
            reason="checked system roots require a closed rational box",
            provenance=provenance,
        )

    if config.candidate is not None and len(config.candidate.center) != len(plan.claim.variables):
        raise ValueError("Krawczyk candidate dimension must match the system")

    response = client.check_unique_system_root(
        system_json,
        box_json,
        candidate=None if config.candidate is None else config.candidate.to_wire(),
        max_iterations=config.max_iterations,
        max_dimension=config.max_dimension,
        precision_bits=config.precision_bits,
        taylor_depth=taylor_depth,
    )
    outcome = contract.parse_system_root_outcome(response)
    search = KrawczykSearchEvidence(
        outcome.search.source,
        outcome.search.attempts,
        outcome.search.refinements,
        outcome.search.contraction_bound.fraction,
        outcome.search.failure,
    )
    common = _common(
        plan,
        original_claim=original_claim,
        normalized_claim=normalized_claim,
        claim_id=claim_id,
        provenance=provenance,
        search=search,
    )
    if outcome.status is OutcomeStatus.VERIFIED:
        descriptor = outcome.certificate
        if descriptor is None:
            raise ProtocolViolation("verified system root lacks a certificate")
        payload = descriptor.payload
        certificate = ReplayableKrawczykCertificate(
            schema_version=descriptor.schema_version,
            payload_schema="checked-unique-system-root/1",
            checker=descriptor.checker,
            verifier=descriptor.verifier,
            verification_route=descriptor.verification_route,
            payload_digest=payload.digest,
            system=payload.system,
            box=tuple(
                ResultInterval(item.lower.fraction, item.upper.fraction) for item in payload.box
            ),
            center=tuple(item.fraction for item in payload.center),
            preconditioner=tuple(
                tuple(item.fraction for item in row) for row in payload.preconditioner
            ),
            taylor_depth=payload.taylor_depth,
            canonical_payload=payload.canonical,
        )
        common["established_uniqueness"] = True
        return VerifiedSystemRoot(**common, certificate=certificate)
    if outcome.status is OutcomeStatus.UNSUPPORTED:
        return UnsupportedSystemRoot(
            **common,
            reason="The checked Krawczyk route does not support this system.",
        )
    failure = outcome.search.failure
    reason = "Krawczyk candidate was rejected"
    if failure is not None and isinstance(failure.get("kind"), str):
        reason += f": {failure['kind']}"
    return CandidateRejected(**common, reason=reason)


__all__ = ["SystemRootPlan", "execute_system_root_plan", "unsupported_system_root"]
