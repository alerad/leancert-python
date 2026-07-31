"""Typed models for the versioned LeanCert bridge wire contract.

The bridge uses line-delimited JSON, not JSON-RPC 2.0. This module validates
the semantic content of handshakes and checked-operation responses without
owning subprocess transport or mathematical SDK result types.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
from types import MappingProxyType
from typing import Any

from .exceptions import ProtocolViolation

SUPPORTED_BRIDGE_API_MAJOR = 1
TYPED_CONTRACT_MINIMUM = (1, 1, 0)


def _object(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolViolation(f"{name} must be a JSON object")
    return value


def _string(value: Any, name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value:
        raise ProtocolViolation(f"{name} must be a non-empty string")
    return value


def _string_set(value: Any, name: str, *, required: bool) -> frozenset[str]:
    if value is None and not required:
        return frozenset()
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ProtocolViolation(f"{name} must be an array of non-empty strings")
    if len(value) != len(set(value)):
        raise ProtocolViolation(f"{name} must not contain duplicates")
    return frozenset(value)


@dataclass(frozen=True, order=True, slots=True)
class ProtocolVersion:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, value: Any, name: str = "bridge_api_version") -> ProtocolVersion:
        text = _string(value, name)
        assert text is not None
        pieces = text.split(".")
        if len(pieces) != 3 or any(not piece.isdigit() for piece in pieces):
            raise ProtocolViolation(f"{name} must use MAJOR.MINOR.PATCH semantic versioning")
        version = cls(*(int(piece) for piece in pieces))
        if str(version) != text:
            raise ProtocolViolation(f"{name} must use canonical decimal components")
        return version

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


class OutcomeStatus(str, Enum):
    VERIFIED = "verified"
    INCONCLUSIVE = "inconclusive"
    UNSUPPORTED = "unsupported"
    DOMAIN_OBSTRUCTION = "domain_obstruction"


@dataclass(frozen=True, slots=True)
class OperationCapability:
    operation: str
    schema_version: str
    outcomes: frozenset[OutcomeStatus]
    backends: frozenset[str]

    @classmethod
    def parse(cls, operation: str, value: Any) -> OperationCapability:
        obj = _object(value, f"capabilities.{operation}")
        schema = _string(obj.get("schema_version"), f"capabilities.{operation}.schema_version")
        raw_outcomes = _string_set(
            obj.get("outcomes"), f"capabilities.{operation}.outcomes", required=True
        )
        try:
            outcomes = frozenset(OutcomeStatus(item) for item in raw_outcomes)
        except ValueError as exc:
            raise ProtocolViolation(
                f"capabilities.{operation}.outcomes contains an unknown outcome"
            ) from exc
        backends = _string_set(
            obj.get("backends"), f"capabilities.{operation}.backends", required=True
        )
        if OutcomeStatus.VERIFIED not in outcomes or not backends:
            raise ProtocolViolation(
                f"capabilities.{operation} must advertise verified and at least one backend"
            )
        assert schema is not None
        return cls(operation, schema, outcomes, backends)


@dataclass(frozen=True, slots=True)
class BridgeHandshake:
    api_version: ProtocolVersion
    protocol_version: ProtocolVersion
    bridge_version: str
    lean_version: str
    leancert_version: str | None
    operations: frozenset[str]
    expression_nodes: frozenset[str]
    certificate_schemas: frozenset[str]
    verification_routes: frozenset[str]
    capabilities: tuple[OperationCapability, ...]
    raw: Mapping[str, Any]
    advertises_operations: bool

    @property
    def typed_contract(self) -> bool:
        return (
            self.api_version.major,
            self.api_version.minor,
            self.api_version.patch,
        ) >= TYPED_CONTRACT_MINIMUM

    def supports(self, operation: str) -> bool:
        return not self.advertises_operations or operation in self.operations

    def capability(self, operation: str) -> OperationCapability | None:
        return next((item for item in self.capabilities if item.operation == operation), None)

    @classmethod
    def parse(cls, value: Any) -> BridgeHandshake:
        obj = _object(value, "get_info result")
        api = ProtocolVersion.parse(obj.get("bridge_api_version"))
        if api.major != SUPPORTED_BRIDGE_API_MAJOR:
            raise ProtocolViolation(
                f"Unsupported bridge_api_version '{api}'; "
                f"this SDK supports major version {SUPPORTED_BRIDGE_API_MAJOR}"
            )
        typed = (api.major, api.minor, api.patch) >= TYPED_CONTRACT_MINIMUM
        protocol_value = obj.get("protocol_version", str(api))
        protocol = ProtocolVersion.parse(protocol_value, "protocol_version")
        if protocol != api:
            raise ProtocolViolation("protocol_version and bridge_api_version must agree")
        bridge_version = _string(obj.get("bridge_version"), "bridge_version")
        lean_version = _string(obj.get("lean_version"), "lean_version")
        leancert_version = _string(
            obj.get("leancert_version"), "leancert_version", optional=not typed
        )
        advertises_operations = "operations" in obj
        operations = _string_set(obj.get("operations"), "operations", required=typed)
        expression_nodes = _string_set(
            obj.get("expression_nodes"), "expression_nodes", required=typed
        )
        certificate_schemas = _string_set(
            obj.get("certificate_schemas"), "certificate_schemas", required=typed
        )
        verification_routes = _string_set(
            obj.get("verification_routes"), "verification_routes", required=typed
        )
        if typed and not {"ping", "get_info"}.issubset(operations):
            raise ProtocolViolation("typed bridges must advertise ping and get_info")
        if typed and (not expression_nodes or not certificate_schemas or not verification_routes):
            raise ProtocolViolation(
                "typed bridges must advertise expression nodes, certificate schemas, and routes"
            )
        raw_capabilities = obj.get("capabilities")
        if raw_capabilities is None and not typed:
            capability_items: tuple[OperationCapability, ...] = ()
        else:
            capability_obj = _object(raw_capabilities, "capabilities")
            capability_items = tuple(
                OperationCapability.parse(operation, capability_obj[operation])
                for operation in sorted(capability_obj)
            )
            unadvertised = {item.operation for item in capability_items} - operations
            if unadvertised:
                raise ProtocolViolation(
                    "capabilities describe unadvertised operations: "
                    + ", ".join(sorted(unadvertised))
                )
        assert bridge_version is not None and lean_version is not None
        return cls(
            api,
            protocol,
            bridge_version,
            lean_version,
            leancert_version,
            operations,
            expression_nodes,
            certificate_schemas,
            verification_routes,
            capability_items,
            MappingProxyType(dict(obj)),
            advertises_operations,
        )


@dataclass(frozen=True, slots=True)
class WireRational:
    numerator: int
    denominator: int

    @classmethod
    def parse(cls, value: Any, name: str) -> WireRational:
        obj = _object(value, name)
        if set(obj) != {"n", "d"}:
            raise ProtocolViolation(f"{name} must contain exactly n and d")
        numerator, denominator = obj["n"], obj["d"]
        if isinstance(numerator, bool) or not isinstance(numerator, int):
            raise ProtocolViolation(f"{name}.n must be an integer")
        if isinstance(denominator, bool) or not isinstance(denominator, int):
            raise ProtocolViolation(f"{name}.d must be an integer")
        if denominator <= 0:
            raise ProtocolViolation(f"{name}.d must be positive")
        reduced = Fraction(numerator, denominator)
        return cls(reduced.numerator, reduced.denominator)

    @property
    def fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)


@dataclass(frozen=True, slots=True)
class WireEnclosure:
    lower: WireRational
    upper: WireRational

    @classmethod
    def parse(cls, value: Any, name: str = "enclosure") -> WireEnclosure:
        obj = _object(value, name)
        if set(obj) != {"lo", "hi"}:
            raise ProtocolViolation(f"{name} must contain exactly lo and hi")
        result = cls(
            WireRational.parse(obj["lo"], f"{name}.lo"),
            WireRational.parse(obj["hi"], f"{name}.hi"),
        )
        if result.lower.fraction > result.upper.fraction:
            raise ProtocolViolation(f"{name} has inverted endpoints")
        return result


@dataclass(frozen=True, slots=True)
class CertificateDescriptor:
    schema_version: str
    checker: str
    verifier: str
    verification_route: str

    @classmethod
    def parse(cls, value: Any) -> CertificateDescriptor:
        obj = _object(value, "certificate")
        required = {"schema_version", "checker", "verifier", "verification_route"}
        if set(obj) != required:
            raise ProtocolViolation("certificate descriptor fields do not match its schema")
        schema_version = _string(obj["schema_version"], "certificate.schema_version")
        checker = _string(obj["checker"], "certificate.checker")
        verifier = _string(obj["verifier"], "certificate.verifier")
        route = _string(obj["verification_route"], "certificate.verification_route")
        assert schema_version is not None and checker is not None
        assert verifier is not None and route is not None
        return cls(
            schema_version=schema_version,
            checker=checker,
            verifier=verifier,
            verification_route=route,
        )


@dataclass(frozen=True, slots=True)
class BoundOperationOutcome:
    status: OutcomeStatus
    direction: str
    enclosure: WireEnclosure
    backend: str | None
    certificate: CertificateDescriptor | None
    raw: Mapping[str, Any]

    @classmethod
    def parse(
        cls,
        value: Any,
        *,
        typed_contract: bool,
        expected_direction: str | None = None,
    ) -> BoundOperationOutcome:
        obj = _object(value, "check_bound result")
        for field in ("verified", "computed_lo", "computed_hi"):
            if field not in obj:
                raise ProtocolViolation(f"check_bound result missing {field}")
        if not isinstance(obj["verified"], bool):
            raise ProtocolViolation("check_bound.verified must be boolean")
        computed = WireEnclosure(
            WireRational.parse(obj["computed_lo"], "computed_lo"),
            WireRational.parse(obj["computed_hi"], "computed_hi"),
        )
        if computed.lower.fraction > computed.upper.fraction:
            raise ProtocolViolation("computed enclosure has inverted endpoints")
        if typed_contract:
            required = {"status", "direction", "enclosure", "backend", "certificate"}
            missing = required - obj.keys()
            if missing:
                raise ProtocolViolation(
                    "typed check_bound result missing " + ", ".join(sorted(missing))
                )
            try:
                status = OutcomeStatus(obj["status"])
            except (TypeError, ValueError) as exc:
                raise ProtocolViolation("check_bound.status is unknown") from exc
            direction = _string(obj["direction"], "check_bound.direction")
            if direction not in {"lower", "upper"}:
                raise ProtocolViolation("check_bound.direction must be lower or upper")
            enclosure = WireEnclosure.parse(obj["enclosure"])
            if enclosure != computed:
                raise ProtocolViolation("legacy and typed check_bound enclosures disagree")
            backend = _string(obj["backend"], "check_bound.backend")
            certificate = (
                None
                if obj["certificate"] is None
                else CertificateDescriptor.parse(obj["certificate"])
            )
        else:
            status = OutcomeStatus.VERIFIED if obj["verified"] else OutcomeStatus.INCONCLUSIVE
            direction = expected_direction or "upper"
            enclosure = computed
            backend = None
            certificate = None
        if obj["verified"] != (status is OutcomeStatus.VERIFIED):
            raise ProtocolViolation("check_bound verified flag contradicts status")
        if (status is OutcomeStatus.VERIFIED) != (certificate is not None) and typed_contract:
            raise ProtocolViolation("only verified check_bound results may retain a certificate")
        if expected_direction is not None and direction != expected_direction:
            raise ProtocolViolation("check_bound direction contradicts the request")
        return cls(status, direction, enclosure, backend, certificate, MappingProxyType(dict(obj)))
