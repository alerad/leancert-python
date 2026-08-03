"""Typed models for the versioned LeanCert bridge wire contract.

The bridge uses line-delimited JSON, not JSON-RPC 2.0. This module validates
the semantic content of handshakes and checked-operation responses without
owning subprocess transport or mathematical SDK result types.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from fractions import Fraction
from types import MappingProxyType
from typing import Any

from .exceptions import ProtocolViolation

SUPPORTED_BRIDGE_API_MAJORS = frozenset({1, 2, 3})
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
    CANDIDATE_REJECTED = "candidate_rejected"


@dataclass(frozen=True, slots=True)
class OperationCapability:
    operation: str
    schema_version: str
    outcomes: frozenset[OutcomeStatus]
    backends: frozenset[str]
    request_schema: str | None = None
    result_schema: str | None = None
    certificate_schemas: frozenset[str] = frozenset()
    verification_routes: frozenset[str] = frozenset()
    details: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({}), compare=False, hash=False, repr=False
    )

    @classmethod
    def parse(cls, operation: str, value: Any) -> OperationCapability:
        obj = _object(value, f"capabilities.{operation}")
        schema = _string(obj.get("schema_version"), f"capabilities.{operation}.schema_version")
        is_replay_service = operation == "replay_registered_enclosure"
        is_registered_enclosure = operation in {
            "check_registered_enclosure",
            "replay_registered_enclosure",
        }
        raw_outcomes = _string_set(
            obj.get("outcomes"),
            f"capabilities.{operation}.outcomes",
            required=not is_replay_service,
        )
        try:
            outcomes = frozenset(OutcomeStatus(item) for item in raw_outcomes)
        except ValueError as exc:
            raise ProtocolViolation(
                f"capabilities.{operation}.outcomes contains an unknown outcome"
            ) from exc
        backends = _string_set(
            obj.get("backends"),
            f"capabilities.{operation}.backends",
            required=not is_registered_enclosure,
        )
        if not is_replay_service and OutcomeStatus.VERIFIED not in outcomes:
            raise ProtocolViolation(
                f"capabilities.{operation} must advertise the verified outcome"
            )
        if not is_registered_enclosure and not backends:
            raise ProtocolViolation(
                f"capabilities.{operation} must advertise verified and at least one backend"
            )
        assert schema is not None
        request_schema = _string(
            obj.get("request_schema"),
            f"capabilities.{operation}.request_schema",
            optional="request_schema" not in obj,
        )
        result_schema = _string(
            obj.get("result_schema"),
            f"capabilities.{operation}.result_schema",
            optional="result_schema" not in obj,
        )
        certificate_schemas = _string_set(
            obj.get("certificate_schemas"),
            f"capabilities.{operation}.certificate_schemas",
            required=False,
        )
        verification_routes = _string_set(
            obj.get("verification_routes"),
            f"capabilities.{operation}.verification_routes",
            required=False,
        )
        return cls(
            operation,
            schema,
            outcomes,
            backends,
            request_schema,
            result_schema,
            certificate_schemas,
            verification_routes,
            _freeze_json(obj),
        )


@dataclass(frozen=True, slots=True)
class RegisteredEnclosureRule:
    function: str
    candidate: str
    checker: str
    theorem: str
    priority: int

    @classmethod
    def parse(cls, value: Any, name: str) -> RegisteredEnclosureRule:
        obj = _object(value, name)
        required = {"function", "candidate", "checker", "theorem", "priority"}
        if set(obj) != required:
            raise ProtocolViolation(f"{name} fields do not match Contract 2.8")
        strings = tuple(
            _string(obj[field], f"{name}.{field}")
            for field in ("function", "candidate", "checker", "theorem")
        )
        priority = obj["priority"]
        if isinstance(priority, bool) or not isinstance(priority, int) or priority < 0:
            raise ProtocolViolation(f"{name}.priority must be a non-negative integer")
        assert all(strings)
        return cls(*strings, priority)


@dataclass(frozen=True, slots=True)
class EnclosureProfileIdentity:
    schema_version: str
    name: str
    modules: tuple[str, ...]
    allowed_functions: tuple[str, ...]
    leancert_revision: str
    environment_digest: str
    registry: tuple[RegisteredEnclosureRule, ...]
    path: str | None = None

    @classmethod
    def parse(cls, value: Any) -> EnclosureProfileIdentity:
        obj = _object(value, "enclosure_profile")
        required = {
            "schema_version", "name", "path", "modules", "allowed_functions",
            "leancert_revision", "environment_digest", "registry",
        }
        if set(obj) != required:
            raise ProtocolViolation("enclosure_profile fields do not match Contract 2.8")
        if obj["schema_version"] != "leancert-enclosure-profile/1":
            raise ProtocolViolation("unsupported enclosure profile schema")
        _string_set(obj["modules"], "enclosure_profile.modules", required=True)
        _string_set(
            obj["allowed_functions"],
            "enclosure_profile.allowed_functions",
            required=True,
        )
        # Preserve the Bridge's deterministic order rather than frozenset order.
        modules = tuple(obj["modules"])
        allowed = tuple(obj["allowed_functions"])
        raw_registry = obj["registry"]
        if not isinstance(raw_registry, list):
            raise ProtocolViolation("enclosure_profile.registry must be an array")
        registry = tuple(
            RegisteredEnclosureRule.parse(item, f"enclosure_profile.registry[{index}]")
            for index, item in enumerate(raw_registry)
        )
        functions = tuple(rule.function for rule in registry)
        if not set(allowed).issubset(functions) or not set(functions).issubset(allowed):
            raise ProtocolViolation("enclosure registry must resolve only allowlisted functions")
        path = _string(obj["path"], "enclosure_profile.path", optional=obj["path"] is None)
        name = _string(obj["name"], "enclosure_profile.name")
        revision = _string(obj["leancert_revision"], "enclosure_profile.leancert_revision")
        digest = _string(obj["environment_digest"], "enclosure_profile.environment_digest")
        assert name and revision and digest
        return cls(obj["schema_version"], name, modules, allowed, revision, digest, registry, path)


@dataclass(frozen=True, slots=True)
class BuildProvenance:
    source_revision: str
    source_digest: str
    environment_digest: str
    profile: str

    @classmethod
    def parse(cls, value: Any) -> BuildProvenance:
        obj = _object(value, "build")
        required = {"source_revision", "source_digest", "environment_digest", "profile"}
        if set(obj) != required:
            raise ProtocolViolation("build provenance fields do not match Contract 2.0")
        values = [_string(obj[field], f"build.{field}") for field in sorted(required)]
        assert all(item is not None for item in values)
        return cls(
            source_revision=obj["source_revision"],
            source_digest=obj["source_digest"],
            environment_digest=obj["environment_digest"],
            profile=obj["profile"],
        )

    @property
    def release_ready(self) -> bool:
        return (
            self.profile == "release"
            and self.source_revision != "development"
            and self.source_digest.startswith("sha256:")
            and self.environment_digest.startswith("sha256:")
        )


@dataclass(frozen=True, slots=True)
class ResolvedDependencies:
    """Exact toolchain and LeanCert source selected by the bridge build."""

    lean_toolchain: str
    leancert_source: str
    leancert_input_revision: str
    leancert_resolved_revision: str

    @classmethod
    def parse(cls, value: Any) -> ResolvedDependencies:
        obj = _object(value, "dependencies")
        if set(obj) != {"lean", "leancert"}:
            raise ProtocolViolation("dependency provenance fields do not match Contract 2.1")
        lean = _object(obj["lean"], "dependencies.lean")
        leancert = _object(obj["leancert"], "dependencies.leancert")
        if set(lean) != {"toolchain"} or set(leancert) != {
            "source",
            "input_revision",
            "resolved_revision",
        }:
            raise ProtocolViolation("resolved dependency fields do not match Contract 2.1")
        toolchain = _string(lean["toolchain"], "dependencies.lean.toolchain")
        source = _string(leancert["source"], "dependencies.leancert.source")
        input_revision = _string(leancert["input_revision"], "dependencies.leancert.input_revision")
        resolved_revision = _string(
            leancert["resolved_revision"], "dependencies.leancert.resolved_revision"
        )
        assert all((toolchain, source, input_revision, resolved_revision))
        return cls(toolchain, source, input_revision, resolved_revision)


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
    protocol_name: str | None = None
    framing: str | None = None
    build: BuildProvenance | None = None
    dependencies: ResolvedDependencies | None = None
    enclosure_profile: EnclosureProfileIdentity | None = None

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

    @property
    def capability_digest(self) -> str:
        """Stable identity for the negotiated semantic capability set."""
        payload = {
            "protocol_version": str(self.protocol_version),
            "enclosure_profile": (
                None
                if self.enclosure_profile is None
                else {
                    "schema_version": self.enclosure_profile.schema_version,
                    "name": self.enclosure_profile.name,
                    "modules": list(self.enclosure_profile.modules),
                    "allowed_functions": list(self.enclosure_profile.allowed_functions),
                    "leancert_revision": self.enclosure_profile.leancert_revision,
                    "environment_digest": self.enclosure_profile.environment_digest,
                    "registry": [
                        {
                            "function": rule.function,
                            "candidate": rule.candidate,
                            "checker": rule.checker,
                            "theorem": rule.theorem,
                            "priority": rule.priority,
                        }
                        for rule in self.enclosure_profile.registry
                    ],
                }
            ),
            "operations": sorted(self.operations),
            "expression_nodes": sorted(self.expression_nodes),
            "certificate_schemas": sorted(self.certificate_schemas),
            "verification_routes": sorted(self.verification_routes),
            "capabilities": [
                {
                    "operation": item.operation,
                    "schema_version": item.schema_version,
                    "request_schema": item.request_schema,
                    "result_schema": item.result_schema,
                    "outcomes": sorted(outcome.value for outcome in item.outcomes),
                    "backends": sorted(item.backends),
                    "certificate_schemas": sorted(item.certificate_schemas),
                    "verification_routes": sorted(item.verification_routes),
                }
                for item in self.capabilities
            ],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def parse_bound_outcome(self, value: Any, *, expected_direction: str) -> BoundOperationOutcome:
        outcome = BoundOperationOutcome.parse(
            value,
            typed_contract=self.typed_contract,
            expected_direction=expected_direction,
        )
        if not self.typed_contract:
            return outcome
        capability = self.capability("check_bound")
        if capability is None:
            raise ProtocolViolation("bridge returned a typed bound without check_bound capability")
        if outcome.status not in capability.outcomes:
            raise ProtocolViolation("bound status was not advertised by check_bound capability")
        if outcome.backend not in capability.backends:
            raise ProtocolViolation("bound backend was not advertised by check_bound capability")
        if outcome.certificate is not None:
            if (
                capability.certificate_schemas
                and outcome.certificate.schema_version not in capability.certificate_schemas
            ):
                raise ProtocolViolation("bound certificate schema was not advertised")
            if (
                capability.verification_routes
                and outcome.certificate.verification_route not in capability.verification_routes
            ):
                raise ProtocolViolation("bound verification route was not advertised")
            if outcome.certificate.schema_version not in self.certificate_schemas:
                raise ProtocolViolation("bound certificate schema is absent from the handshake")
            if outcome.certificate.verification_route not in self.verification_routes:
                raise ProtocolViolation("bound verification route is absent from the handshake")
        return outcome

    def parse_strict_bound_outcome(
        self, value: Any, *, expected_relation: str
    ) -> StrictBoundOperationOutcome:
        capability = self.capability("check_strict_bound")
        if capability is None:
            raise ProtocolViolation(
                "bridge returned a strict bound without check_strict_bound capability"
            )
        outcome = StrictBoundOperationOutcome.parse(value, expected_relation=expected_relation)
        if outcome.status not in capability.outcomes:
            raise ProtocolViolation("strict-bound status was not advertised")
        if outcome.backend not in capability.backends:
            raise ProtocolViolation("strict-bound backend was not advertised")
        if outcome.certificate is not None:
            if outcome.certificate.schema_version not in capability.certificate_schemas:
                raise ProtocolViolation("strict-bound certificate schema was not advertised")
            if outcome.certificate.verification_route not in capability.verification_routes:
                raise ProtocolViolation("strict-bound verification route was not advertised")
            if outcome.certificate.schema_version not in self.certificate_schemas:
                raise ProtocolViolation("strict-bound certificate schema is absent from handshake")
            if outcome.certificate.verification_route not in self.verification_routes:
                raise ProtocolViolation("strict-bound verification route is absent from handshake")
        return outcome

    def parse_adaptive_outcome(
        self, value: Any, *, expected_direction: str
    ) -> AdaptiveOperationOutcome:
        capability = self.capability("verify_adaptive")
        if capability is None:
            raise ProtocolViolation(
                "bridge returned an adaptive outcome without verify_adaptive capability"
            )
        outcome = AdaptiveOperationOutcome.parse(value, expected_direction=expected_direction)
        if outcome.status not in capability.outcomes:
            raise ProtocolViolation("adaptive status was not advertised")
        if outcome.backend not in capability.backends:
            raise ProtocolViolation("adaptive backend was not advertised")
        if outcome.certificate is not None:
            if "adaptive-bound-check/1" not in capability.certificate_schemas:
                raise ProtocolViolation("adaptive certificate schema was not advertised")
            if "compiled_checker" not in capability.verification_routes:
                raise ProtocolViolation("adaptive verification route was not advertised")
        return outcome

    def parse_system_root_outcome(self, value: Any) -> SystemRootOperationOutcome:
        capability = self.capability("check_unique_system_root")
        if capability is None:
            raise ProtocolViolation(
                "bridge returned a system-root outcome without check_unique_system_root capability"
            )
        outcome = SystemRootOperationOutcome.parse(value)
        if outcome.status not in capability.outcomes:
            raise ProtocolViolation("system-root status was not advertised")
        if outcome.backend not in capability.backends:
            raise ProtocolViolation("system-root backend was not advertised")
        if outcome.certificate is not None:
            if outcome.certificate.schema_version not in capability.certificate_schemas:
                raise ProtocolViolation("Krawczyk certificate schema was not advertised")
            if outcome.certificate.verification_route not in capability.verification_routes:
                raise ProtocolViolation("Krawczyk verification route was not advertised")
            if outcome.certificate.schema_version not in self.certificate_schemas:
                raise ProtocolViolation("Krawczyk certificate schema is absent from handshake")
        return outcome

    def parse_eventual_outcome(self, value: Any) -> EventualOperationOutcome:
        capability = self.capability("check_eventual_bound")
        if capability is None:
            raise ProtocolViolation(
                "bridge returned an eventual-bound outcome without check_eventual_bound capability"
            )
        outcome = EventualOperationOutcome.parse(value)
        if outcome.status not in capability.outcomes:
            raise ProtocolViolation("eventual-bound status was not advertised")
        if outcome.backend not in capability.backends:
            raise ProtocolViolation("eventual-bound backend was not advertised")
        if outcome.certificate is not None:
            if outcome.certificate.schema_version not in capability.certificate_schemas:
                raise ProtocolViolation("eventual-bound certificate schema was not advertised")
            if outcome.certificate.verification_route not in capability.verification_routes:
                raise ProtocolViolation("eventual-bound verification route was not advertised")
            if outcome.certificate.schema_version not in self.certificate_schemas:
                raise ProtocolViolation(
                    "eventual-bound certificate schema is absent from handshake"
                )
        return outcome

    def parse_scalar_root_outcome(
        self, value: Any, *, expected_claim: str
    ) -> ScalarRootOperationOutcome:
        capability = self.capability("check_scalar_root")
        if capability is None:
            raise ProtocolViolation(
                "bridge returned a scalar-root outcome without check_scalar_root capability"
            )
        outcome = ScalarRootOperationOutcome.parse(value, expected_claim=expected_claim)
        if outcome.status not in capability.outcomes:
            raise ProtocolViolation("scalar-root status was not advertised")
        if outcome.backend not in capability.backends:
            raise ProtocolViolation("scalar-root backend was not advertised")
        if outcome.certificate is not None:
            if outcome.certificate.schema_version not in capability.certificate_schemas:
                raise ProtocolViolation("scalar-root certificate schema was not advertised")
            if outcome.certificate.verification_route not in capability.verification_routes:
                raise ProtocolViolation("scalar-root verification route was not advertised")
            if outcome.certificate.schema_version not in self.certificate_schemas:
                raise ProtocolViolation("scalar-root certificate schema is absent from handshake")
        return outcome

    def parse_integral_outcome(
        self, value: Any, *, expected_relation: str
    ) -> IntegralOperationOutcome:
        capability = self.capability("check_integral")
        if capability is None:
            raise ProtocolViolation(
                "bridge returned an integral outcome without check_integral capability"
            )
        outcome = IntegralOperationOutcome.parse(value, expected_relation=expected_relation)
        if outcome.status not in capability.outcomes:
            raise ProtocolViolation("integral status was not advertised")
        if outcome.backend not in capability.backends:
            raise ProtocolViolation("integral backend was not advertised")
        if outcome.certificate is not None:
            if outcome.certificate.schema_version not in capability.certificate_schemas:
                raise ProtocolViolation("integral certificate schema was not advertised")
            if outcome.certificate.verification_route not in capability.verification_routes:
                raise ProtocolViolation("integral verification route was not advertised")
            if outcome.certificate.schema_version not in self.certificate_schemas:
                raise ProtocolViolation("integral certificate schema is absent from handshake")
        return outcome

    @classmethod
    def parse(cls, value: Any) -> BridgeHandshake:
        obj = _object(value, "get_info result")
        api = ProtocolVersion.parse(obj.get("bridge_api_version"))
        if api.major not in SUPPORTED_BRIDGE_API_MAJORS:
            raise ProtocolViolation(
                f"Unsupported bridge_api_version '{api}'; "
                "this SDK supports major versions "
                + ", ".join(str(item) for item in sorted(SUPPORTED_BRIDGE_API_MAJORS))
            )
        typed = (api.major, api.minor, api.patch) >= TYPED_CONTRACT_MINIMUM
        protocol_value = obj.get("protocol_version", str(api))
        protocol = ProtocolVersion.parse(protocol_value, "protocol_version")
        if protocol != api:
            raise ProtocolViolation("protocol_version and bridge_api_version must agree")
        protocol_name = _string(obj.get("protocol_name"), "protocol_name", optional=api.major < 2)
        framing = _string(obj.get("framing"), "framing", optional=api.major < 2)
        if api.major >= 2 and (protocol_name != "leancert-line-json" or framing != "ndjson"):
            raise ProtocolViolation("Contract 2.0 requires leancert-line-json over ndjson")
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
        # Contract 2.x originally embedded supply-chain provenance in the
        # Bridge handshake. Managed execution environments now own that
        # identity, while older Bridge releases remain valid inputs.
        build = BuildProvenance.parse(obj["build"]) if "build" in obj else None
        dependencies = (
            ResolvedDependencies.parse(obj["dependencies"])
            if "dependencies" in obj
            else None
        )
        enclosure_profile = (
            None
            if obj.get("enclosure_profile") is None
            else EnclosureProfileIdentity.parse(obj.get("enclosure_profile"))
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
            if api.major >= 2:
                incomplete = [
                    item.operation
                    for item in capability_items
                    if not item.request_schema
                    or not item.result_schema
                    or not item.certificate_schemas
                    or not item.verification_routes
                ]
                if incomplete:
                    raise ProtocolViolation(
                        "Contract 2.0 checked capabilities lack schema or route identity: "
                        + ", ".join(incomplete)
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
            protocol_name,
            framing,
            build,
            dependencies,
            enclosure_profile,
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


def _canonical_wire_rational(value: Any, name: str) -> WireRational:
    parsed = WireRational.parse(value, name)
    obj = _object(value, name)
    if obj["n"] != parsed.numerator or obj["d"] != parsed.denominator:
        raise ProtocolViolation(f"{name} must be reduced with a positive denominator")
    return parsed


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_json(item) for item in value]
    return value


def _canonical_core_expression(value: Any, name: str = "certificate.payload.expression") -> Any:
    obj = _object(value, name)
    kind = _string(obj.get("kind"), f"{name}.kind")
    if kind == "const":
        if set(obj) != {"kind", "val"}:
            raise ProtocolViolation(f"{name} constant fields are not canonical")
        rat = _canonical_wire_rational(obj["val"], f"{name}.val")
        return {"kind": "const", "val": {"n": rat.numerator, "d": rat.denominator}}
    if kind == "var":
        if set(obj) != {"kind", "idx"}:
            raise ProtocolViolation(f"{name} variable fields are not canonical")
        index = obj["idx"]
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ProtocolViolation(f"{name}.idx must be a natural number")
        return {"kind": "var", "idx": index}
    if kind in {"add", "mul"}:
        if set(obj) != {"kind", "e1", "e2"}:
            raise ProtocolViolation(f"{name} binary fields are not canonical")
        return {
            "kind": kind,
            "e1": _canonical_core_expression(obj["e1"], f"{name}.e1"),
            "e2": _canonical_core_expression(obj["e2"], f"{name}.e2"),
        }
    if kind in {
        "neg",
        "inv",
        "exp",
        "sin",
        "cos",
        "log",
        "atan",
        "arsinh",
        "atanh",
        "sinc",
        "erf",
        "sinh",
        "cosh",
        "tanh",
        "sqrt",
    }:
        if set(obj) != {"kind", "e"}:
            raise ProtocolViolation(f"{name} unary fields are not canonical")
        return {"kind": kind, "e": _canonical_core_expression(obj["e"], f"{name}.e")}
    if kind == "named_const":
        if set(obj) != {"kind", "name"} or obj["name"] not in {
            "pi",
            "euler_mascheroni",
        }:
            raise ProtocolViolation(f"{name} named constant is not canonical")
        return {"kind": kind, "name": obj["name"]}
    raise ProtocolViolation(f"{name} contains unknown core expression kind {kind!r}")


@dataclass(frozen=True, slots=True)
class ReplayBoundConfig:
    max_iterations: int
    tolerance: WireRational
    use_monotonicity: bool
    taylor_depth: int


@dataclass(frozen=True, slots=True)
class ReplayBoundPayload:
    expression: Mapping[str, Any]
    box: tuple[WireEnclosure, ...]
    bound: WireRational
    direction: str
    config: ReplayBoundConfig
    canonical: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> ReplayBoundPayload:
        obj = _object(value, "certificate.payload")
        required = {"schema_version", "expression", "box", "bound", "direction", "config"}
        if set(obj) != required or obj.get("schema_version") != "global-opt-bound-replay/1":
            raise ProtocolViolation("replay payload fields do not match global-opt-bound-replay/1")
        expression = _canonical_core_expression(obj["expression"])
        if not isinstance(obj["box"], list):
            raise ProtocolViolation("certificate.payload.box must be an array")
        box_items: list[WireEnclosure] = []
        for index, entry in enumerate(obj["box"]):
            item = _object(entry, f"certificate.payload.box[{index}]")
            if set(item) != {"lo", "hi"}:
                raise ProtocolViolation("certificate replay interval fields are not canonical")
            box_items.append(
                WireEnclosure(
                    _canonical_wire_rational(item["lo"], f"certificate.payload.box[{index}].lo"),
                    _canonical_wire_rational(item["hi"], f"certificate.payload.box[{index}].hi"),
                )
            )
        box = tuple(box_items)
        if any(item.lower.fraction > item.upper.fraction for item in box):
            raise ProtocolViolation("certificate replay box has inverted endpoints")
        bound = _canonical_wire_rational(obj["bound"], "certificate.payload.bound")
        direction = _string(obj["direction"], "certificate.payload.direction")
        if direction not in {"lower", "upper"}:
            raise ProtocolViolation("certificate.payload.direction must be lower or upper")
        config_obj = _object(obj["config"], "certificate.payload.config")
        if set(config_obj) != {"max_iterations", "tolerance", "use_monotonicity", "taylor_depth"}:
            raise ProtocolViolation("replay configuration fields are not canonical")
        maximum, depth = config_obj["max_iterations"], config_obj["taylor_depth"]
        monotonicity = config_obj["use_monotonicity"]
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in (maximum, depth)
        ):
            raise ProtocolViolation("replay iteration and Taylor limits must be natural numbers")
        if not isinstance(monotonicity, bool):
            raise ProtocolViolation("replay use_monotonicity must be boolean")
        tolerance = _canonical_wire_rational(
            config_obj["tolerance"], "certificate.payload.config.tolerance"
        )
        config = ReplayBoundConfig(maximum, tolerance, monotonicity, depth)
        canonical_box = [
            {
                "lo": {"n": item.lower.numerator, "d": item.lower.denominator},
                "hi": {"n": item.upper.numerator, "d": item.upper.denominator},
            }
            for item in box
        ]
        canonical = {
            "schema_version": "global-opt-bound-replay/1",
            "expression": expression,
            "box": canonical_box,
            "bound": {"n": bound.numerator, "d": bound.denominator},
            "direction": direction,
            "config": {
                "max_iterations": maximum,
                "tolerance": {"n": tolerance.numerator, "d": tolerance.denominator},
                "use_monotonicity": monotonicity,
                "taylor_depth": depth,
            },
        }
        frozen = _freeze_json(canonical)
        return cls(frozen["expression"], box, bound, direction, config, frozen)

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            _plain_json(self.canonical), sort_keys=True, separators=(",", ":")
        ).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ReplayStrictBoundPayload:
    expression: Mapping[str, Any]
    box: tuple[WireEnclosure, ...]
    relation: str
    target_bound: WireRational
    certified_bound: WireRational
    config: ReplayBoundConfig
    canonical: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> ReplayStrictBoundPayload:
        obj = _object(value, "certificate.payload")
        required = {
            "schema_version",
            "expression",
            "box",
            "relation",
            "target_bound",
            "certified_bound",
            "config",
        }
        if set(obj) != required or obj.get("schema_version") != "checked-strict-bound/1":
            raise ProtocolViolation("replay payload fields do not match checked-strict-bound/1")
        expression = _canonical_core_expression(obj["expression"])
        if not isinstance(obj["box"], list):
            raise ProtocolViolation("certificate.payload.box must be an array")
        box_items: list[WireEnclosure] = []
        for index, entry in enumerate(obj["box"]):
            item = _object(entry, f"certificate.payload.box[{index}]")
            if set(item) != {"lo", "hi"}:
                raise ProtocolViolation("certificate replay interval fields are not canonical")
            box_items.append(
                WireEnclosure(
                    _canonical_wire_rational(item["lo"], f"certificate.payload.box[{index}].lo"),
                    _canonical_wire_rational(item["hi"], f"certificate.payload.box[{index}].hi"),
                )
            )
        box = tuple(box_items)
        if any(item.lower.fraction > item.upper.fraction for item in box):
            raise ProtocolViolation("certificate replay box has inverted endpoints")
        relation = _string(obj["relation"], "certificate.payload.relation")
        if relation not in {"lt", "gt"}:
            raise ProtocolViolation("certificate.payload.relation must be lt or gt")
        target = _canonical_wire_rational(obj["target_bound"], "certificate.payload.target_bound")
        certified = _canonical_wire_rational(
            obj["certified_bound"], "certificate.payload.certified_bound"
        )
        if relation == "lt" and not certified.fraction < target.fraction:
            raise ProtocolViolation("strict upper certificate has no exact interior margin")
        if relation == "gt" and not target.fraction < certified.fraction:
            raise ProtocolViolation("strict lower certificate has no exact interior margin")
        config_obj = _object(obj["config"], "certificate.payload.config")
        if set(config_obj) != {"max_iterations", "tolerance", "use_monotonicity", "taylor_depth"}:
            raise ProtocolViolation("replay configuration fields are not canonical")
        maximum, depth = config_obj["max_iterations"], config_obj["taylor_depth"]
        monotonicity = config_obj["use_monotonicity"]
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in (maximum, depth)
        ):
            raise ProtocolViolation("replay iteration and Taylor limits must be natural numbers")
        if not isinstance(monotonicity, bool):
            raise ProtocolViolation("replay use_monotonicity must be boolean")
        tolerance = _canonical_wire_rational(
            config_obj["tolerance"], "certificate.payload.config.tolerance"
        )
        config = ReplayBoundConfig(maximum, tolerance, monotonicity, depth)
        canonical = {
            "schema_version": "checked-strict-bound/1",
            "expression": expression,
            "box": [
                {
                    "lo": {"n": item.lower.numerator, "d": item.lower.denominator},
                    "hi": {"n": item.upper.numerator, "d": item.upper.denominator},
                }
                for item in box
            ],
            "relation": relation,
            "target_bound": {"n": target.numerator, "d": target.denominator},
            "certified_bound": {"n": certified.numerator, "d": certified.denominator},
            "config": {
                "max_iterations": maximum,
                "tolerance": {"n": tolerance.numerator, "d": tolerance.denominator},
                "use_monotonicity": monotonicity,
                "taylor_depth": depth,
            },
        }
        frozen = _freeze_json(canonical)
        return cls(frozen["expression"], box, relation, target, certified, config, frozen)

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            _plain_json(self.canonical), sort_keys=True, separators=(",", ":")
        ).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CertificateDescriptor:
    schema_version: str
    checker: str
    verifier: str
    verification_route: str
    payload: ReplayBoundPayload | ReplayStrictBoundPayload | None = None

    @classmethod
    def parse(cls, value: Any) -> CertificateDescriptor:
        obj = _object(value, "certificate")
        schema_version = _string(obj.get("schema_version"), "certificate.schema_version")
        required = {"schema_version", "checker", "verifier", "verification_route"}
        if schema_version in {"bound-check/2", "strict-bound-check/1"}:
            required.add("payload")
        if set(obj) != required:
            raise ProtocolViolation("certificate descriptor fields do not match its schema")
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
            payload=(
                ReplayStrictBoundPayload.parse(obj["payload"])
                if schema_version == "strict-bound-check/1"
                else ReplayBoundPayload.parse(obj["payload"])
                if "payload" in obj
                else None
            ),
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
        if (
            certificate is not None
            and certificate.payload is not None
            and certificate.payload.direction != direction
        ):
            raise ProtocolViolation("replay payload direction contradicts bound outcome")
        return cls(status, direction, enclosure, backend, certificate, MappingProxyType(dict(obj)))


@dataclass(frozen=True, slots=True)
class StrictBoundOperationOutcome:
    status: OutcomeStatus
    relation: str
    target_bound: WireRational
    certified_bound: WireRational
    enclosure: WireEnclosure
    backend: str
    certificate: CertificateDescriptor | None
    raw: Mapping[str, Any]

    @classmethod
    def parse(
        cls, value: Any, *, expected_relation: str | None = None
    ) -> StrictBoundOperationOutcome:
        obj = _object(value, "check_strict_bound result")
        required = {
            "verified",
            "status",
            "relation",
            "target_bound",
            "certified_bound",
            "enclosure",
            "backend",
            "certificate",
        }
        if set(obj) != required:
            raise ProtocolViolation("strict-bound outcome fields are not canonical")
        if not isinstance(obj["verified"], bool):
            raise ProtocolViolation("check_strict_bound.verified must be boolean")
        try:
            status = OutcomeStatus(obj["status"])
        except (TypeError, ValueError) as exc:
            raise ProtocolViolation("check_strict_bound.status is unknown") from exc
        relation = _string(obj["relation"], "check_strict_bound.relation")
        if relation not in {"lt", "gt"}:
            raise ProtocolViolation("check_strict_bound.relation must be lt or gt")
        if expected_relation is not None and relation != expected_relation:
            raise ProtocolViolation("check_strict_bound relation contradicts the request")
        target = _canonical_wire_rational(obj["target_bound"], "target_bound")
        certified = _canonical_wire_rational(obj["certified_bound"], "certified_bound")
        enclosure = WireEnclosure.parse(obj["enclosure"])
        if enclosure.lower.fraction > enclosure.upper.fraction:
            raise ProtocolViolation("strict-bound enclosure has inverted endpoints")
        if relation == "lt" and certified != enclosure.upper:
            raise ProtocolViolation("strict upper certified bound must equal enclosure upper")
        if relation == "gt" and certified != enclosure.lower:
            raise ProtocolViolation("strict lower certified bound must equal enclosure lower")
        backend = _string(obj["backend"], "check_strict_bound.backend")
        assert backend is not None
        certificate = (
            None if obj["certificate"] is None else CertificateDescriptor.parse(obj["certificate"])
        )
        if obj["verified"] != (status is OutcomeStatus.VERIFIED):
            raise ProtocolViolation("strict-bound verified flag contradicts status")
        if (status is OutcomeStatus.VERIFIED) != (certificate is not None):
            raise ProtocolViolation("only verified strict bounds may retain a certificate")
        if certificate is not None:
            if certificate.schema_version != "strict-bound-check/1":
                raise ProtocolViolation("strict-bound certificate has the wrong schema")
            payload = certificate.payload
            if not isinstance(payload, ReplayStrictBoundPayload):
                raise ProtocolViolation("strict-bound certificate lacks a replay payload")
            if (
                payload.relation != relation
                or payload.target_bound != target
                or payload.certified_bound != certified
            ):
                raise ProtocolViolation("strict-bound certificate contradicts its outcome")
            expected_checker = (
                "LeanCert.Validity.GlobalOpt.checkGlobalUpperBound"
                if relation == "lt"
                else "LeanCert.Validity.GlobalOpt.checkGlobalLowerBound"
            )
            expected_verifier = (
                "LeanCert.Validity.GlobalOpt.verify_global_upper_bound"
                if relation == "lt"
                else "LeanCert.Validity.GlobalOpt.verify_global_lower_bound"
            )
            if certificate.checker != expected_checker or certificate.verifier != expected_verifier:
                raise ProtocolViolation("strict-bound certificate authority is inconsistent")
        return cls(
            status,
            relation,
            target,
            certified,
            enclosure,
            backend,
            certificate,
            MappingProxyType(dict(obj)),
        )


@dataclass(frozen=True, slots=True)
class AdaptiveOperationOutcome:
    """Checked adaptive-optimizer outcome introduced by Bridge Contract 2.2."""

    status: OutcomeStatus
    direction: str
    backend: str
    enclosure: WireEnclosure | None
    certificate: Mapping[str, Any] | None
    raw: Mapping[str, Any]

    @classmethod
    def parse(
        cls,
        value: Any,
        *,
        expected_direction: str,
    ) -> AdaptiveOperationOutcome:
        obj = _object(value, "verify_adaptive result")
        required = {"verified", "status", "direction", "backend", "certificate"}
        missing = required - obj.keys()
        if missing:
            raise ProtocolViolation(
                "typed verify_adaptive result missing " + ", ".join(sorted(missing))
            )
        if not isinstance(obj["verified"], bool):
            raise ProtocolViolation("verify_adaptive.verified must be boolean")
        try:
            status = OutcomeStatus(obj["status"])
        except (TypeError, ValueError) as exc:
            raise ProtocolViolation("verify_adaptive.status is unknown") from exc
        direction = _string(obj["direction"], "verify_adaptive.direction")
        backend = _string(obj["backend"], "verify_adaptive.backend")
        assert direction is not None and backend is not None
        if direction != expected_direction:
            raise ProtocolViolation("verify_adaptive direction contradicts the request")
        if obj["verified"] != (status is OutcomeStatus.VERIFIED):
            raise ProtocolViolation("verify_adaptive verified flag contradicts status")
        enclosure = (
            WireEnclosure.parse(obj["enclosure"], "verify_adaptive.enclosure")
            if "enclosure" in obj
            else None
        )
        certificate = obj["certificate"]
        if status is OutcomeStatus.VERIFIED:
            cert = _object(certificate, "verify_adaptive.certificate")
            if set(cert) != {
                "schema_version",
                "checker",
                "verifier",
                "verification_route",
                "payload",
            }:
                raise ProtocolViolation("adaptive certificate fields are not canonical")
            if cert["schema_version"] != "adaptive-bound-check/1":
                raise ProtocolViolation("adaptive certificate schema is unsupported")
            if cert["verification_route"] != "compiled_checker":
                raise ProtocolViolation("adaptive certificate route is unsupported")
            expected_checker = (
                "LeanCert.Engine.Optimization.globalMaximizeRationalChecked"
                if direction == "upper"
                else "LeanCert.Engine.Optimization.globalMinimizeRationalChecked"
            )
            expected_verifier = (
                "LeanCert.Engine.Optimization.globalMaximizeRationalChecked_hi_correct"
                if direction == "upper"
                else "LeanCert.Engine.Optimization.globalMinimizeRationalChecked_lo_correct"
            )
            if cert["checker"] != expected_checker or cert["verifier"] != expected_verifier:
                raise ProtocolViolation("adaptive certificate authority is not recognized")
            payload = _object(cert["payload"], "verify_adaptive.certificate.payload")
            if payload.get("schema_version") != "checked-global-opt-bound/1":
                raise ProtocolViolation("adaptive certificate payload schema is unsupported")
            if payload.get("direction") != direction:
                raise ProtocolViolation("adaptive certificate direction contradicts outcome")
            if (
                enclosure is None
                or WireEnclosure.parse(
                    payload.get("candidate_enclosure"),
                    "verify_adaptive.certificate.payload.candidate_enclosure",
                )
                != enclosure
            ):
                raise ProtocolViolation("adaptive certificate enclosure contradicts outcome")
        elif certificate is not None:
            raise ProtocolViolation("only verified adaptive outcomes may retain a certificate")
        return cls(
            status,
            direction,
            backend,
            enclosure,
            None if certificate is None else _freeze_json(certificate),
            MappingProxyType(dict(obj)),
        )


@dataclass(frozen=True, slots=True)
class ReplayKrawczykPayload:
    system: tuple[Mapping[str, Any], ...]
    box: tuple[WireEnclosure, ...]
    center: tuple[WireRational, ...]
    preconditioner: tuple[tuple[WireRational, ...], ...]
    taylor_depth: int
    canonical: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> ReplayKrawczykPayload:
        obj = _object(value, "Krawczyk certificate payload")
        if (
            set(obj) != {"schema_version", "system", "box", "center", "preconditioner", "config"}
            or obj.get("schema_version") != "checked-unique-system-root/1"
        ):
            raise ProtocolViolation(
                "Krawczyk payload fields do not match checked-unique-system-root/1"
            )
        if not isinstance(obj["system"], list) or not obj["system"]:
            raise ProtocolViolation("Krawczyk payload system must be a non-empty array")
        system = tuple(
            _freeze_json(_canonical_core_expression(expression, f"system[{index}]"))
            for index, expression in enumerate(obj["system"])
        )
        dimension = len(system)
        if not isinstance(obj["box"], list) or len(obj["box"]) != dimension:
            raise ProtocolViolation("Krawczyk payload box dimension must match the system")
        box = tuple(
            WireEnclosure.parse(interval, f"box[{index}]")
            for index, interval in enumerate(obj["box"])
        )
        if not isinstance(obj["center"], list) or len(obj["center"]) != dimension:
            raise ProtocolViolation("Krawczyk payload center dimension must match the system")
        center = tuple(
            _canonical_wire_rational(value, f"center[{index}]")
            for index, value in enumerate(obj["center"])
        )
        if not isinstance(obj["preconditioner"], list) or len(obj["preconditioner"]) != dimension:
            raise ProtocolViolation("Krawczyk preconditioner must be square")
        matrix: list[tuple[WireRational, ...]] = []
        for row_index, row in enumerate(obj["preconditioner"]):
            if not isinstance(row, list) or len(row) != dimension:
                raise ProtocolViolation("Krawczyk preconditioner must be square")
            matrix.append(
                tuple(
                    _canonical_wire_rational(value, f"preconditioner[{row_index}][{column}]")
                    for column, value in enumerate(row)
                )
            )
        config = _object(obj["config"], "Krawczyk payload config")
        if set(config) != {"taylor_depth"}:
            raise ProtocolViolation("Krawczyk payload config fields are not canonical")
        depth = config["taylor_depth"]
        if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
            raise ProtocolViolation("Krawczyk Taylor depth must be a natural number")
        canonical = {
            "schema_version": "checked-unique-system-root/1",
            "system": [_plain_json(item) for item in system],
            "box": obj["box"],
            "center": obj["center"],
            "preconditioner": obj["preconditioner"],
            "config": {"taylor_depth": depth},
        }
        return cls(system, box, center, tuple(matrix), depth, _freeze_json(canonical))

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            _plain_json(self.canonical), sort_keys=True, separators=(",", ":")
        ).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class KrawczykCertificateDescriptor:
    schema_version: str
    checker: str
    verifier: str
    verification_route: str
    payload: ReplayKrawczykPayload

    @classmethod
    def parse(cls, value: Any) -> KrawczykCertificateDescriptor:
        obj = _object(value, "Krawczyk certificate")
        if set(obj) != {"schema_version", "checker", "verifier", "verification_route", "payload"}:
            raise ProtocolViolation("Krawczyk certificate fields are not canonical")
        if obj["schema_version"] != "krawczyk-check/1":
            raise ProtocolViolation("Krawczyk certificate schema is unsupported")
        if obj["checker"] != "LeanCert.Engine.krawczykCheck":
            raise ProtocolViolation("Krawczyk checker authority is not recognized")
        if obj["verifier"] != "LeanCert.Validity.verify_unique_system_root":
            raise ProtocolViolation("Krawczyk verifier authority is not recognized")
        if obj["verification_route"] != "compiled_checker":
            raise ProtocolViolation("Krawczyk verification route is unsupported")
        return cls(
            obj["schema_version"],
            obj["checker"],
            obj["verifier"],
            obj["verification_route"],
            ReplayKrawczykPayload.parse(obj["payload"]),
        )


@dataclass(frozen=True, slots=True)
class SystemRootSearchOutcome:
    source: str
    attempts: int
    refinements: int
    contraction_bound: WireRational
    failure: Mapping[str, Any] | None


@dataclass(frozen=True, slots=True)
class SystemRootOperationOutcome:
    status: OutcomeStatus
    backend: str
    root_box: tuple[WireEnclosure, ...]
    search: SystemRootSearchOutcome
    certificate: KrawczykCertificateDescriptor | None
    raw: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> SystemRootOperationOutcome:
        obj = _object(value, "check_unique_system_root result")
        required = {"verified", "status", "backend", "root_box", "search", "certificate"}
        if set(obj) != required:
            raise ProtocolViolation("system-root outcome fields are not canonical")
        if not isinstance(obj["verified"], bool):
            raise ProtocolViolation("system-root verified flag must be boolean")
        try:
            status = OutcomeStatus(obj["status"])
        except (TypeError, ValueError) as exc:
            raise ProtocolViolation("system-root status is unknown") from exc
        if status not in {
            OutcomeStatus.VERIFIED,
            OutcomeStatus.CANDIDATE_REJECTED,
            OutcomeStatus.UNSUPPORTED,
        }:
            raise ProtocolViolation("system-root status is invalid for this operation")
        if obj["verified"] != (status is OutcomeStatus.VERIFIED):
            raise ProtocolViolation("system-root verified flag contradicts status")
        backend = _string(obj["backend"], "system-root backend")
        if not isinstance(obj["root_box"], list) or not obj["root_box"]:
            raise ProtocolViolation("system-root box must be a non-empty array")
        root_box = tuple(
            WireEnclosure.parse(item, f"root_box[{index}]")
            for index, item in enumerate(obj["root_box"])
        )
        search_obj = _object(obj["search"], "system-root search")
        if set(search_obj) != {"source", "attempts", "refinements", "contraction_bound", "failure"}:
            raise ProtocolViolation("system-root search fields are not canonical")
        source = _string(search_obj["source"], "system-root search source")
        if source not in {"automatic", "provided"}:
            raise ProtocolViolation("system-root search source is unknown")
        attempts, refinements = search_obj["attempts"], search_obj["refinements"]
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in (attempts, refinements)
        ):
            raise ProtocolViolation("system-root search counts must be natural numbers")
        contraction = _canonical_wire_rational(
            search_obj["contraction_bound"], "system-root contraction bound"
        )
        failure = search_obj["failure"]
        if failure is not None:
            failure = _freeze_json(_object(failure, "system-root failure"))
        certificate = (
            None
            if obj["certificate"] is None
            else KrawczykCertificateDescriptor.parse(obj["certificate"])
        )
        if (status is OutcomeStatus.VERIFIED) != (certificate is not None):
            raise ProtocolViolation("only verified system-root outcomes may retain a certificate")
        if certificate is not None:
            payload = certificate.payload
            if payload.box != root_box:
                raise ProtocolViolation("Krawczyk payload box contradicts the outcome")
            if len(payload.system) != len(root_box):
                raise ProtocolViolation("Krawczyk payload dimension contradicts the outcome")
        assert backend is not None and source is not None
        return cls(
            status,
            backend,
            root_box,
            SystemRootSearchOutcome(source, attempts, refinements, contraction, failure),
            certificate,
            MappingProxyType(dict(obj)),
        )


SCALAR_ROOT_AUTHORITIES = {
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


@dataclass(frozen=True, slots=True)
class ReplayScalarRootPayload:
    expression: Mapping[str, Any]
    interval: WireEnclosure
    claim: str
    taylor_depth: int
    canonical: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> ReplayScalarRootPayload:
        obj = _object(value, "scalar-root certificate payload")
        if set(obj) != {"schema_version", "expression", "interval", "claim", "config"}:
            raise ProtocolViolation("scalar-root payload fields are not canonical")
        if obj["schema_version"] != "checked-scalar-root/1":
            raise ProtocolViolation("scalar-root replay payload schema is unsupported")
        expression = _freeze_json(_object(obj["expression"], "scalar-root expression"))
        interval = WireEnclosure.parse(obj["interval"], "scalar-root interval")
        claim = _string(obj["claim"], "scalar-root claim")
        if claim not in SCALAR_ROOT_AUTHORITIES:
            raise ProtocolViolation("scalar-root claim kind is unknown")
        config = _object(obj["config"], "scalar-root config")
        if set(config) != {"taylor_depth"}:
            raise ProtocolViolation("scalar-root config fields are not canonical")
        depth = config["taylor_depth"]
        if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
            raise ProtocolViolation("scalar-root Taylor depth must be a natural number")
        canonical = _freeze_json(dict(obj))
        assert claim is not None
        return cls(expression, interval, claim, depth, canonical)

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            _plain_json(self.canonical), sort_keys=True, separators=(",", ":")
        ).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ScalarRootCertificateDescriptor:
    schema_version: str
    checker: str
    verifier: str
    verification_route: str
    payload: ReplayScalarRootPayload

    @classmethod
    def parse(cls, value: Any) -> ScalarRootCertificateDescriptor:
        obj = _object(value, "scalar-root certificate")
        if set(obj) != {"schema_version", "checker", "verifier", "verification_route", "payload"}:
            raise ProtocolViolation("scalar-root certificate fields are not canonical")
        if obj["schema_version"] != "scalar-root-check/1":
            raise ProtocolViolation("scalar-root certificate schema is unsupported")
        payload = ReplayScalarRootPayload.parse(obj["payload"])
        checker, verifier = SCALAR_ROOT_AUTHORITIES[payload.claim]
        if obj["checker"] != checker or obj["verifier"] != verifier:
            raise ProtocolViolation("scalar-root certificate authority is not recognized")
        if obj["verification_route"] != "compiled_checker":
            raise ProtocolViolation("scalar-root verification route is unsupported")
        return cls(obj["schema_version"], checker, verifier, obj["verification_route"], payload)


@dataclass(frozen=True, slots=True)
class ScalarRootOperationOutcome:
    status: OutcomeStatus
    claim: str
    backend: str
    interval: WireEnclosure
    certificate: ScalarRootCertificateDescriptor | None
    raw: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any, *, expected_claim: str) -> ScalarRootOperationOutcome:
        obj = _object(value, "check_scalar_root result")
        required = {"verified", "status", "claim", "backend", "interval", "certificate"}
        if set(obj) != required:
            raise ProtocolViolation("scalar-root outcome fields are not canonical")
        if not isinstance(obj["verified"], bool):
            raise ProtocolViolation("scalar-root verified flag must be boolean")
        try:
            status = OutcomeStatus(obj["status"])
        except (TypeError, ValueError) as exc:
            raise ProtocolViolation("scalar-root status is unknown") from exc
        if status not in {
            OutcomeStatus.VERIFIED,
            OutcomeStatus.CANDIDATE_REJECTED,
            OutcomeStatus.UNSUPPORTED,
        }:
            raise ProtocolViolation("scalar-root status is invalid for this operation")
        if obj["verified"] != (status is OutcomeStatus.VERIFIED):
            raise ProtocolViolation("scalar-root verified flag contradicts status")
        claim = _string(obj["claim"], "scalar-root claim")
        if claim != expected_claim or claim not in SCALAR_ROOT_AUTHORITIES:
            raise ProtocolViolation("scalar-root claim contradicts the request")
        backend = _string(obj["backend"], "scalar-root backend")
        interval = WireEnclosure.parse(obj["interval"], "scalar-root interval")
        certificate = (
            None
            if obj["certificate"] is None
            else ScalarRootCertificateDescriptor.parse(obj["certificate"])
        )
        if (status is OutcomeStatus.VERIFIED) != (certificate is not None):
            raise ProtocolViolation("only verified scalar-root outcomes may retain a certificate")
        if certificate is not None:
            if certificate.payload.claim != claim or certificate.payload.interval != interval:
                raise ProtocolViolation("scalar-root certificate contradicts the outcome")
        assert claim is not None and backend is not None
        return cls(status, claim, backend, interval, certificate, MappingProxyType(dict(obj)))


INTEGRAL_AUTHORITIES = {
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


@dataclass(frozen=True, slots=True)
class ReplayIntegralPayload:
    expression: Mapping[str, Any]
    interval: WireEnclosure
    relation: str
    bound: WireRational
    partitions: int | None
    canonical: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> ReplayIntegralPayload:
        obj = _object(value, "integral certificate payload")
        if set(obj) != {
            "schema_version",
            "expression",
            "interval",
            "relation",
            "bound",
            "partitions",
        }:
            raise ProtocolViolation("integral payload fields are not canonical")
        if obj["schema_version"] != "checked-integral/1":
            raise ProtocolViolation("integral replay payload schema is unsupported")
        expression = _freeze_json(_object(obj["expression"], "integral expression"))
        interval = WireEnclosure.parse(obj["interval"], "integral interval")
        relation = _string(obj["relation"], "integral relation")
        if relation not in INTEGRAL_AUTHORITIES:
            raise ProtocolViolation("integral relation is unknown")
        bound = _canonical_wire_rational(obj["bound"], "integral bound")
        partitions = obj["partitions"]
        if relation == "eq":
            if partitions is not None:
                raise ProtocolViolation("exact integral certificates cannot retain partitions")
        elif isinstance(partitions, bool) or not isinstance(partitions, int) or partitions <= 0:
            raise ProtocolViolation("bounded integral certificates require positive partitions")
        canonical = _freeze_json(dict(obj))
        assert relation is not None
        return cls(expression, interval, relation, bound, partitions, canonical)

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            _plain_json(self.canonical), sort_keys=True, separators=(",", ":")
        ).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class IntegralCertificateDescriptor:
    schema_version: str
    checker: str
    verifier: str
    verification_route: str
    payload: ReplayIntegralPayload

    @classmethod
    def parse(cls, value: Any) -> IntegralCertificateDescriptor:
        obj = _object(value, "integral certificate")
        if set(obj) != {
            "schema_version",
            "checker",
            "verifier",
            "verification_route",
            "payload",
        }:
            raise ProtocolViolation("integral certificate fields are not canonical")
        if obj["schema_version"] != "integral-check/1":
            raise ProtocolViolation("integral certificate schema is unsupported")
        payload = ReplayIntegralPayload.parse(obj["payload"])
        checker, verifier = INTEGRAL_AUTHORITIES[payload.relation]
        if obj["checker"] != checker or obj["verifier"] != verifier:
            raise ProtocolViolation("integral certificate authority is not recognized")
        if obj["verification_route"] != "compiled_checker":
            raise ProtocolViolation("integral verification route is unsupported")
        return cls(obj["schema_version"], checker, verifier, obj["verification_route"], payload)


@dataclass(frozen=True, slots=True)
class IntegralSearchOutcome:
    source: str
    start_partitions: int | None
    max_partitions: int | None
    chosen_partitions: int | None
    attempts: int
    failure: Mapping[str, Any] | None

    @classmethod
    def parse(cls, value: Any) -> IntegralSearchOutcome:
        obj = _object(value, "integral search")
        if set(obj) != {
            "source",
            "start_partitions",
            "max_partitions",
            "chosen_partitions",
            "attempts",
            "failure",
        }:
            raise ProtocolViolation("integral search fields are not canonical")
        source = _string(obj["source"], "integral search source")
        if source not in {"exact", "automatic"}:
            raise ProtocolViolation("integral search source is unknown")
        start, maximum, chosen, attempts = (
            obj["start_partitions"],
            obj["max_partitions"],
            obj["chosen_partitions"],
            obj["attempts"],
        )
        if source == "exact":
            if start is not None or maximum is not None or chosen is not None or attempts != 0:
                raise ProtocolViolation("exact integral search metadata is contradictory")
        else:
            if (
                any(
                    isinstance(item, bool) or not isinstance(item, int) or item <= 0
                    for item in (start, maximum)
                )
                or start > maximum
            ):
                raise ProtocolViolation("integral partition limits are invalid")
            if chosen is not None and (
                isinstance(chosen, bool) or not isinstance(chosen, int) or chosen <= 0
            ):
                raise ProtocolViolation("chosen integral partitions must be positive")
            if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
                raise ProtocolViolation("integral search attempts must be natural")
        failure = obj["failure"]
        if failure is not None:
            failure = _freeze_json(_object(failure, "integral failure"))
        assert source is not None
        return cls(source, start, maximum, chosen, attempts, failure)


@dataclass(frozen=True, slots=True)
class IntegralOperationOutcome:
    status: OutcomeStatus
    relation: str
    route: str
    backend: str
    interval: WireEnclosure
    bound: WireRational
    enclosure: WireEnclosure | None
    search: IntegralSearchOutcome
    certificate: IntegralCertificateDescriptor | None
    raw: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any, *, expected_relation: str) -> IntegralOperationOutcome:
        obj = _object(value, "check_integral result")
        if set(obj) != {
            "verified",
            "status",
            "relation",
            "route",
            "backend",
            "interval",
            "bound",
            "enclosure",
            "search",
            "certificate",
        }:
            raise ProtocolViolation("integral outcome fields are not canonical")
        if not isinstance(obj["verified"], bool):
            raise ProtocolViolation("integral verified flag must be boolean")
        try:
            status = OutcomeStatus(obj["status"])
        except (TypeError, ValueError) as exc:
            raise ProtocolViolation("integral status is unknown") from exc
        if status not in {
            OutcomeStatus.VERIFIED,
            OutcomeStatus.CANDIDATE_REJECTED,
            OutcomeStatus.INCONCLUSIVE,
            OutcomeStatus.UNSUPPORTED,
            OutcomeStatus.DOMAIN_OBSTRUCTION,
        }:
            raise ProtocolViolation("integral status is invalid for this operation")
        if obj["verified"] != (status is OutcomeStatus.VERIFIED):
            raise ProtocolViolation("integral verified flag contradicts status")
        relation = _string(obj["relation"], "integral relation")
        if relation != expected_relation or relation not in INTEGRAL_AUTHORITIES:
            raise ProtocolViolation("integral relation contradicts the request")
        route = _string(obj["route"], "integral route")
        expected_route = "exact_polynomial" if relation == "eq" else "checked_partitions"
        if route != expected_route:
            raise ProtocolViolation("integral route contradicts its relation")
        backend = _string(obj["backend"], "integral backend")
        expected_backend = (
            "rational_exact_polynomial" if relation == "eq" else "rational_checked_partitions"
        )
        if backend != expected_backend:
            raise ProtocolViolation("integral backend contradicts its relation")
        interval = WireEnclosure.parse(obj["interval"], "integral interval")
        bound = _canonical_wire_rational(obj["bound"], "integral bound")
        enclosure = (
            None
            if obj["enclosure"] is None
            else WireEnclosure.parse(obj["enclosure"], "integral enclosure")
        )
        search = IntegralSearchOutcome.parse(obj["search"])
        certificate = (
            None
            if obj["certificate"] is None
            else IntegralCertificateDescriptor.parse(obj["certificate"])
        )
        if (status is OutcomeStatus.VERIFIED) != (certificate is not None):
            raise ProtocolViolation("only verified integral outcomes may retain a certificate")
        if status is OutcomeStatus.VERIFIED and enclosure is None:
            raise ProtocolViolation("verified integral outcomes require an enclosure")
        if relation == "eq" and status is OutcomeStatus.VERIFIED:
            assert enclosure is not None
            if enclosure.lower != bound or enclosure.upper != bound:
                raise ProtocolViolation("exact integral enclosure contradicts its bound")
        if relation == "eq" and search.source != "exact":
            raise ProtocolViolation("exact integral outcomes require exact search metadata")
        if relation != "eq" and search.source != "automatic":
            raise ProtocolViolation("bounded integral outcomes require partition search metadata")
        if certificate is not None:
            payload = certificate.payload
            if (
                payload.relation != relation
                or payload.interval != interval
                or payload.bound != bound
                or payload.expression is None
            ):
                raise ProtocolViolation("integral certificate contradicts the outcome")
            if relation != "eq" and payload.partitions != search.chosen_partitions:
                raise ProtocolViolation("integral certificate partitions contradict the search")
        assert relation is not None and route is not None and backend is not None
        return cls(
            status,
            relation,
            route,
            backend,
            interval,
            bound,
            enclosure,
            search,
            certificate,
            MappingProxyType(dict(obj)),
        )


@dataclass(frozen=True, slots=True)
class ReplayEventualPayload:
    coefficient: WireRational
    bound: WireRational
    exponent: int
    cutoff: int
    canonical: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> ReplayEventualPayload:
        obj = _object(value, "eventual-bound certificate payload")
        if (
            set(obj) != {"schema_version", "coefficient", "bound", "exponent", "cutoff"}
            or obj.get("schema_version") != "checked-eventual-bound/1"
        ):
            raise ProtocolViolation(
                "eventual-bound payload fields do not match checked-eventual-bound/1"
            )
        coefficient = _canonical_wire_rational(
            obj["coefficient"], "eventual-bound payload coefficient"
        )
        bound = _canonical_wire_rational(obj["bound"], "eventual-bound payload bound")
        exponent, cutoff = obj["exponent"], obj["cutoff"]
        if any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in (exponent, cutoff)
        ):
            raise ProtocolViolation("eventual-bound exponent and cutoff must be natural numbers")
        canonical = {
            "schema_version": "checked-eventual-bound/1",
            "coefficient": {
                "n": coefficient.numerator,
                "d": coefficient.denominator,
            },
            "bound": {"n": bound.numerator, "d": bound.denominator},
            "exponent": exponent,
            "cutoff": cutoff,
        }
        return cls(coefficient, bound, exponent, cutoff, _freeze_json(canonical))

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            _plain_json(self.canonical), sort_keys=True, separators=(",", ":")
        ).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class EventualCertificateDescriptor:
    schema_version: str
    checker: str
    verifier: str
    verification_route: str
    payload: ReplayEventualPayload

    @classmethod
    def parse(cls, value: Any) -> EventualCertificateDescriptor:
        obj = _object(value, "eventual-bound certificate")
        if set(obj) != {"schema_version", "checker", "verifier", "verification_route", "payload"}:
            raise ProtocolViolation("eventual-bound certificate fields are not canonical")
        if obj["schema_version"] != "eventual-bound-check/1":
            raise ProtocolViolation("eventual-bound certificate schema is unsupported")
        if obj["checker"] != "LeanCert.Validity.checkReciprocalPowerUpper":
            raise ProtocolViolation("eventual-bound checker authority is not recognized")
        if obj["verifier"] != "LeanCert.Validity.verify_reciprocal_power_upper":
            raise ProtocolViolation("eventual-bound verifier authority is not recognized")
        if obj["verification_route"] != "compiled_checker":
            raise ProtocolViolation("eventual-bound verification route is unsupported")
        return cls(
            obj["schema_version"],
            obj["checker"],
            obj["verifier"],
            obj["verification_route"],
            ReplayEventualPayload.parse(obj["payload"]),
        )


@dataclass(frozen=True, slots=True)
class EventualSearchOutcome:
    source: str
    checks: int | None
    configured_limit: int | None
    exponential_steps: int | None
    refinement_steps: int | None
    lower_bracket: int | None
    upper_bracket: int | None
    refinement_complete: bool | None
    last_cutoff: int | None
    raw: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> EventualSearchOutcome:
        obj = _object(value, "eventual-bound search")
        allowed = {
            "source",
            "checks",
            "configured_limit",
            "exponential_steps",
            "refinement_steps",
            "lower_bracket",
            "upper_bracket",
            "refinement_complete",
            "last_cutoff",
        }
        if not set(obj) <= allowed or "source" not in obj:
            raise ProtocolViolation("eventual-bound search fields are not canonical")
        source = _string(obj["source"], "eventual-bound search source")
        if source not in {"automatic", "provided"}:
            raise ProtocolViolation("eventual-bound search source is unknown")
        if source == "provided" and set(obj) != {"source"}:
            raise ProtocolViolation("provided eventual-bound search must not retain discovery data")
        numeric_names = (
            "checks",
            "configured_limit",
            "exponential_steps",
            "refinement_steps",
            "lower_bracket",
            "upper_bracket",
            "last_cutoff",
        )
        values: dict[str, int | None] = {}
        for name in numeric_names:
            item = obj.get(name)
            if item is not None and (
                isinstance(item, bool) or not isinstance(item, int) or item < 0
            ):
                raise ProtocolViolation(f"eventual-bound search {name} must be natural")
            values[name] = item
        complete = obj.get("refinement_complete")
        if complete is not None and not isinstance(complete, bool):
            raise ProtocolViolation("eventual-bound search refinement_complete must be boolean")
        assert source is not None
        return cls(
            source,
            values["checks"],
            values["configured_limit"],
            values["exponential_steps"],
            values["refinement_steps"],
            values["lower_bracket"],
            values["upper_bracket"],
            complete,
            values["last_cutoff"],
            _freeze_json(obj),
        )


@dataclass(frozen=True, slots=True)
class EventualOperationOutcome:
    status: OutcomeStatus
    backend: str
    cutoff: int | None
    search: EventualSearchOutcome
    failure: Mapping[str, Any] | None
    certificate: EventualCertificateDescriptor | None
    raw: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> EventualOperationOutcome:
        obj = _object(value, "check_eventual_bound result")
        if set(obj) != {
            "verified",
            "status",
            "backend",
            "cutoff",
            "search",
            "failure",
            "certificate",
        }:
            raise ProtocolViolation("eventual-bound outcome fields are not canonical")
        if not isinstance(obj["verified"], bool):
            raise ProtocolViolation("eventual-bound verified flag must be boolean")
        try:
            status = OutcomeStatus(obj["status"])
        except (TypeError, ValueError) as exc:
            raise ProtocolViolation("eventual-bound status is unknown") from exc
        if status not in {
            OutcomeStatus.VERIFIED,
            OutcomeStatus.CANDIDATE_REJECTED,
            OutcomeStatus.INCONCLUSIVE,
            OutcomeStatus.UNSUPPORTED,
        }:
            raise ProtocolViolation("eventual-bound status is invalid for this operation")
        if obj["verified"] != (status is OutcomeStatus.VERIFIED):
            raise ProtocolViolation("eventual-bound verified flag contradicts status")
        backend = _string(obj["backend"], "eventual-bound backend")
        cutoff = obj["cutoff"]
        if cutoff is not None and (
            isinstance(cutoff, bool) or not isinstance(cutoff, int) or cutoff < 0
        ):
            raise ProtocolViolation("eventual-bound cutoff must be a natural number")
        search = EventualSearchOutcome.parse(obj["search"])
        failure = obj["failure"]
        if failure is not None:
            failure_obj = _object(failure, "eventual-bound failure")
            if set(failure_obj) != {"kind", "detail"}:
                raise ProtocolViolation("eventual-bound failure fields are not canonical")
            _string(failure_obj["kind"], "eventual-bound failure kind")
            _string(failure_obj["detail"], "eventual-bound failure detail")
            failure = _freeze_json(failure_obj)
        certificate = (
            None
            if obj["certificate"] is None
            else EventualCertificateDescriptor.parse(obj["certificate"])
        )
        if (status is OutcomeStatus.VERIFIED) != (certificate is not None):
            raise ProtocolViolation(
                "only verified eventual-bound outcomes may retain a certificate"
            )
        if status is OutcomeStatus.VERIFIED and (cutoff is None or failure is not None):
            raise ProtocolViolation("verified eventual-bound outcome is internally inconsistent")
        if status is not OutcomeStatus.VERIFIED and failure is None:
            raise ProtocolViolation("non-verified eventual-bound outcome lacks a failure")
        if certificate is not None and certificate.payload.cutoff != cutoff:
            raise ProtocolViolation("eventual-bound certificate cutoff contradicts outcome")
        assert backend is not None
        return cls(
            status,
            backend,
            cutoff,
            search,
            failure,
            certificate,
            MappingProxyType(dict(obj)),
        )
