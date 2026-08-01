"""Typed models for the versioned LeanCert bridge wire contract.

The bridge uses line-delimited JSON, not JSON-RPC 2.0. This module validates
the semantic content of handshakes and checked-operation responses without
owning subprocess transport or mathematical SDK result types.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
from types import MappingProxyType
from typing import Any

from .exceptions import ProtocolViolation

SUPPORTED_BRIDGE_API_MAJORS = frozenset({1, 2})
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
    request_schema: str | None = None
    result_schema: str | None = None
    certificate_schemas: frozenset[str] = frozenset()
    verification_routes: frozenset[str] = frozenset()

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
        )


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
        input_revision = _string(
            leancert["input_revision"], "dependencies.leancert.input_revision"
        )
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

    def parse_bound_outcome(
        self, value: Any, *, expected_direction: str
    ) -> BoundOperationOutcome:
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

    def parse_adaptive_outcome(
        self, value: Any, *, expected_direction: str
    ) -> AdaptiveOperationOutcome:
        capability = self.capability("verify_adaptive")
        if capability is None:
            raise ProtocolViolation(
                "bridge returned an adaptive outcome without verify_adaptive capability"
            )
        outcome = AdaptiveOperationOutcome.parse(
            value, expected_direction=expected_direction
        )
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
        protocol_name = _string(
            obj.get("protocol_name"), "protocol_name", optional=api.major < 2
        )
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
        build = None if api.major < 2 else BuildProvenance.parse(obj.get("build"))
        dependencies = (
            ResolvedDependencies.parse(obj.get("dependencies"))
            if api >= ProtocolVersion(2, 1, 0)
            else None
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
        "neg", "inv", "exp", "sin", "cos", "log", "atan", "arsinh",
        "atanh", "sinc", "erf", "sinh", "cosh", "tanh", "sqrt",
    }:
        if set(obj) != {"kind", "e"}:
            raise ProtocolViolation(f"{name} unary fields are not canonical")
        return {"kind": kind, "e": _canonical_core_expression(obj["e"], f"{name}.e")}
    if kind == "named_const":
        if set(obj) != {"kind", "name"} or obj["name"] not in {
            "pi", "euler_mascheroni",
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
                    _canonical_wire_rational(
                        item["lo"], f"certificate.payload.box[{index}].lo"
                    ),
                    _canonical_wire_rational(
                        item["hi"], f"certificate.payload.box[{index}].hi"
                    ),
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
        if set(config_obj) != {
            "max_iterations", "tolerance", "use_monotonicity", "taylor_depth"
        }:
            raise ProtocolViolation("replay configuration fields are not canonical")
        maximum, depth = config_obj["max_iterations"], config_obj["taylor_depth"]
        monotonicity = config_obj["use_monotonicity"]
        if any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in (maximum, depth)):
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
class CertificateDescriptor:
    schema_version: str
    checker: str
    verifier: str
    verification_route: str
    payload: ReplayBoundPayload | None = None

    @classmethod
    def parse(cls, value: Any) -> CertificateDescriptor:
        obj = _object(value, "certificate")
        schema_version = _string(obj.get("schema_version"), "certificate.schema_version")
        required = {"schema_version", "checker", "verifier", "verification_route"}
        if schema_version == "bound-check/2":
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
            payload=(ReplayBoundPayload.parse(obj["payload"]) if "payload" in obj else None),
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
                "schema_version", "checker", "verifier", "verification_route", "payload"
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
            if enclosure is None or WireEnclosure.parse(
                payload.get("candidate_enclosure"),
                "verify_adaptive.certificate.payload.candidate_enclosure",
            ) != enclosure:
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
