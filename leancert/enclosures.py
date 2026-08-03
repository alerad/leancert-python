"""Immutable downstream enclosure profiles and negotiated function handles."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import ast
from .exceptions import ProtocolViolation
from .protocol import EnclosureProfileIdentity, RegisteredEnclosureRule


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class EnclosureProfile:
    """A local immutable profile used to start one Bridge process."""

    path: Path
    name: str
    modules: tuple[str, ...]
    allowed_functions: tuple[str, ...]
    leancert_revision: str
    environment_digest: str
    schema_version: str = "leancert-enclosure-profile/1"

    @classmethod
    def load(cls, path: str | Path) -> EnclosureProfile:
        profile_path = Path(path).expanduser().resolve()
        try:
            value = json.loads(profile_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot load enclosure profile {profile_path}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError("enclosure profile must be a JSON object")
        expected = {
            "schema_version", "name", "modules", "allowed_functions",
            "leancert_revision", "environment_digest",
        }
        if set(value) != expected:
            raise ValueError("enclosure profile fields do not match leancert-enclosure-profile/1")
        if value["schema_version"] != "leancert-enclosure-profile/1":
            raise ValueError("unsupported enclosure profile schema")
        for key in ("name", "leancert_revision", "environment_digest"):
            if not isinstance(value[key], str) or not value[key]:
                raise ValueError(f"enclosure profile {key} must be a non-empty string")
        modules = value["modules"]
        functions = value["allowed_functions"]
        for key, items in (("modules", modules), ("allowed_functions", functions)):
            if (
                not isinstance(items, list)
                or not items
                or any(not isinstance(item, str) or not item for item in items)
                or len(items) != len(set(items))
            ):
                raise ValueError(f"enclosure profile {key} must be a unique non-empty string list")
        return cls(
            profile_path,
            value["name"],
            tuple(modules),
            tuple(functions),
            value["leancert_revision"],
            value["environment_digest"],
        )

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "modules": list(self.modules),
            "allowed_functions": list(self.allowed_functions),
            "leancert_revision": self.leancert_revision,
            "environment_digest": self.environment_digest,
        }

    @property
    def fingerprint(self) -> str:
        return _canonical_digest(self.identity_payload)

    def validate_handshake(self, remote: EnclosureProfileIdentity | None) -> None:
        if remote is None:
            raise ProtocolViolation("Bridge did not load the requested enclosure profile")
        actual = {
            "schema_version": remote.schema_version,
            "name": remote.name,
            "modules": list(remote.modules),
            "allowed_functions": list(remote.allowed_functions),
            "leancert_revision": remote.leancert_revision,
            "environment_digest": remote.environment_digest,
        }
        if actual != self.identity_payload:
            raise ProtocolViolation("Bridge enclosure profile identity differs from the local profile")


@dataclass(frozen=True, slots=True)
class RegisteredFunction:
    """Callable handle issued from the Bridge's frozen registered-rule inventory."""

    reference: ast.ExternalFunctionRef
    rules: tuple[RegisteredEnclosureRule, ...]
    profile_fingerprint: str

    @property
    def lean_name(self) -> str:
        return self.reference.lean_name

    def __call__(self, argument: object) -> ast.FunctionCall:
        return ast.FunctionCall(self.reference, (ast.as_expr(argument),))


class EnclosureEnvironment:
    """Read-only registry negotiated with a profile-loaded Bridge process."""

    def __init__(self, profile: EnclosureProfile, remote: EnclosureProfileIdentity):
        profile.validate_handshake(remote)
        package = ast.PackageIdentity(
            profile.name,
            f"leancert-enclosure-profile:{profile.name}",
            profile.leancert_revision,
            profile.environment_digest,
        )
        self._profile = profile
        self._remote = remote
        rules_by_function = {
            function: tuple(rule for rule in remote.registry if rule.function == function)
            for function in remote.allowed_functions
        }
        self._functions = {
            function: RegisteredFunction(
                ast.external_unary(
                    function,
                    package,
                    f"leancert.registered-enclosure.{profile.fingerprint}.{function}",
                    declaration_digest=_canonical_digest(
                        {
                            "profile": profile.fingerprint,
                            "function": function,
                            "rules": [
                                {
                                    "candidate": rule.candidate,
                                    "checker": rule.checker,
                                    "theorem": rule.theorem,
                                    "priority": rule.priority,
                                }
                                for rule in rules_by_function[function]
                            ],
                        }
                    ),
                ),
                rules_by_function[function],
                profile.fingerprint,
            )
            for function in remote.allowed_functions
        }

    @property
    def profile(self) -> EnclosureProfile:
        return self._profile

    @property
    def identity(self) -> EnclosureProfileIdentity:
        return self._remote

    @property
    def functions(self) -> tuple[str, ...]:
        return tuple(self._functions)

    def function(self, lean_name: str) -> RegisteredFunction:
        try:
            return self._functions[lean_name]
        except KeyError as exc:
            raise KeyError(f"{lean_name!r} is not registered by profile {self._profile.name!r}") from exc

    def validates(self, reference: ast.ExternalFunctionRef) -> bool:
        handle = self._functions.get(reference.lean_name)
        return handle is not None and handle.reference == reference


__all__ = ["EnclosureEnvironment", "EnclosureProfile", "RegisteredFunction"]
