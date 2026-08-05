"""Installation and bridge-contract diagnostics for LeanCert Python."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from .client import DEFAULT_BRIDGE_PACKAGE_REF, LeanClient
from .protocol import ProtocolVersion


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]
    bridge_info: dict[str, Any]

    @property
    def healthy(self) -> bool:
        return all(check.ok for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "checks": [asdict(check) for check in self.checks],
            "bridge_info": self.bridge_info,
        }


def diagnose(
    package_ref: str | None = None,
    *,
    client_factory: Callable[..., LeanClient] = LeanClient,
) -> DoctorReport:
    """Ensure the managed environment and negotiate the production contract."""
    checks: list[DoctorCheck] = []
    try:
        client = client_factory(package_ref=package_ref or DEFAULT_BRIDGE_PACKAGE_REF)
    except Exception as exc:
        return DoctorReport((DoctorCheck("environment", False, str(exc)),), {})

    try:
        try:
            info = client.get_info()
            contract = client.bridge_contract
            environment_id = client.environment_id
            program_id = getattr(client, "program_id", None)
            execution_id = client.execution_id
        except Exception as exc:
            checks.append(DoctorCheck("handshake", False, str(exc)))
            return DoctorReport(tuple(checks), {})

        execution_target = program_id or environment_id
        checks.append(
            DoctorCheck(
                "environment",
                isinstance(execution_target, str) and bool(execution_target),
                execution_target or "<unavailable>",
            )
        )

        checks.append(
            DoctorCheck(
                "contract",
                contract.api_version >= ProtocolVersion(2, 2, 0),
                f"Bridge Contract {contract.api_version}",
            )
        )
        bound = contract.capability("check_bound")
        checks.append(
            DoctorCheck(
                "replayable_bounds",
                bound is not None and "bound-check/2" in bound.certificate_schemas,
                "fixed bound replay",
            )
        )
        adaptive = contract.capability("verify_adaptive")
        checks.append(
            DoctorCheck(
                "checked_adaptive",
                adaptive is not None and "adaptive-bound-check/1" in adaptive.certificate_schemas,
                "checked rational adaptive optimizer",
            )
        )
        checks.append(
            DoctorCheck(
                "runtime_provenance",
                isinstance(execution_id, str) and bool(execution_id),
                f"managed execution {execution_id or '<unavailable>'}",
            )
        )
        return DoctorReport(tuple(checks), dict(info))
    finally:
        client.close()


__all__ = ["DoctorCheck", "DoctorReport", "diagnose"]
