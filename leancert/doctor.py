"""Installation and bridge-contract diagnostics for LeanCert Python."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .client import LeanClient
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
    binary_path: str | None = None,
    *,
    client_factory: Callable[..., LeanClient] = LeanClient,
) -> DoctorReport:
    """Inspect the installed binary and negotiate the production contract."""
    checks: list[DoctorCheck] = []
    try:
        client = client_factory(binary_path=binary_path)
    except Exception as exc:
        return DoctorReport((DoctorCheck("binary", False, str(exc)),), {})

    try:
        resolved = Path(client.binary_path).expanduser().resolve()
        checks.append(DoctorCheck("binary", resolved.is_file(), str(resolved)))
        try:
            info = client.get_info()
            contract = client.bridge_contract
        except Exception as exc:
            checks.append(DoctorCheck("handshake", False, str(exc)))
            return DoctorReport(tuple(checks), {})

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
                bound is not None
                and "bound-check/2" in bound.certificate_schemas
                and contract.dependencies is not None,
                "fixed bound replay and resolved dependency provenance",
            )
        )
        adaptive = contract.capability("verify_adaptive")
        checks.append(
            DoctorCheck(
                "checked_adaptive",
                adaptive is not None
                and "adaptive-bound-check/1" in adaptive.certificate_schemas,
                "checked rational adaptive optimizer",
            )
        )
        build = contract.build
        checks.append(
            DoctorCheck(
                "release_provenance",
                build is not None and build.release_ready,
                "release binary with source and environment digests",
            )
        )
        return DoctorReport(tuple(checks), dict(info))
    finally:
        client.close()


__all__ = ["DoctorCheck", "DoctorReport", "diagnose"]
