"""Tests for installation diagnostics and the command-line presentation."""

from __future__ import annotations

import json
from pathlib import Path

from leancert.cli import main
from leancert.doctor import diagnose
from leancert.protocol import BridgeHandshake

FIXTURES = Path(__file__).parent / "fixtures"


class FakeClient:
    def __init__(self, *, binary_path=None):
        self.binary_path = __file__
        self.closed = False
        self._info = json.loads(
            (FIXTURES / "bridge-contract-2.1" / "handshake.json").read_text()
        )
        self._info["bridge_api_version"] = "2.2.0"
        self._info["protocol_version"] = "2.2.0"
        self._info["certificate_schemas"].append("adaptive-bound-check/1")
        self._info["operations"].append("verify_adaptive")
        self._info["capabilities"]["verify_adaptive"] = {
            "schema_version": "2.2",
            "request_schema": "verify-adaptive-request/1",
            "result_schema": "adaptive-bound-outcome/1",
            "certificate_schemas": ["adaptive-bound-check/1"],
            "verification_routes": ["compiled_checker"],
            "outcomes": ["verified", "inconclusive", "unsupported", "domain_obstruction"],
            "backends": ["rational_checked_global_optimization"],
        }
        self._info["build"]["profile"] = "release"

    def get_info(self):
        return self._info

    @property
    def bridge_contract(self):
        return BridgeHandshake.parse(self._info)

    def close(self):
        self.closed = True


def test_doctor_accepts_release_contract_2_2():
    report = diagnose(client_factory=FakeClient)
    assert report.healthy
    assert {check.name for check in report.checks} == {
        "binary", "contract", "replayable_bounds", "checked_adaptive", "release_provenance"
    }


def test_doctor_reports_missing_binary_without_throwing():
    class Missing:
        def __init__(self, **kwargs):
            raise FileNotFoundError("no bridge")

    report = diagnose(client_factory=Missing)
    assert not report.healthy
    assert report.checks[0].name == "binary"


def test_doctor_cli_json_exit_status(monkeypatch, capsys):
    report = diagnose(client_factory=FakeClient)
    monkeypatch.setattr("leancert.cli.diagnose", lambda path: report)
    assert main(["doctor", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["healthy"] is True
