"""Replayable fixed-certificate export."""

from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

import leancert as lc
from leancert import ast
from leancert.exceptions import ProtocolViolation
from leancert.protocol import BridgeHandshake

FIXTURES = Path(__file__).parent / "fixtures"


class ReplayClient:
    def __init__(self, responses: tuple[dict, ...]):
        info = json.loads(
            (FIXTURES / "bridge-contract-2.1" / "handshake.json").read_text()
        )
        info["expression_nodes"].extend(["sin", "cos", "exp"])
        self.bridge_contract = BridgeHandshake.parse(info)
        self.bridge_info = info
        self.responses = list(responses)

    def check_bound(self, *args, **kwargs):
        return deepcopy(self.responses.pop(0))


def response(*, direction="upper", bound=1):
    value = json.loads(
        (FIXTURES / "bridge-contract-2.1" / "verified-bound.json").read_text()
    )
    value["direction"] = direction
    value["certificate"]["payload"]["direction"] = direction
    value["certificate"]["payload"]["bound"] = {"n": bound, "d": 1}
    if direction == "lower":
        value["certificate"]["checker"] = (
            "LeanCert.Validity.GlobalOpt.checkGlobalLowerBound"
        )
        value["certificate"]["verifier"] = (
            "LeanCert.Validity.GlobalOpt.verify_global_lower_bound"
        )
    return value


def test_verified_result_retains_replay_identity_and_exports_project(tmp_path):
    x = ast.var("x")
    result = lc.prove(x <= 1, where={x: (0, 1)}, client=ReplayClient((response(),)))
    assert isinstance(result, lc.Verified)
    replay = result.checks[0].replay_certificate
    assert replay is not None and replay.payload_digest.startswith("sha256:")

    exported = result.export_lean_project(str(tmp_path / "proof"), verify=False)
    assert isinstance(exported, lc.ExportPrepared)
    source = (tmp_path / "proof" / "LeanCertExport.lean").read_text()
    assert "decide +kernel" in source
    assert "ADSupported expression" in source
    assert "#assert_trust kernel exported_claim_0" in source
    assert "leancert (" not in source
    certificate = json.loads((tmp_path / "proof" / "certificate.json").read_text())
    assert certificate["certificates"][0]["payload_digest"] == replay.payload_digest
    assert 'defaultTargets = ["LeanCertExport"]' in (
        tmp_path / "proof" / "lakefile.toml"
    ).read_text()


def test_two_sided_export_replays_each_checked_direction(tmp_path):
    x = ast.var("x")
    result = lc.prove(
        ast.all_of(x >= 0, x <= 1),
        where={x: (0, 1)},
        client=ReplayClient((response(direction="lower", bound=0), response())),
    )
    exported = result.export_lean_project(str(tmp_path / "proof"), verify=False)
    assert isinstance(exported, lc.ExportPrepared)
    source = (tmp_path / "proof" / "LeanCertExport.lean").read_text()
    assert "checkGlobalLowerBound" in source
    assert "checkGlobalUpperBound" in source
    assert source.count("#assert_trust kernel") == 2


def test_contract_2_0_verified_result_is_explicitly_non_exportable(tmp_path):
    from leancert.tests.test_unified_prove import FakeCheckedClient

    x = ast.var("x")
    result = lc.prove(x <= 1, where={x: (0, 1)}, client=FakeCheckedClient())
    exported = result.export_lean_project(str(tmp_path / "proof"), verify=False)
    assert isinstance(exported, lc.ExportUnsupported)
    assert not (tmp_path / "proof").exists()


def test_replay_payload_must_agree_with_checked_request():
    x = ast.var("x")
    mismatched = response()
    mismatched["certificate"]["payload"]["bound"] = {"n": 2, "d": 1}
    with pytest.raises(ProtocolViolation, match="bound does not match"):
        lc.prove(x <= 1, where={x: (0, 1)}, client=ReplayClient((mismatched,)))


def test_export_refuses_to_overwrite_existing_directory(tmp_path):
    x = ast.var("x")
    result = lc.prove(x <= 1, where={x: (0, 1)}, client=ReplayClient((response(),)))
    destination = tmp_path / "proof"
    destination.mkdir()
    with pytest.raises(FileExistsError):
        result.export_lean_project(str(destination), verify=False)


def test_export_verification_builds_the_explicit_lean_target(tmp_path, monkeypatch):
    x = ast.var("x")
    result = lc.prove(x <= 1, where={x: (0, 1)}, client=ReplayClient((response(),)))
    observed = {}

    def run(command, **kwargs):
        observed["command"] = command
        observed["cwd"] = kwargs["cwd"]
        return type("Completed", (), {"returncode": 0, "stdout": "kernel checked"})()

    monkeypatch.setattr("leancert.export.shutil.which", lambda name: "/toolchain/lake")
    monkeypatch.setattr("leancert.export.subprocess.run", run)
    exported = result.export_lean_project(str(tmp_path / "proof"))
    assert isinstance(exported, lc.ExportVerified)
    assert observed["command"] == ["/toolchain/lake", "build", "LeanCertExport"]
    assert observed["cwd"].parent == tmp_path.resolve()
    assert observed["cwd"].name.startswith(".proof.")
    assert (tmp_path / "proof").is_dir()


def test_failed_export_is_atomic(tmp_path, monkeypatch):
    x = ast.var("x")
    result = lc.prove(x <= 1, where={x: (0, 1)}, client=ReplayClient((response(),)))
    monkeypatch.setattr("leancert.export.shutil.which", lambda name: "/toolchain/lake")
    monkeypatch.setattr(
        "leancert.export.subprocess.run",
        lambda *args, **kwargs: type(
            "Completed", (), {"returncode": 1, "stdout": "bad certificate"}
        )(),
    )

    exported = result.export_lean_project(str(tmp_path / "proof"))
    assert isinstance(exported, lc.ExportVerificationMismatch)
    assert not (tmp_path / "proof").exists()
    assert not list(tmp_path.glob(".proof.*"))


def test_export_timeout_is_typed_and_atomic(tmp_path, monkeypatch):
    x = ast.var("x")
    result = lc.prove(x <= 1, where={x: (0, 1)}, client=ReplayClient((response(),)))
    monkeypatch.setattr("leancert.export.shutil.which", lambda name: "/toolchain/lake")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output="still building")

    monkeypatch.setattr("leancert.export.subprocess.run", timeout)
    exported = result.export_lean_project(str(tmp_path / "proof"))
    assert isinstance(exported, lc.ExportResourceLimit)
    assert exported.timeout_seconds == 900
    assert exported.build_output == "still building"
    assert not (tmp_path / "proof").exists()
    assert not list(tmp_path.glob(".proof.*"))
