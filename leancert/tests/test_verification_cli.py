"""Independent exported-project verification and CLI behavior."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import leancert as lc
from leancert import ast
from leancert.cli import main
from leancert.tests.test_eventual_bounds import FakeEventualClient, reciprocal_claim
from leancert.tests.test_export import ReplayClient, response
from leancert.tests.test_system_roots import FakeSystemRootClient, coupled_claim


def exported_project(tmp_path: Path, name: str = "proof") -> Path:
    x = ast.var("x")
    result = lc.prove(x <= 1, where={x: (0, 1)}, client=ReplayClient((response(),)))
    exported = result.export_lean_project(str(tmp_path / name), verify=False)
    assert isinstance(exported, lc.ExportPrepared)
    return tmp_path / name


def successful_build(command, **kwargs):
    assert command[-2:] == ["build", "LeanCertExport"]
    return subprocess.CompletedProcess(command, 0, "kernel checked")


def test_export_writes_versioned_integrity_manifest(tmp_path):
    project = exported_project(tmp_path)
    manifest = json.loads((project / "artifact.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "leancert-export/1"
    assert manifest["trust_class"] == "kernel"
    assert manifest["target"] == "LeanCertExport"
    assert set(manifest["files"]) == {
        "LeanCertExport.lean",
        "lean-toolchain",
        "lakefile.toml",
        "claim.json",
        "certificate.json",
        "provenance.json",
    }
    assert all(value.startswith("sha256:") for value in manifest["files"].values())


def test_verify_rebuilds_valid_artifact(tmp_path, monkeypatch):
    project = exported_project(tmp_path)
    monkeypatch.setattr("leancert.verification.shutil.which", lambda name: "/tools/lake")
    monkeypatch.setattr("leancert.verification.subprocess.run", successful_build)
    report = lc.verify_exported_projects([project])
    assert report.verified
    assert report.exit_code == lc.VerificationExitCode.SUCCESS
    assert report.artifacts[0].trust_class == "kernel"
    assert (
        report.artifacts[0].claim_id
        == json.loads((project / "artifact.json").read_text(encoding="utf-8"))["claim_id"]
    )


@pytest.mark.parametrize("kind", ["system_root", "eventual"])
def test_verifier_accepts_every_exported_certificate_family(tmp_path, monkeypatch, kind):
    if kind == "system_root":
        result = lc.prove(coupled_claim(), client=FakeSystemRootClient())
    else:
        result = lc.prove(reciprocal_claim(), client=FakeEventualClient())
    project = tmp_path / kind
    assert isinstance(result.export_lean_project(project, verify=False), lc.ExportPrepared)
    monkeypatch.setattr("leancert.verification.shutil.which", lambda name: "/tools/lake")
    monkeypatch.setattr("leancert.verification.subprocess.run", successful_build)
    report = lc.verify_exported_projects([project])
    assert report.verified, report.to_dict()


def test_recursive_discovery_is_deterministic_and_skips_build_trees(tmp_path, monkeypatch):
    second = exported_project(tmp_path / "nested", "b")
    first = exported_project(tmp_path, "a")
    ignored = tmp_path / ".lake" / "hidden"
    ignored.mkdir(parents=True)
    (ignored / "artifact.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr("leancert.verification.shutil.which", lambda name: "/tools/lake")
    monkeypatch.setattr("leancert.verification.subprocess.run", successful_build)
    report = lc.verify_exported_projects([tmp_path])
    assert [Path(item.path) for item in report.artifacts] == [first.resolve(), second.resolve()]


def test_tampered_source_is_rejected_before_lake_runs(tmp_path, monkeypatch):
    project = exported_project(tmp_path)
    source = project / "LeanCertExport.lean"
    source.write_text(source.read_text(encoding="utf-8") + "-- tampered\n", encoding="utf-8")
    monkeypatch.setattr(
        "leancert.verification.subprocess.run",
        lambda *args, **kwargs: pytest.fail("lake must not run for an invalid artifact"),
    )
    report = lc.verify_exported_projects([project], lake="/tools/lake")
    assert report.exit_code == lc.VerificationExitCode.INVALID_ARTIFACT
    assert "digest mismatch" in report.artifacts[0].message


def test_tampered_certificate_payload_is_rejected_even_with_updated_file_hash(
    tmp_path, monkeypatch
):
    project = exported_project(tmp_path)
    certificate_path = project / "certificate.json"
    certificate = json.loads(certificate_path.read_text(encoding="utf-8"))
    certificate["certificates"][0]["payload"]["bound"] = {"n": 2, "d": 1}
    certificate_path.write_text(json.dumps(certificate, sort_keys=True), encoding="utf-8")
    manifest_path = project / "artifact.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    from leancert.verification import file_digest

    manifest["files"]["certificate.json"] = file_digest(certificate_path)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    monkeypatch.setattr(
        "leancert.verification.subprocess.run",
        lambda *args, **kwargs: pytest.fail("lake must not run for an invalid certificate"),
    )
    report = lc.verify_exported_projects([project], lake="/tools/lake")
    assert report.exit_code == lc.VerificationExitCode.INVALID_ARTIFACT
    assert "payload digest" in report.artifacts[0].message


def test_tampered_authority_is_rejected_even_with_updated_file_hash(tmp_path, monkeypatch):
    project = exported_project(tmp_path)
    certificate_path = project / "certificate.json"
    certificate = json.loads(certificate_path.read_text(encoding="utf-8"))
    certificate["certificates"][0]["checker"] = "Untrusted.accept"
    certificate_path.write_text(json.dumps(certificate, sort_keys=True), encoding="utf-8")
    manifest_path = project / "artifact.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    from leancert.verification import file_digest

    manifest["files"]["certificate.json"] = file_digest(certificate_path)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    monkeypatch.setattr(
        "leancert.verification.subprocess.run",
        lambda *args, **kwargs: pytest.fail("lake must not run for a forged authority"),
    )
    report = lc.verify_exported_projects([project], lake="/tools/lake")
    assert report.exit_code == lc.VerificationExitCode.INVALID_ARTIFACT
    assert "authority" in report.artifacts[0].message


def test_missing_lake_is_an_infrastructure_failure(tmp_path, monkeypatch):
    project = exported_project(tmp_path)
    monkeypatch.setattr("leancert.verification.shutil.which", lambda name: None)
    report = lc.verify_exported_projects([project])
    assert report.exit_code == lc.VerificationExitCode.INFRASTRUCTURE_FAILURE
    assert report.artifacts[0].status == "infrastructure_failure"


def test_lake_rejection_is_a_verification_failure(tmp_path, monkeypatch):
    project = exported_project(tmp_path)
    monkeypatch.setattr("leancert.verification.shutil.which", lambda name: "/tools/lake")
    monkeypatch.setattr(
        "leancert.verification.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "bad theorem"),
    )
    report = lc.verify_exported_projects([project])
    assert report.exit_code == lc.VerificationExitCode.VERIFICATION_FAILED
    assert report.artifacts[0].build_output == "bad theorem"


def test_timeout_has_a_distinct_exit_code(tmp_path, monkeypatch):
    project = exported_project(tmp_path)
    monkeypatch.setattr("leancert.verification.shutil.which", lambda name: "/tools/lake")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output="still building")

    monkeypatch.setattr("leancert.verification.subprocess.run", timeout)
    report = lc.verify_exported_projects([project], timeout=1)
    assert report.exit_code == lc.VerificationExitCode.RESOURCE_LIMIT
    assert report.artifacts[0].build_output == "still building"


def test_cli_emits_stable_json_report(tmp_path, monkeypatch, capsys):
    project = exported_project(tmp_path)
    monkeypatch.setattr("leancert.verification.shutil.which", lambda name: "/tools/lake")
    monkeypatch.setattr("leancert.verification.subprocess.run", successful_build)
    assert main(["verify", str(project), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == "leancert-verification-report/1"
    assert payload["verified"] is True
    assert payload["artifacts"][0]["status"] == "verified"


def test_no_artifacts_is_invalid(tmp_path):
    report = lc.verify_exported_projects([tmp_path])
    assert report.exit_code == lc.VerificationExitCode.INVALID_ARTIFACT
    assert "no artifact.json" in report.artifacts[0].message


def test_non_positive_timeout_is_cli_usage_error(capsys):
    assert main(["verify", ".", "--timeout", "0"]) == 2
    assert "timeout must be positive" in capsys.readouterr().err
