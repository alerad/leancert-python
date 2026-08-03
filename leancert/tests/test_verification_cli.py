"""Independent exported-project verification and CLI behavior."""

from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import pytest
from lean_runtime import EnvironmentError

import leancert as lc
from leancert import ast
from leancert.cli import main
from leancert.tests.test_eventual_bounds import FakeEventualClient, reciprocal_claim
from leancert.tests.test_export import ReplayClient, response
from leancert.tests.test_integral_claims import FakeIntegralClient, integral_expression
from leancert.tests.test_scalar_roots import FakeScalarRootClient
from leancert.tests.test_strict_bounds import StrictClient, strict_response
from leancert.tests.test_system_roots import FakeSystemRootClient, coupled_claim


def exported_project(tmp_path: Path, name: str = "proof") -> Path:
    x = ast.var("x")
    result = lc.prove(x <= 1, where={x: (0, 1)}, client=ReplayClient((response(),)))
    exported = result.export_lean_project(str(tmp_path / name), verify=False)
    assert isinstance(exported, lc.ExportPrepared)
    return tmp_path / name


def managed(client):
    """Give protocol fakes the runtime identity required by exported artifacts."""
    client.environment = SimpleNamespace(id="env_" + "a" * 64)
    client.execution_id = "execution_" + "b" * 64
    return client


class FakeRuntime:
    def __init__(self, *, ok=True, timed_out=False, output="kernel checked", missing=False):
        self.ok = ok
        self.timed_out = timed_out
        self.output = output
        self.missing = missing
        self.checked = []

    def open(self, environment_id):
        if self.missing:
            raise EnvironmentError("managed environment is absent")
        assert environment_id == "env_" + "a" * 64
        return self

    def check_files(self, files, *, entrypoint, policy):
        self.checked.append((files, entrypoint, policy))
        return SimpleNamespace(
            ok=self.ok,
            timed_out=self.timed_out,
            stdout=self.output,
            stderr="",
            elapsed_seconds=0.25,
        )


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


def test_verify_checks_valid_artifact_in_managed_environment(tmp_path):
    project = exported_project(tmp_path)
    runtime = FakeRuntime()
    report = lc.verify_exported_projects([project], runtime=runtime)
    assert report.verified
    assert report.exit_code == lc.VerificationExitCode.SUCCESS
    assert report.artifacts[0].trust_class == "kernel"
    assert (
        report.artifacts[0].claim_id
        == json.loads((project / "artifact.json").read_text(encoding="utf-8"))["claim_id"]
    )
    assert runtime.checked[0][1] == "LeanCertExport.lean"


@pytest.mark.parametrize(
    "kind", ["strict_bound", "system_root", "scalar_root", "integral", "eventual"]
)
def test_verifier_accepts_every_exported_certificate_family(tmp_path, kind):
    if kind == "strict_bound":
        x = ast.var("x")
        result = lc.prove(
            x < 2,
            where={x: (0, 1)},
            client=managed(StrictClient((strict_response(),))),
        )
    elif kind == "system_root":
        result = lc.prove(coupled_claim(), client=managed(FakeSystemRootClient()))
    elif kind == "scalar_root":
        x = ast.var("x")
        result = lc.prove(
            ast.unique_root(x, variable=x, within=(-1, 1)),
            client=managed(FakeScalarRootClient()),
        )
    elif kind == "integral":
        _, integral = integral_expression()
        result = lc.prove(ast.eq(integral, Fraction(1, 3)), client=managed(FakeIntegralClient()))
    else:
        result = lc.prove(reciprocal_claim(), client=managed(FakeEventualClient()))
    project = tmp_path / kind
    assert isinstance(result.export_lean_project(project, verify=False), lc.ExportPrepared)
    report = lc.verify_exported_projects([project], runtime=FakeRuntime())
    assert report.verified, report.to_dict()


def test_recursive_discovery_is_deterministic_and_skips_build_trees(tmp_path):
    second = exported_project(tmp_path / "nested", "b")
    first = exported_project(tmp_path, "a")
    ignored = tmp_path / ".lake" / "hidden"
    ignored.mkdir(parents=True)
    (ignored / "artifact.json").write_text("{}", encoding="utf-8")
    report = lc.verify_exported_projects([tmp_path], runtime=FakeRuntime())
    assert [Path(item.path) for item in report.artifacts] == [first.resolve(), second.resolve()]


def test_tampered_source_is_rejected_before_runtime_runs(tmp_path):
    project = exported_project(tmp_path)
    source = project / "LeanCertExport.lean"
    source.write_text(source.read_text(encoding="utf-8") + "-- tampered\n", encoding="utf-8")
    report = lc.verify_exported_projects([project], runtime=FakeRuntime())
    assert report.exit_code == lc.VerificationExitCode.INVALID_ARTIFACT
    assert "digest mismatch" in report.artifacts[0].message


def test_tampered_certificate_payload_is_rejected_even_with_updated_file_hash(tmp_path):
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
    report = lc.verify_exported_projects([project], runtime=FakeRuntime())
    assert report.exit_code == lc.VerificationExitCode.INVALID_ARTIFACT
    assert "payload digest" in report.artifacts[0].message


def test_tampered_authority_is_rejected_even_with_updated_file_hash(tmp_path):
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
    report = lc.verify_exported_projects([project], runtime=FakeRuntime())
    assert report.exit_code == lc.VerificationExitCode.INVALID_ARTIFACT
    assert "authority" in report.artifacts[0].message


def test_missing_managed_environment_is_an_infrastructure_failure(tmp_path):
    project = exported_project(tmp_path)
    report = lc.verify_exported_projects([project], runtime=FakeRuntime(missing=True))
    assert report.exit_code == lc.VerificationExitCode.INFRASTRUCTURE_FAILURE
    assert report.artifacts[0].status == "infrastructure_failure"


def test_kernel_rejection_is_a_verification_failure(tmp_path):
    project = exported_project(tmp_path)
    report = lc.verify_exported_projects(
        [project], runtime=FakeRuntime(ok=False, output="bad theorem")
    )
    assert report.exit_code == lc.VerificationExitCode.VERIFICATION_FAILED
    assert report.artifacts[0].build_output == "bad theorem"


def test_timeout_has_a_distinct_exit_code(tmp_path):
    project = exported_project(tmp_path)
    report = lc.verify_exported_projects(
        [project],
        runtime=FakeRuntime(ok=False, timed_out=True, output="still building"),
        timeout=1,
    )
    assert report.exit_code == lc.VerificationExitCode.RESOURCE_LIMIT
    assert report.artifacts[0].build_output == "still building"


def test_cli_emits_stable_json_report(tmp_path, monkeypatch, capsys):
    project = exported_project(tmp_path)
    monkeypatch.setattr("leancert.verification.Runtime", FakeRuntime)
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
