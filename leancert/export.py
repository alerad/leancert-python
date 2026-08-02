"""Deterministic standalone Lean export for retained bound certificates."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict
from fractions import Fraction
from pathlib import Path
from typing import Any

from . import ast
from .result import (
    ExportDependencyUnavailable,
    ExportPrepared,
    ExportResourceLimit,
    ExportUnsupported,
    ExportVerificationMismatch,
    ExportVerified,
    LeanProjectArtifact,
    ReplayableBoundCertificate,
    ReplayableEventualCertificate,
    ReplayableKrawczykCertificate,
    Verified,
    VerifiedEventualBound,
    VerifiedSystemRoot,
)
from .verification import write_export_manifest


def _rat(value: Fraction) -> str:
    if value.denominator == 1:
        return f"({value.numerator} : ℚ)"
    return f"({value.numerator} / {value.denominator} : ℚ)"


def _core_expression(node: Any) -> str:
    kind = node["kind"]
    if kind == "const":
        return f"(.const {_rat(Fraction(node['val']['n'], node['val']['d']))})"
    if kind == "var":
        return f"(.var {node['idx']})"
    if kind in {"add", "mul"}:
        return f"(.{kind} {_core_expression(node['e1'])} {_core_expression(node['e2'])})"
    if kind in {
        "neg",
        "inv",
        "sin",
        "cos",
        "exp",
        "log",
        "sqrt",
        "atan",
        "arsinh",
        "atanh",
        "sinc",
        "erf",
        "sinh",
        "cosh",
        "tanh",
    }:
        return f"(.{kind} {_core_expression(node['e'])})"
    if kind == "named_const":
        name = "pi" if node["name"] == "pi" else "eulerMascheroni"
        return f"(.namedConst .{name})"
    raise ValueError(f"core expression kind {kind!r} is not globally exportable")


def _support_proof(node: Any) -> str:
    kind = node["kind"]
    if kind == "const":
        value = Fraction(node["val"]["n"], node["val"]["d"])
        return f"(ADSupported.const {_rat(value)})"
    if kind == "var":
        return f"(ADSupported.var {node['idx']})"
    if kind in {"add", "mul"}:
        return f"(ADSupported.{kind} {_support_proof(node['e1'])} {_support_proof(node['e2'])})"
    if kind in {"neg", "sin", "cos", "exp"}:
        return f"(ADSupported.{kind} {_support_proof(node['e'])})"
    raise ValueError(f"core expression kind {kind!r} has no global-support proof")


def _interval(value: Any) -> str:
    return "{ lo := " + _rat(value.lo) + ", hi := " + _rat(value.hi) + ", le := by norm_num }"


def _render_project(certificates: tuple[ReplayableBoundCertificate, ...]) -> str:
    expression = _core_expression(certificates[0].expression)
    support = _support_proof(certificates[0].expression)
    domain = ",\n  ".join(_interval(item) for item in certificates[0].box)
    lines = [
        "import LeanCert.Validity.Bounds",
        "import LeanCert.Tactic.Verification",
        "",
        "open LeanCert.Core LeanCert.Engine LeanCert.Engine.Optimization",
        "",
        "namespace LeanCertExport",
        "",
        f"def expression : Expr := {expression}",
        "",
        "def domain : Box := [",
        f"  {domain}",
        "]",
        "",
        "theorem expression_supported : ADSupported expression := by",
        "  unfold expression",
        f"  exact {support}",
        "",
    ]
    for index, certificate in enumerate(certificates):
        cfg = certificate.config
        expected_checker = (
            "LeanCert.Validity.GlobalOpt.checkGlobalUpperBound"
            if certificate.direction == "upper"
            else "LeanCert.Validity.GlobalOpt.checkGlobalLowerBound"
        )
        expected_verifier = (
            "LeanCert.Validity.GlobalOpt.verify_global_upper_bound"
            if certificate.direction == "upper"
            else "LeanCert.Validity.GlobalOpt.verify_global_lower_bound"
        )
        if certificate.checker != expected_checker or certificate.verifier != expected_verifier:
            raise ValueError("certificate checker or verifier is not the supported bound authority")
        lines.extend(
            [
                f"def config_{index} : GlobalOptConfig := {{",
                f"  maxIterations := {cfg.max_iterations}",
                f"  tolerance := {_rat(cfg.tolerance)}",
                f"  useMonotonicity := {str(cfg.use_monotonicity).lower()}",
                f"  taylorDepth := {cfg.taylor_depth}",
                "}",
                "",
                f"theorem certificate_{index} :",
                f"    {expected_checker} expression domain {_rat(certificate.bound)} "
                f"config_{index} = true := by",
                "  decide +kernel",
                "",
                f"theorem exported_claim_{index} :",
                "    ∀ (ρ : Nat → ℝ), Box.envMem ρ domain →",
                "      (∀ i, i ≥ domain.length → ρ i = 0) →",
                (
                    f"      Expr.eval ρ expression ≤ (({_rat(certificate.bound)}) : ℝ) :="
                    if certificate.direction == "upper"
                    else f"      (({_rat(certificate.bound)}) : ℝ) ≤ Expr.eval ρ expression :="
                ),
                f"  {expected_verifier}",
                f"    expression expression_supported domain {_rat(certificate.bound)} "
                f"config_{index} certificate_{index}",
                "",
                f"#assert_trust kernel exported_claim_{index}",
                "",
            ]
        )
    lines.extend(["end LeanCertExport", ""])
    return "\n".join(lines)


def _jsonable(value: Any) -> Any:
    if isinstance(value, Fraction):
        return {"n": value.numerator, "d": value.denominator}
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if hasattr(value, "items"):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def export_verified_bound(result: Verified, path: str, *, verify: bool = True):
    """Create a fixed-certificate project and optionally rebuild it in kernel mode."""
    certificates = tuple(check.replay_certificate for check in result.checks)
    if not certificates or any(item is None for item in certificates):
        return ExportUnsupported(
            "every checked bound requires a replayable bound-check/2 certificate"
        )
    replay = tuple(item for item in certificates if item is not None)
    if any(item.expression != replay[0].expression or item.box != replay[0].box for item in replay):
        return ExportUnsupported("two-sided export requires one shared expression and box")
    provenance = result.provenance
    if not all(
        (
            provenance.lean_toolchain,
            provenance.leancert_source,
            provenance.leancert_resolved_revision,
        )
    ):
        return ExportUnsupported("bridge provenance lacks Contract 2.1 dependency identities")
    if provenance.leancert_source != "https://github.com/alerad/leancert.git":
        return ExportUnsupported("export requires the canonical LeanCert repository")
    assert provenance.leancert_resolved_revision is not None
    assert provenance.lean_toolchain is not None
    if re.fullmatch(r"[0-9a-f]{40}", provenance.leancert_resolved_revision) is None:
        return ExportUnsupported("LeanCert dependency is not pinned to a full Git revision")
    if re.fullmatch(r"leanprover/lean4:v[0-9]+\.[0-9]+\.[0-9]+", provenance.lean_toolchain) is None:
        return ExportUnsupported("Lean dependency is not a canonical released toolchain")
    try:
        lean_source = _render_project(replay)
    except ValueError as exc:
        return ExportUnsupported(str(exc))

    output = Path(path).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"export destination already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    claim_id = str(result.claim_id)
    artifact = LeanProjectArtifact(
        str(output), claim_id, tuple(item.payload_digest for item in replay)
    )
    lakefile = (
        'name = "LeanCertExport"\n'
        'version = "0.1.0"\n\n'
        'defaultTargets = ["LeanCertExport"]\n\n'
        "[[require]]\n"
        'name = "leancert"\n'
        f'git = "{provenance.leancert_source}"\n'
        f'rev = "{provenance.leancert_resolved_revision}"\n\n'
        "[[lean_lib]]\n"
        'name = "LeanCertExport"\n'
    )
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=str(output.parent))).resolve()
    try:
        (staging / "lean-toolchain").write_text(f"{provenance.lean_toolchain}\n", encoding="utf-8")
        (staging / "lakefile.toml").write_text(lakefile, encoding="utf-8")
        (staging / "LeanCertExport.lean").write_text(lean_source, encoding="utf-8")
        (staging / "claim.json").write_text(
            json.dumps(ast.encode_canonical(result.normalized_claim), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        (staging / "certificate.json").write_text(
            json.dumps(
                {
                    "claim_id": claim_id,
                    "certificates": [
                        {
                            "schema_version": item.schema_version,
                            "payload_digest": item.payload_digest,
                            "checker": item.checker,
                            "verifier": item.verifier,
                            "verification_route": item.verification_route,
                            "payload": _jsonable(item.canonical_payload),
                        }
                        for item in replay
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (staging / "provenance.json").write_text(
            json.dumps(_jsonable(asdict(provenance)), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (staging / "README.md").write_text(
            "# LeanCert exported claim\n\n"
            "This project replays the fixed bound checker input retained by the Python SDK.\n\n"
            "```bash\nlake update\nlake build\n```\n",
            encoding="utf-8",
        )
        write_export_manifest(
            staging,
            claim_id=claim_id,
            certificate_digests=artifact.certificate_digests,
        )
        if verify:
            lake = shutil.which("lake")
            if lake is None:
                return ExportDependencyUnavailable("lake is not available on PATH")
            try:
                process = subprocess.run(
                    [lake, "build", "LeanCertExport"],
                    cwd=staging,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=900,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                output_text = exc.stdout or ""
                if isinstance(output_text, bytes):
                    output_text = output_text.decode(errors="replace")
                return ExportResourceLimit(
                    artifact,
                    "kernel replay exceeded the export time limit",
                    900,
                    output_text,
                )
            if process.returncode != 0:
                return ExportVerificationMismatch(
                    artifact, "exported project did not kernel-check", process.stdout
                )
        staging.rename(output)
        staging = output
        if not verify:
            return ExportPrepared(artifact)
        return ExportVerified(artifact, "kernel", process.stdout)
    finally:
        if staging != output and staging.exists():
            shutil.rmtree(staging)


def _render_krawczyk_project(certificate: ReplayableKrawczykCertificate) -> str:
    if (
        certificate.checker != "LeanCert.Engine.krawczykCheck"
        or certificate.verifier != "LeanCert.Validity.verify_unique_system_root"
    ):
        raise ValueError("certificate authority is not the supported Krawczyk boundary")
    dimension = len(certificate.system)
    system = ",\n  ".join(_core_expression(item) for item in certificate.system)
    box = ",\n  ".join(_interval(item) for item in certificate.box)
    center = ", ".join(_rat(item) for item in certificate.center)
    rows = "; ".join(", ".join(_rat(item) for item in row) for row in certificate.preconditioner)
    return "\n".join(
        [
            "import LeanCert.Validity.Krawczyk",
            "import LeanCert.Tactic.Verification",
            "",
            "open LeanCert.Core LeanCert.Engine LeanCert.Validity",
            "",
            "namespace LeanCertExport",
            "",
            f"def system : Fin {dimension} → Expr := ![",
            f"  {system}",
            "]",
            "",
            f"def box : Fin {dimension} → IntervalRat := ![",
            f"  {box}",
            "]",
            "",
            f"def certificate : KrawczykCert {dimension} where",
            f"  center := ![{center}]",
            f"  preconditioner := !![{rows}]",
            "",
            "def config : EvalConfig := {",
            f"  taylorDepth := {certificate.taylor_depth}",
            "}",
            "",
            "theorem certificate_check :",
            "    krawczykCheck system box certificate config = true := by",
            "  decide +kernel",
            "",
            "theorem exported_claim :",
            "    ∃! x, FinBoxMem x box ∧ SystemZero system x :=",
            "  verify_unique_system_root system box certificate config certificate_check",
            "",
            "#assert_trust kernel exported_claim",
            "",
            "end LeanCertExport",
            "",
        ]
    )


def export_verified_system_root(result: VerifiedSystemRoot, path: str, *, verify: bool = True):
    """Create a standalone fixed Krawczyk project and optionally kernel-check it."""
    certificate = result.certificate
    provenance = result.provenance
    if not all(
        (
            provenance.lean_toolchain,
            provenance.leancert_source,
            provenance.leancert_resolved_revision,
        )
    ):
        return ExportUnsupported("bridge provenance lacks dependency identities")
    if provenance.leancert_source != "https://github.com/alerad/leancert.git":
        return ExportUnsupported("export requires the canonical LeanCert repository")
    assert provenance.leancert_resolved_revision is not None
    assert provenance.lean_toolchain is not None
    if re.fullmatch(r"[0-9a-f]{40}", provenance.leancert_resolved_revision) is None:
        return ExportUnsupported("LeanCert dependency is not pinned to a full Git revision")
    try:
        lean_source = _render_krawczyk_project(certificate)
    except ValueError as exc:
        return ExportUnsupported(str(exc))

    output = Path(path).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"export destination already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    artifact = LeanProjectArtifact(str(output), str(result.claim_id), (certificate.payload_digest,))
    lakefile = (
        'name = "LeanCertExport"\n'
        'version = "0.1.0"\n\n'
        'defaultTargets = ["LeanCertExport"]\n\n'
        "[[require]]\n"
        'name = "leancert"\n'
        f'git = "{provenance.leancert_source}"\n'
        f'rev = "{provenance.leancert_resolved_revision}"\n\n'
        "[[lean_lib]]\n"
        'name = "LeanCertExport"\n'
    )
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=str(output.parent))).resolve()
    try:
        (staging / "lean-toolchain").write_text(f"{provenance.lean_toolchain}\n", encoding="utf-8")
        (staging / "lakefile.toml").write_text(lakefile, encoding="utf-8")
        (staging / "LeanCertExport.lean").write_text(lean_source, encoding="utf-8")
        (staging / "claim.json").write_text(
            json.dumps(ast.encode_canonical(result.normalized_claim), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        (staging / "certificate.json").write_text(
            json.dumps(
                {
                    "claim_id": str(result.claim_id),
                    "schema_version": certificate.schema_version,
                    "payload_digest": certificate.payload_digest,
                    "checker": certificate.checker,
                    "verifier": certificate.verifier,
                    "verification_route": certificate.verification_route,
                    "payload": _jsonable(certificate.canonical_payload),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (staging / "provenance.json").write_text(
            json.dumps(_jsonable(asdict(provenance)), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (staging / "README.md").write_text(
            "# LeanCert exported unique system root\n\n"
            "This project replays a fixed rational Krawczyk certificate.\n\n"
            "```bash\nlake update\nlake build\n```\n",
            encoding="utf-8",
        )
        write_export_manifest(
            staging,
            claim_id=artifact.claim_id,
            certificate_digests=artifact.certificate_digests,
        )
        if verify:
            lake = shutil.which("lake")
            if lake is None:
                return ExportDependencyUnavailable("lake is not available on PATH")
            try:
                process = subprocess.run(
                    [lake, "build", "LeanCertExport"],
                    cwd=staging,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=900,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                output_text = exc.stdout or ""
                if isinstance(output_text, bytes):
                    output_text = output_text.decode(errors="replace")
                return ExportResourceLimit(
                    artifact, "kernel replay exceeded the export time limit", 900, output_text
                )
            if process.returncode != 0:
                return ExportVerificationMismatch(
                    artifact, "exported project did not kernel-check", process.stdout
                )
        staging.rename(output)
        staging = output
        if not verify:
            return ExportPrepared(artifact)
        return ExportVerified(artifact, "kernel", process.stdout)
    finally:
        if staging != output and staging.exists():
            shutil.rmtree(staging)


def _render_eventual_project(certificate: ReplayableEventualCertificate) -> str:
    if (
        certificate.checker != "LeanCert.Validity.checkReciprocalPowerUpper"
        or certificate.verifier != "LeanCert.Validity.verify_reciprocal_power_upper"
    ):
        raise ValueError("certificate authority is not the supported eventual-bound boundary")
    return "\n".join(
        [
            "import LeanCert.Validity.Eventual",
            "import LeanCert.Tactic.Verification",
            "",
            "namespace LeanCertExport",
            "",
            "theorem certificate_check :",
            "    LeanCert.Validity.checkReciprocalPowerUpper",
            f"      {_rat(certificate.coefficient)} {_rat(certificate.bound)}",
            f"      {certificate.exponent} {certificate.cutoff} = true := by",
            "  decide +kernel",
            "",
            "theorem exported_claim :",
            f"    ∀ n : Nat, {certificate.cutoff} ≤ n →",
            f"      (({_rat(certificate.coefficient)}) : ℝ) / (n : ℝ) ^ {certificate.exponent} ≤",
            f"        (({_rat(certificate.bound)}) : ℝ) :=",
            "  LeanCert.Validity.verify_reciprocal_power_upper",
            f"    {_rat(certificate.coefficient)} {_rat(certificate.bound)}",
            f"    {certificate.exponent} {certificate.cutoff} certificate_check",
            "",
            "#assert_trust kernel exported_claim",
            "",
            "end LeanCertExport",
            "",
        ]
    )


def export_verified_eventual_bound(
    result: VerifiedEventualBound, path: str, *, verify: bool = True
):
    """Create a standalone fixed-cutoff project and optionally kernel-check it."""
    certificate = result.certificate
    provenance = result.provenance
    if not all(
        (
            provenance.lean_toolchain,
            provenance.leancert_source,
            provenance.leancert_resolved_revision,
        )
    ):
        return ExportUnsupported("bridge provenance lacks dependency identities")
    if provenance.leancert_source != "https://github.com/alerad/leancert.git":
        return ExportUnsupported("export requires the canonical LeanCert repository")
    assert provenance.leancert_resolved_revision is not None
    assert provenance.lean_toolchain is not None
    if re.fullmatch(r"[0-9a-f]{40}", provenance.leancert_resolved_revision) is None:
        return ExportUnsupported("LeanCert dependency is not pinned to a full Git revision")
    try:
        lean_source = _render_eventual_project(certificate)
    except ValueError as exc:
        return ExportUnsupported(str(exc))

    output = Path(path).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"export destination already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    artifact = LeanProjectArtifact(str(output), str(result.claim_id), (certificate.payload_digest,))
    lakefile = (
        'name = "LeanCertExport"\n'
        'version = "0.1.0"\n\n'
        'defaultTargets = ["LeanCertExport"]\n\n'
        "[[require]]\n"
        'name = "leancert"\n'
        f'git = "{provenance.leancert_source}"\n'
        f'rev = "{provenance.leancert_resolved_revision}"\n\n'
        "[[lean_lib]]\n"
        'name = "LeanCertExport"\n'
    )
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=str(output.parent))).resolve()
    try:
        (staging / "lean-toolchain").write_text(f"{provenance.lean_toolchain}\n", encoding="utf-8")
        (staging / "lakefile.toml").write_text(lakefile, encoding="utf-8")
        (staging / "LeanCertExport.lean").write_text(lean_source, encoding="utf-8")
        (staging / "claim.json").write_text(
            json.dumps(ast.encode_canonical(result.normalized_claim), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        (staging / "certificate.json").write_text(
            json.dumps(
                {
                    "claim_id": str(result.claim_id),
                    "schema_version": certificate.schema_version,
                    "payload_digest": certificate.payload_digest,
                    "checker": certificate.checker,
                    "verifier": certificate.verifier,
                    "verification_route": certificate.verification_route,
                    "payload": _jsonable(certificate.canonical_payload),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (staging / "provenance.json").write_text(
            json.dumps(_jsonable(asdict(provenance)), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (staging / "README.md").write_text(
            "# LeanCert exported eventual bound\n\n"
            "This project replays a fixed reciprocal-power cutoff certificate.\n\n"
            "```bash\nlake update\nlake build\n```\n",
            encoding="utf-8",
        )
        write_export_manifest(
            staging,
            claim_id=artifact.claim_id,
            certificate_digests=artifact.certificate_digests,
        )
        if verify:
            lake = shutil.which("lake")
            if lake is None:
                return ExportDependencyUnavailable("lake is not available on PATH")
            try:
                process = subprocess.run(
                    [lake, "build", "LeanCertExport"],
                    cwd=staging,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=900,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                output_text = exc.stdout or ""
                if isinstance(output_text, bytes):
                    output_text = output_text.decode(errors="replace")
                return ExportResourceLimit(
                    artifact, "kernel replay exceeded the export time limit", 900, output_text
                )
            if process.returncode != 0:
                return ExportVerificationMismatch(
                    artifact, "exported project did not kernel-check", process.stdout
                )
        staging.rename(output)
        staging = output
        if not verify:
            return ExportPrepared(artifact)
        return ExportVerified(artifact, "kernel", process.stdout)
    finally:
        if staging != output and staging.exists():
            shutil.rmtree(staging)


__all__ = [
    "export_verified_bound",
    "export_verified_eventual_bound",
    "export_verified_system_root",
]
