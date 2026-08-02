"""Command-line entry point for LeanCert Python."""

from __future__ import annotations

import argparse
import json
import sys

from .doctor import diagnose
from .verification import verify_exported_projects


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="leancert")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="diagnose the bundled Lean bridge")
    doctor.add_argument("--bridge", help="explicit path to a lean_bridge binary")
    doctor.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    verify = commands.add_parser("verify", help="independently rebuild exported LeanCert projects")
    verify.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="exported project or directory to search (default: current directory)",
    )
    verify.add_argument(
        "--require-trust",
        choices=("kernel",),
        default="kernel",
        help="required exported theorem trust class (default: kernel)",
    )
    verify.add_argument("--lake", help="explicit path to the lake executable")
    verify.add_argument(
        "--timeout",
        type=float,
        default=900,
        help="per-project build timeout in seconds (default: 900)",
    )
    verify.add_argument("--fail-fast", action="store_true", help="stop after the first failure")
    verify.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "doctor":
        doctor_report = diagnose(args.bridge)
        if args.json:
            print(json.dumps(doctor_report.to_dict(), sort_keys=True))
        else:
            for check in doctor_report.checks:
                marker = "ok" if check.ok else "FAIL"
                print(f"[{marker}] {check.name}: {check.detail}")
        return 0 if doctor_report.healthy else 1
    if args.command == "verify":
        try:
            verification_report = verify_exported_projects(
                args.paths,
                require_trust=args.require_trust,
                lake=args.lake,
                timeout=args.timeout,
                fail_fast=args.fail_fast,
            )
        except ValueError as exc:
            print(f"leancert verify: {exc}", file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(verification_report.to_dict(), sort_keys=True))
        else:
            for artifact in verification_report.artifacts:
                marker = "ok" if artifact.verified else "FAIL"
                trust = f" ({artifact.trust_class})" if artifact.trust_class else ""
                print(f"[{marker}] {artifact.path}{trust}: {artifact.message}")
            print(
                f"{verification_report.verified_count}/"
                f"{len(verification_report.artifacts)} exported claims "
                "independently rebuilt"
            )
        return int(verification_report.exit_code)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
