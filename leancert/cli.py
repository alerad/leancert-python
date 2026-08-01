"""Command-line entry point for LeanCert Python."""

from __future__ import annotations

import argparse
import json

from .doctor import diagnose


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="leancert")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="diagnose the bundled Lean bridge")
    doctor.add_argument("--bridge", help="explicit path to a lean_bridge binary")
    doctor.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "doctor":
        report = diagnose(args.bridge)
        if args.json:
            print(json.dumps(report.to_dict(), sort_keys=True))
        else:
            for check in report.checks:
                marker = "ok" if check.ok else "FAIL"
                print(f"[{marker}] {check.name}: {check.detail}")
        return 0 if report.healthy else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
