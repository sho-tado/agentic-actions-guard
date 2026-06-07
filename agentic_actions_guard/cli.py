from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import SEVERITY_ORDER, load_allowlist, scan_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentic-actions-guard",
        description="Audit GitHub Actions workflows for risky AI-agent automation patterns.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="Scan a repository or workflow directory.")
    scan.add_argument("path", type=Path, help="Repository root or .github/workflows directory.")
    scan.add_argument(
        "--format",
        choices=("markdown", "json", "sarif", "review", "annotations", "summary"),
        default="markdown",
        help="Output format.",
    )
    scan.add_argument(
        "--review-target",
        default=None,
        help="Human-readable repository or workflow name used in review reports.",
    )
    scan.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER),
        default="critical",
        help="Exit 1 when a finding at or above this severity is present.",
    )
    scan.add_argument(
        "--allowlist",
        type=Path,
        default=None,
        help="Optional JSON policy file with accepted findings to suppress.",
    )

    validate_allowlist = subcommands.add_parser(
        "validate-allowlist",
        help="Validate an accepted-risk allowlist policy without scanning workflows.",
    )
    validate_allowlist.add_argument("path", type=Path, help="JSON allowlist policy file.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "validate-allowlist":
        try:
            entries = load_allowlist(args.path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"allowlist error: {exc}", file=sys.stderr)
            return 2
        print(f"allowlist ok: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")
        return 0

    if args.command != "scan":
        parser.error("unknown command")

    try:
        report = scan_repository(args.path, allowlist_path=args.allowlist)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"scan error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    elif args.format == "sarif":
        print(json.dumps(report.to_sarif(), indent=2, ensure_ascii=False))
    elif args.format == "review":
        print(report.to_review_markdown(target=args.review_target))
    elif args.format == "annotations":
        print(report.to_github_annotations())
    elif args.format == "summary":
        print(report.to_step_summary())
    else:
        print(report.to_markdown())

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in report.findings) else 0
