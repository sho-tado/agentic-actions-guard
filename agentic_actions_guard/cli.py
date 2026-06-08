from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import RULE_METADATA, SEVERITY_ORDER, load_allowlist, scan_repository


RULE_DEFAULT_SEVERITY = {
    "UNTRUSTED_INPUT_WITH_SECRETS": "critical",
    "UNTRUSTED_INPUT_TO_AGENT": "high",
    "AGENT_WITH_WRITE_TOKEN": "high",
    "PULL_REQUEST_TARGET_AGENT": "high or critical",
    "WORKFLOW_RUN_AGENT_HANDOFF": "high",
    "AI_OUTPUT_TO_SHELL": "high",
    "AI_GENERATED_CHANGES_PUSHED": "high",
    "AGENT_JOB_RUNS_SHELL": "medium",
    "CHECKOUT_CREDENTIALS_IN_AGENT_JOB": "medium",
    "UNPINNED_AI_ACTION_REF": "medium",
    "MISSING_EXPLICIT_PERMISSIONS": "medium",
    "CURATED_AI_ACTION_DETECTED": "info",
    "AI_ACTION_DETECTED": "info",
}


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
    scan.add_argument(
        "--allowlist-max-expiry-days",
        type=int,
        default=None,
        help="Reject allowlist entries whose expires date is more than this many days in the future.",
    )
    scan.add_argument(
        "--allowlist-require-removal-condition",
        action="store_true",
        help="Reject allowlist entries that do not document the condition for removing the accepted risk.",
    )

    validate_allowlist = subcommands.add_parser(
        "validate-allowlist",
        help="Validate an accepted-risk allowlist policy without scanning workflows.",
    )
    validate_allowlist.add_argument("path", type=Path, help="JSON allowlist policy file.")
    validate_allowlist.add_argument(
        "--max-expiry-days",
        type=int,
        default=None,
        help="Reject entries whose expires date is more than this many days in the future.",
    )
    validate_allowlist.add_argument(
        "--require-removal-condition",
        action="store_true",
        help="Reject entries that do not document the condition for removing the accepted risk.",
    )

    rules = subcommands.add_parser("rules", help="List stable scanner rule IDs.")
    rules.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Rule catalog output format.",
    )
    return parser


def rule_catalog() -> list[dict[str, str]]:
    return [
        {
            "rule": rule_id,
            "severity": RULE_DEFAULT_SEVERITY[rule_id],
            "name": metadata["name"],
            "help": metadata["help"],
        }
        for rule_id, metadata in RULE_METADATA.items()
    ]


def rules_markdown() -> str:
    lines = [
        "| Rule | Severity | Name | Help |",
        "|---|---|---|---|",
    ]
    for rule in rule_catalog():
        lines.append(
            f"| `{rule['rule']}` | {rule['severity']} | {rule['name']} | {rule['help']} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "validate-allowlist":
        try:
            entries = load_allowlist(
                args.path,
                max_expiry_days=args.max_expiry_days,
                require_removal_condition=args.require_removal_condition,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"allowlist error: {exc}", file=sys.stderr)
            return 2
        print(f"allowlist ok: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")
        return 0

    if args.command == "rules":
        if args.format == "json":
            print(json.dumps({"rules": rule_catalog()}, indent=2, ensure_ascii=False))
        else:
            print(rules_markdown())
        return 0

    if args.command != "scan":
        parser.error("unknown command")

    try:
        report = scan_repository(
            args.path,
            allowlist_path=args.allowlist,
            allowlist_max_expiry_days=args.allowlist_max_expiry_days,
            require_allowlist_removal_condition=args.allowlist_require_removal_condition,
        )
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
