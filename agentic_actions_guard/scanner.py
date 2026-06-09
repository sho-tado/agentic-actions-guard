from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path
import re


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

RULE_METADATA = {
    "AI_ACTION_DETECTED": {
        "name": "AI action detected",
        "help": "Review AI or agent-like actions before enabling them on public repository events.",
    },
    "CURATED_AI_ACTION_DETECTED": {
        "name": "Curated AI action detected",
        "help": "Review known AI maintainer actions with action-specific guardrails before enabling them on public events.",
    },
    "UNTRUSTED_INPUT_WITH_SECRETS": {
        "name": "Untrusted input with secrets",
        "help": "Separate untrusted event text analysis from privileged jobs that have secrets or write tokens.",
    },
    "UNTRUSTED_INPUT_TO_AGENT": {
        "name": "Untrusted input to agent",
        "help": "Treat issue, pull request, comment, discussion, review, commit text, and caller-supplied workflow inputs as hostile input to AI agents.",
    },
    "AGENT_WITH_WRITE_TOKEN": {
        "name": "Agent with write token",
        "help": "Use least-privilege permissions and split read-only AI analysis from write operations.",
    },
    "MISSING_EXPLICIT_PERMISSIONS": {
        "name": "Missing explicit permissions",
        "help": "Declare workflow or job permissions explicitly, preferably read-only for AI analysis jobs.",
    },
    "PULL_REQUEST_TARGET_AGENT": {
        "name": "Agent on pull_request_target",
        "help": "Avoid running AI agent workflows on pull_request_target, especially with fork code checkout.",
    },
    "AGENT_JOB_RUNS_SHELL": {
        "name": "Agent job runs shell",
        "help": "Constrain shell steps near AI workflows and never interpolate model output into commands.",
    },
    "CHECKOUT_CREDENTIALS_IN_AGENT_JOB": {
        "name": "Checkout credentials in agent job",
        "help": "Disable checkout credential persistence in AI jobs unless git push behavior is explicitly required.",
    },
    "UNPINNED_AI_ACTION_REF": {
        "name": "Unpinned AI action reference",
        "help": "Pin AI maintainer actions to an immutable full-length commit SHA when possible.",
    },
    "AI_OUTPUT_TO_SHELL": {
        "name": "AI output to shell",
        "help": "Do not pass AI step outputs directly into shell commands.",
    },
    "WORKFLOW_RUN_AGENT_HANDOFF": {
        "name": "Workflow run agent handoff",
        "help": "Review workflow_run handoffs before privileged AI follow-up jobs consume artifacts or upstream outputs.",
    },
    "AI_GENERATED_CHANGES_PUSHED": {
        "name": "AI generated changes pushed",
        "help": "Require maintainer review before AI-related jobs commit, push, merge, or publish repository changes.",
    },
}

WORKFLOW_EXTENSIONS = {".yml", ".yaml"}

AI_HINTS = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(ai|agent|codex|openai|claude|anthropic|gemini|qwen|iflow|aptu|copilot|aider|llm|gpt|reviewdog|autofix|triage)"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)
UNTRUSTED_CONTEXT = re.compile(
    r"(?:"
    r"github\.head_ref"
    r"|github\.ref_name"
    r"|github\.event_path"
    r"|GITHUB_EVENT_PATH"
    r"|inputs\.(?:prompt|instruction|instructions|query|body|text|message|review|comment|title|request|task|content|description)"
    r"|github\.event\.(?:"
    r"(?:issue|comment|review|review_comment|discussion|discussion_comment|answer|head_commit)\."
    r"(?:title|body|body_text|message|ref)"
    r"|(?:issue|comment|review|review_comment|discussion|answer|head_commit)(?!\.)"
    r"|commits(?:\[[^\]]+\])?\.(?:message|id)"
    r"|pull_request\.(?:title|body|body_text|ref|head\.(?:ref|label))"
    r"|pull_request(?!\.)"
    r"|(?:inputs|client_payload)\.[A-Za-z0-9_.-]+"
    r")"
    r")",
    re.IGNORECASE,
)
SECRET_CONTEXT = re.compile(
    r"(\$\{\{\s*(?:secrets\.|github\.token\s*\}\})|^\s*secrets:\s*inherit\s*$|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN)",
    re.IGNORECASE | re.MULTILINE,
)
WRITE_PERMISSION = re.compile(
    r"^\s*(contents|issues|pull-requests|actions|checks|deployments|id-token|packages|statuses):\s*write\s*$",
    re.IGNORECASE | re.MULTILINE,
)
WRITE_ALL_PERMISSION = re.compile(r"^\s*permissions:\s*write-all\s*$", re.IGNORECASE | re.MULTILINE)
PERMISSIONS_BLOCK = re.compile(r"^\s*permissions:\s*(\n|$|read-all\s*$|write-all\s*$)", re.IGNORECASE | re.MULTILINE)
PULL_REQUEST_TARGET = re.compile(r"pull_request_target\s*:", re.IGNORECASE)
WORKFLOW_RUN = re.compile(r"workflow_run\s*:", re.IGNORECASE)
CHECKOUT_HEAD_REF = re.compile(
    r"actions/checkout@[\w.\-]+[\s\S]{0,500}(github\.event\.pull_request\.head\.(sha|ref)|ref:\s*\$\{\{)",
    re.IGNORECASE,
)
CHECKOUT_ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*actions/checkout@[\w.\-]+", re.IGNORECASE | re.MULTILINE)
CHECKOUT_PERSIST_CREDENTIALS_FALSE = re.compile(r"persist-credentials:\s*false\s*(#.*)?$", re.IGNORECASE | re.MULTILINE)
RUNS_SHELL = re.compile(r"^\s*(?:-\s*)?run:\s*(\||>|[^\n]+)", re.IGNORECASE | re.MULTILINE)
USES_ACTION = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.IGNORECASE | re.MULTILINE)
FULL_COMMIT_SHA_REF = re.compile(r"@[0-9a-f]{40}$", re.IGNORECASE)
STEP_START = re.compile(r"^\s*-\s+", re.MULTILINE)
STEP_ID = re.compile(r"^\s*(?:-\s*)?id:\s*([A-Za-z0-9_-]+)\s*(#.*)?$", re.IGNORECASE | re.MULTILINE)
JOB_LEVEL_PROMPT_INPUT = re.compile(
    r"^\s*(?:prompt|instruction|instructions|system-prompt|query|model):\s*",
    re.IGNORECASE,
)
REPOSITORY_MUTATION_COMMAND = re.compile(
    r"^\s*(?:-\s*run:\s*)?"
    r"(?:"
    r"git\s+(?:commit|push|tag)"
    r"|gh\s+(?:pr\s+(?:create|merge)|release\s+(?:create|upload)|issue\s+(?:edit|comment))"
    r")\b",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass(frozen=True)
class TextBlock:
    name: str
    text: str
    start_offset: int


@dataclass(frozen=True)
class CuratedActionProfile:
    name: str
    pattern: re.Pattern[str]
    recommendation: str


CURATED_AI_ACTION_PROFILES = [
    CuratedActionProfile(
        name="Anthropic Claude Code Action",
        pattern=re.compile(r"^anthropics/claude-code(-base)?-action(?:@|$)", re.IGNORECASE),
        recommendation=(
            "Keep Claude issue and PR automation read-only by default; require maintainer approval before file writes, "
            "tool expansion, or privileged GitHub token use."
        ),
    ),
    CuratedActionProfile(
        name="Google Gemini CLI Action",
        pattern=re.compile(r"^google-github-actions/run-gemini-cli(?:@|$)", re.IGNORECASE),
        recommendation=(
            "Review Gemini prompts, command arguments, and token scope together; isolate untrusted issue or PR text "
            "from jobs with secrets or write permissions."
        ),
    ),
    CuratedActionProfile(
        name="Qwen Code Action",
        pattern=re.compile(r"^qwenlm/qwen-code-action(?:@|$)", re.IGNORECASE),
        recommendation=(
            "Constrain Qwen Code review and triage jobs to read-only permissions unless a separate trusted workflow "
            "performs the write step."
        ),
    ),
    CuratedActionProfile(
        name="iFlow CLI Action",
        pattern=re.compile(r"^iflow-ai/iflow-cli-action(?:@|$)", re.IGNORECASE),
        recommendation=(
            "Treat iFlow CLI commands as tool-capable agent execution; keep public-event inputs away from secrets, "
            "write tokens, and broad shell mutation steps."
        ),
    ),
    CuratedActionProfile(
        name="GitHub AI Assessment Comment Labeler",
        pattern=re.compile(r"^(?:github/)?ai-assessment-comment-labeler(?:@|$)", re.IGNORECASE),
        recommendation=(
            "Review prompt files, issue body input, comment output, and label writes together; keep assessment jobs "
            "least-privileged and suppress comments or labels until maintainers approve the rollout."
        ),
    ),
    CuratedActionProfile(
        name="Issue AI Agent",
        pattern=re.compile(r"^alexyan0431/issue-ai-agent(?:@|$)", re.IGNORECASE),
        recommendation=(
            "Treat issue triage, duplicate detection, labels, and reply comments as repository mutation; keep tokens "
            "least-privileged and separate untrusted issue bodies from write-capable steps."
        ),
    ),
    CuratedActionProfile(
        name="Aptu",
        pattern=re.compile(r"^clouatre-labs/aptu(?:@|$)", re.IGNORECASE),
        recommendation=(
            "Review Aptu issue triage, PR review, PR labeling, security scan, and queue modes separately; use dry-run "
            "or no-comment options before enabling labels, comments, or write-capable tokens."
        ),
    ),
    CuratedActionProfile(
        name="OpenAI or Codex agent action",
        pattern=re.compile(r"^(openai|[^/\s]+)/(?:.*(?:codex|agent).*)action(?:@|$)", re.IGNORECASE),
        recommendation=(
            "Split OpenAI/Codex agent analysis from repository mutation and explicitly document accepted token and "
            "secret exposure."
        ),
    ),
]


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    path: str
    line: int
    message: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity,
            "rule": self.rule,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class AllowlistEntry:
    rule: str | None = None
    path: str | None = None
    evidence: str | None = None
    reason: str | None = None
    owner: str | None = None
    expires: str | None = None
    rationale: str | None = None
    removal_condition: str | None = None

    def matches(self, finding: Finding) -> bool:
        return (
            _matches_rule(self.rule, finding.rule)
            and _matches_path(self.path, finding.path)
            and _matches_optional(self.evidence, finding.evidence)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            key: value
            for key, value in {
                "rule": self.rule,
                "path": self.path,
                "evidence": self.evidence,
                "reason": self.reason,
                "owner": self.owner,
                "expires": self.expires,
                "rationale": self.rationale,
                "removal_condition": self.removal_condition,
            }.items()
            if value is not None
        }


@dataclass(frozen=True)
class ScanReport:
    root: str
    workflow_count: int
    findings: list[Finding]
    suppressed_findings: list[Finding]
    allowlist_entries: list[AllowlistEntry]

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "workflow_count": self.workflow_count,
            "findings": [finding.to_dict() for finding in self.findings],
            "suppressed_findings": [finding.to_dict() for finding in self.suppressed_findings],
            "suppressions": [
                {"finding": finding.to_dict(), "allowlist_entry": entry.to_dict()}
                for finding, entry in _suppression_rows(self.suppressed_findings, self.allowlist_entries)
            ],
            "allowlist_entries": [entry.to_dict() for entry in self.allowlist_entries],
            "summary": summarize_findings(self.findings),
            "suppressed_summary": summarize_findings(self.suppressed_findings),
        }

    def to_sarif(self) -> dict[str, object]:
        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "agentic-actions-guard",
                            "informationUri": "https://github.com/sho-tado/agentic-actions-guard",
                            "rules": _sarif_rules(self.findings),
                        }
                    },
                    "results": [_sarif_result(finding) for finding in self.findings],
                    "properties": {
                        "root": self.root,
                        "workflowCount": self.workflow_count,
                        "summary": summarize_findings(self.findings),
                        "suppressedSummary": summarize_findings(self.suppressed_findings),
                        "suppressions": _suppression_records(self.suppressed_findings, self.allowlist_entries),
                    },
                }
            ],
        }

    def to_github_annotations(self) -> str:
        lines = []
        for finding in sorted(self.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line)):
            level = _annotation_level(finding.severity)
            title = _escape_command_property(f"{finding.severity.upper()} {finding.rule}")
            path = _escape_command_property(finding.path)
            message = _escape_command_message(f"{finding.message} Recommendation: {finding.recommendation}")
            lines.append(f"::{level} file={path},line={finding.line},title={title}::{message}")
        if not lines and self.suppressed_findings:
            lines.append(
                "::notice title=Agentic Actions Guard::"
                + _escape_command_message(
                    f"No active findings. {len(self.suppressed_findings)} finding(s) were suppressed by allowlist policy."
                )
            )
        elif not lines:
            lines.append(
                "::notice title=Agentic Actions Guard::"
                + _escape_command_message("No risky AI-agent workflow patterns were detected.")
            )
        return "\n".join(lines)

    def to_step_summary(self) -> str:
        summary = summarize_findings(self.findings)
        lines = [
            "## Agentic Actions Guard Summary",
            "",
            f"- Workflows scanned: `{self.workflow_count}`",
            f"- Active findings: `{len(self.findings)}`",
            f"- Suppressed findings: `{len(self.suppressed_findings)}`",
            "",
            "| Severity | Count |",
            "|---|---:|",
        ]
        for severity in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| {severity} | `{summary.get(severity, 0)}` |")

        lines.extend(["", "### Recommended Gate", "", _recommended_gate(summary)])

        top_findings = sorted(self.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line))[:3]
        if top_findings:
            lines.extend(["", "### Top Findings", ""])
            for finding in top_findings:
                lines.append(f"- `{finding.severity}` `{finding.rule}` at `{finding.path}:{finding.line}`")

        rule_counts = _count_by_rule(self.findings)
        if rule_counts:
            lines.extend(["", "### Rule Breakdown", "", "| Rule | Count |", "|---|---:|"])
            for rule, count in rule_counts[:8]:
                lines.append(f"| `{rule}` | `{count}` |")
            if len(rule_counts) > 8:
                remaining = sum(count for _, count in rule_counts[8:])
                lines.append(f"| Other rules | `{remaining}` |")

            lines.extend(["", "### Suggested Next Actions", ""])
            lines.extend(f"{index}. {action}" for index, action in enumerate(_summary_next_actions(summary), start=1))

        if self.suppressed_findings:
            lines.extend(
                [
                    "",
                    "### Allowlist Note",
                    "",
                    f"`{len(self.suppressed_findings)}` finding(s) were suppressed by allowlist policy. Review accepted risks on their documented cadence.",
                ]
            )
            lines.extend(_suppression_summary_lines(self.suppressed_findings, self.allowlist_entries, limit=3))
            lines.extend(_suppression_review_queue_lines(self.suppressed_findings, self.allowlist_entries, limit=5))

        return "\n".join(lines).rstrip()

    def to_markdown(self) -> str:
        summary = summarize_findings(self.findings)
        lines = [
            "# Agentic Actions Guard Report",
            "",
            f"- Root: `{self.root}`",
            f"- Workflows scanned: `{self.workflow_count}`",
            f"- Findings: `{len(self.findings)}`",
            f"- Suppressed findings: `{len(self.suppressed_findings)}`",
            "",
            "## Summary",
            "",
        ]
        for severity in ("critical", "high", "medium", "low", "info"):
            lines.append(f"- {severity}: `{summary.get(severity, 0)}`")
        if not self.findings:
            lines.extend(["", "No risky AI-agent workflow patterns were detected."])
            if self.suppressed_findings:
                lines.extend(["", f"`{len(self.suppressed_findings)}` finding(s) were suppressed by policy."])
                lines.extend(_suppression_detail_lines(self.suppressed_findings, self.allowlist_entries))
            return "\n".join(lines)

        lines.extend(["", "## Findings", ""])
        for finding in sorted(self.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line)):
            lines.extend(
                [
                    f"### {finding.severity.upper()} {finding.rule}",
                    "",
                    f"- Location: `{finding.path}:{finding.line}`",
                    f"- Finding: {finding.message}",
                    f"- Evidence: `{finding.evidence}`",
                    f"- Recommendation: {finding.recommendation}",
                    "",
                ]
            )
        if self.suppressed_findings:
            lines.extend(["", "## Suppressed Findings", ""])
            lines.extend(_suppression_detail_lines(self.suppressed_findings, self.allowlist_entries))
            lines.extend(["", "## Accepted Risk Review Queue", ""])
            lines.extend(_suppression_review_queue_lines(self.suppressed_findings, self.allowlist_entries, limit=10))
        return "\n".join(lines).rstrip()

    def to_review_markdown(self, target: str | None = None) -> str:
        summary = summarize_findings(self.findings)
        display_target = target or self.root
        lines = [
            "# Agentic Actions Guard Review",
            "",
            "## Scope",
            "",
            f"- Target: `{display_target}`",
            f"- Workflows scanned: `{self.workflow_count}`",
            f"- Findings: `{len(self.findings)}`",
            f"- Suppressed findings: `{len(self.suppressed_findings)}`",
            "",
            "## Severity Summary",
            "",
        ]
        for severity in ("critical", "high", "medium", "low", "info"):
            lines.append(f"- {severity}: `{summary.get(severity, 0)}`")

        lines.extend(["", "## Maintainer Takeaway", ""])
        if summary["critical"] or summary["high"]:
            lines.append(
                "This workflow set has high-impact AI-agent automation risks. Prioritize separating untrusted GitHub event text from jobs that have secrets, write permissions, privileged events, or shell execution."
            )
        elif summary["medium"]:
            lines.append(
                "No high-impact AI-agent workflow risks were detected, but there are medium-severity hardening opportunities worth reviewing before enabling stricter CI gates."
            )
        else:
            lines.append(
                "No risky AI-agent workflow patterns were detected by the current scanner rules. Keep AI jobs read-only by default and re-run this review when workflow automation changes."
            )
        if self.suppressed_findings:
            lines.extend(
                [
                    "",
                    f"Policy note: `{len(self.suppressed_findings)}` finding(s) were suppressed by allowlist policy. Review accepted risks periodically.",
                ]
            )
            lines.extend(_suppression_summary_lines(self.suppressed_findings, self.allowlist_entries, limit=5))
            lines.extend(_suppression_review_queue_lines(self.suppressed_findings, self.allowlist_entries, limit=5))

        top_findings = sorted(self.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line))[:5]
        if top_findings:
            lines.extend(["", "## Top Findings", ""])
            for finding in top_findings:
                lines.extend(
                    [
                        f"### {finding.severity.upper()} {finding.rule}",
                        "",
                        f"- Location: `{finding.path}:{finding.line}`",
                        f"- Evidence: `{finding.evidence}`",
                        f"- Risk: {finding.message}",
                        f"- Suggested fix: {finding.recommendation}",
                        "",
                    ]
                )
            remaining_findings = sorted(self.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line))[5:]
            if remaining_findings:
                lines.extend(["## Additional Findings Summary", ""])
                for rule, count in _count_by_rule(remaining_findings):
                    lines.append(f"- `{rule}`: `{count}` additional finding(s)")
                lines.append("")

        lines.extend(
            [
                "## Recommended Next Steps",
                "",
                "1. Keep AI analysis jobs at `contents: read` whenever possible.",
                "2. Move write actions into a separate maintainer-approved job or workflow.",
                "3. Do not expose secrets to jobs that process issue, PR, comment, review, or commit text.",
                "4. Avoid `pull_request_target` for agent workflows unless the privileged path is tightly constrained.",
                "5. Start CI gating at `--fail-on critical`, then move to `high` after expected findings are fixed.",
                "",
                "## Reproduce",
                "",
                "```powershell",
                "python -m agentic_actions_guard scan . --format review --fail-on critical",
                "```",
            ]
        )
        return "\n".join(lines).rstrip()


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    summary = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        summary[finding.severity] += 1
    return summary


def _count_by_rule(findings: list[Finding]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.rule] = counts.get(finding.rule, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def _suppression_rows(
    suppressed_findings: list[Finding],
    allowlist_entries: list[AllowlistEntry],
) -> list[tuple[Finding, AllowlistEntry]]:
    rows: list[tuple[Finding, AllowlistEntry]] = []
    for finding in suppressed_findings:
        entry = next((candidate for candidate in allowlist_entries if candidate.matches(finding)), None)
        if entry is not None:
            rows.append((finding, entry))
    return rows


def _suppression_records(
    suppressed_findings: list[Finding],
    allowlist_entries: list[AllowlistEntry],
) -> list[dict[str, object]]:
    return [
        {
            "rule": finding.rule,
            "severity": finding.severity,
            "path": finding.path,
            "line": finding.line,
            "evidence": finding.evidence,
            "reason": entry.reason,
            "owner": entry.owner,
            "expires": entry.expires,
            "rationale": entry.rationale,
            "removalCondition": entry.removal_condition,
        }
        for finding, entry in _suppression_rows(suppressed_findings, allowlist_entries)
    ]


def _suppression_summary_lines(
    suppressed_findings: list[Finding],
    allowlist_entries: list[AllowlistEntry],
    *,
    limit: int,
) -> list[str]:
    rows = _suppression_rows(suppressed_findings, allowlist_entries)
    lines = ["", "Suppressed accepted risks:"]
    for finding, entry in rows[:limit]:
        lines.append(
            f"- `{finding.rule}` at `{finding.path}:{finding.line}`: {entry.reason} "
            f"(owner: `{entry.owner}`, expires: `{entry.expires}`)"
        )
    if len(rows) > limit:
        lines.append(f"- `{len(rows) - limit}` additional suppressed finding(s)")
    return lines


def _suppression_detail_lines(
    suppressed_findings: list[Finding],
    allowlist_entries: list[AllowlistEntry],
) -> list[str]:
    lines: list[str] = []
    for finding, entry in _suppression_rows(suppressed_findings, allowlist_entries):
        lines.extend(
            [
                f"### {finding.severity.upper()} {finding.rule}",
                "",
                f"- Location: `{finding.path}:{finding.line}`",
                f"- Evidence: `{finding.evidence}`",
                f"- Allowlist reason: {entry.reason}",
                f"- Owner: `{entry.owner}`",
                f"- Expires: `{entry.expires}`",
                f"- Rationale: {entry.rationale}",
                *([f"- Removal condition: {entry.removal_condition}"] if entry.removal_condition else []),
                "",
            ]
        )
    return lines


def _suppression_review_queue_lines(
    suppressed_findings: list[Finding],
    allowlist_entries: list[AllowlistEntry],
    *,
    limit: int,
) -> list[str]:
    rows = sorted(
        _suppression_rows(suppressed_findings, allowlist_entries),
        key=lambda row: (
            row[1].expires or "",
            -SEVERITY_ORDER[row[0].severity],
            row[0].path,
            row[0].line,
            row[0].rule,
        ),
    )
    if not rows:
        return []

    lines = ["", "Accepted risk review queue:"]
    for finding, entry in rows[:limit]:
        lines.append(
            f"- `{entry.expires}` `{finding.rule}` at `{finding.path}:{finding.line}` "
            f"(owner: `{entry.owner}`): {entry.rationale}"
        )
    if len(rows) > limit:
        lines.append(f"- `{len(rows) - limit}` additional accepted risk(s)")
    return lines


def _recommended_gate(summary: dict[str, int]) -> str:
    if summary["critical"]:
        return (
            "Keep CI at `--fail-on critical` and separate untrusted event text from secrets or privileged tokens before tightening the gate."
        )
    if summary["high"]:
        return (
            "Run in report-only or annotations mode, review high findings, then move CI to `--fail-on high` after expected risks are fixed or explicitly accepted."
        )
    if summary["medium"]:
        return "Use annotations or SARIF with `--fail-on high`; track medium findings as hardening tasks."
    return "No active high-risk AI workflow boundary was detected. Re-run the scan whenever AI workflow automation changes."


def _summary_next_actions(summary: dict[str, int]) -> list[str]:
    if summary["critical"]:
        return [
            "Split jobs that process untrusted public event text away from secrets or privileged token contexts.",
            "Keep the first rollout at `--fail-on critical` until critical findings are fixed or removed.",
            "Use `--format review` for a maintainer-facing report before enabling stricter gates.",
        ]
    if summary["high"]:
        return [
            "Review high findings for write tokens, privileged events, AI output to shell, or repository mutation.",
            "Keep AI analysis read-only and move writes into maintainer-approved jobs.",
            "Move to `--fail-on high` only after expected high findings are fixed or explicitly accepted.",
        ]
    if summary["medium"]:
        return [
            "Review medium findings for missing explicit permissions, checkout credentials, and mutable AI action refs.",
            "Document any temporary accepted risk with an owner, expiry date, rationale, and removal condition.",
            "Re-run the scan after hardening before enabling stricter CI gates.",
        ]
    return [
        "Keep monitoring enabled for workflow changes.",
        "Re-run the scan whenever AI actions, prompts, permissions, or token scopes change.",
        "Use review reports for periodic maintainer checks even when CI stays green.",
    ]


def load_allowlist(
    path: Path | None,
    max_expiry_days: int | None = None,
    require_removal_condition: bool = False,
) -> list[AllowlistEntry]:
    if path is None:
        return []
    if max_expiry_days is not None and max_expiry_days < 0:
        raise ValueError("max_expiry_days must be non-negative")
    policy = json.loads(path.read_text(encoding="utf-8"))
    entries = policy.get("allowlist", [])
    if not isinstance(entries, list):
        raise ValueError("allowlist policy must contain an 'allowlist' array")

    allowlist: list[AllowlistEntry] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"allowlist entry {index} must be an object")
        _require_allowlist_matcher(entry, index)
        allowlist.append(
            AllowlistEntry(
                rule=_optional_string(entry, "rule"),
                path=_optional_string(entry, "path"),
                evidence=_optional_string(entry, "evidence"),
                reason=_required_reason(entry, index),
                owner=_required_non_empty_string(entry, "owner", index),
                expires=_required_expires(entry, index, max_expiry_days=max_expiry_days),
                rationale=_required_non_empty_string(entry, "rationale", index),
                removal_condition=_removal_condition(entry, index, required=require_removal_condition),
            )
        )
    return allowlist


def _require_allowlist_matcher(entry: dict[str, object], index: int) -> None:
    if not any(_optional_string(entry, key) is not None for key in ("rule", "path", "evidence")):
        raise ValueError(f"allowlist entry {index} must include at least one matcher: 'rule', 'path', or 'evidence'")
    rule = _optional_string(entry, "rule")
    if rule is not None and rule not in RULE_METADATA:
        raise ValueError(f"allowlist entry {index} references unknown rule '{rule}'")


def _required_reason(entry: dict[str, object], index: int) -> str:
    return _required_non_empty_string(entry, "reason", index)


def _removal_condition(entry: dict[str, object], index: int, *, required: bool) -> str | None:
    if required:
        return _required_non_empty_string(entry, "removal_condition", index)
    value = _optional_string(entry, "removal_condition")
    if value is not None and not value.strip():
        raise ValueError(f"allowlist entry {index} must include a non-empty 'removal_condition'")
    return value


def _required_non_empty_string(entry: dict[str, object], key: str, index: int) -> str:
    value = _optional_string(entry, key)
    if value is None or not value.strip():
        raise ValueError(f"allowlist entry {index} must include a non-empty '{key}'")
    return value


def _required_expires(entry: dict[str, object], index: int, max_expiry_days: int | None = None) -> str:
    expires = _required_non_empty_string(entry, "expires", index)
    try:
        expires_date = date.fromisoformat(expires)
    except ValueError as exc:
        raise ValueError(f"allowlist entry {index} must include 'expires' as YYYY-MM-DD") from exc
    if expires_date < date.today():
        raise ValueError(f"allowlist entry {index} expired on {expires}")
    if max_expiry_days is not None and (expires_date - date.today()).days > max_expiry_days:
        raise ValueError(
            f"allowlist entry {index} expires on {expires}, beyond the allowed {max_expiry_days} day window"
        )
    return expires


def _optional_string(entry: dict[str, object], key: str) -> str | None:
    value = entry.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"allowlist field '{key}' must be a string")
    return value


def _matches_optional(pattern: str | None, value: str) -> bool:
    if pattern is None:
        return True
    return pattern == value or pattern in value


def _matches_rule(pattern: str | None, value: str) -> bool:
    if pattern is None:
        return True
    return pattern == value


def _matches_path(pattern: str | None, value: str) -> bool:
    if pattern is None:
        return True
    normalized_pattern = _normalize_match_path(pattern)
    normalized_value = _normalize_match_path(value)
    return normalized_pattern == normalized_value or normalized_pattern in normalized_value


def _normalize_match_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _apply_allowlist(
    findings: list[Finding],
    allowlist_entries: list[AllowlistEntry],
) -> tuple[list[Finding], list[Finding]]:
    if not allowlist_entries:
        return findings, []
    active: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        if any(entry.matches(finding) for entry in allowlist_entries):
            suppressed.append(finding)
        else:
            active.append(finding)
    return active, suppressed


def _sarif_rules(findings: list[Finding]) -> list[dict[str, object]]:
    rule_ids = sorted({finding.rule for finding in findings})
    return [_sarif_rule(rule_id) for rule_id in rule_ids]


def _sarif_rule(rule_id: str) -> dict[str, object]:
    metadata = RULE_METADATA.get(rule_id, {"name": rule_id, "help": "Review this workflow finding."})
    return {
        "id": rule_id,
        "name": metadata["name"],
        "shortDescription": {"text": metadata["name"]},
        "fullDescription": {"text": metadata["help"]},
        "help": {"text": metadata["help"]},
    }


def _sarif_result(finding: Finding) -> dict[str, object]:
    return {
        "ruleId": finding.rule,
        "level": _sarif_level(finding.severity),
        "message": {"text": f"{finding.message} Recommendation: {finding.recommendation}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path.replace("\\", "/")},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": 1,
                    },
                }
            }
        ],
        "properties": {
            "severity": finding.severity,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
        },
    }


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _annotation_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "notice"


def _escape_command_property(value: str) -> str:
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _escape_command_message(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def scan_repository(
    path: Path,
    allowlist_path: Path | None = None,
    *,
    allowlist_max_expiry_days: int | None = None,
    require_allowlist_removal_condition: bool = False,
) -> ScanReport:
    root = path.resolve()
    allowlist_entries = load_allowlist(
        allowlist_path,
        max_expiry_days=allowlist_max_expiry_days,
        require_removal_condition=require_allowlist_removal_condition,
    )
    workflows = list(_iter_workflows(root))
    findings: list[Finding] = []
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8", errors="replace")
        rel_path = str(workflow.relative_to(root if root.is_dir() else root.parent)).replace("\\", "/")
        findings.extend(_scan_workflow(rel_path, text))
    active_findings, suppressed_findings = _apply_allowlist(findings, allowlist_entries)
    return ScanReport(
        root=str(root),
        workflow_count=len(workflows),
        findings=active_findings,
        suppressed_findings=suppressed_findings,
        allowlist_entries=allowlist_entries,
    )


def _iter_workflows(root: Path) -> list[Path]:
    if root.is_file() and root.suffix.lower() in WORKFLOW_EXTENSIONS:
        return [root]
    if root.name == "workflows":
        search_root = root
    else:
        search_root = root / ".github" / "workflows"
    if not search_root.exists():
        return []
    return sorted(p for p in search_root.rglob("*") if p.suffix.lower() in WORKFLOW_EXTENSIONS)


def _scan_workflow(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    job_blocks = _job_blocks(text)
    ai_job_blocks = [block for block in job_blocks if _is_ai_job_block(block)]
    ai_matches = list(AI_HINTS.finditer(text))
    has_ai = bool(ai_job_blocks) or (not job_blocks and bool(ai_matches))
    risk_scope_blocks = ai_job_blocks if ai_job_blocks else []
    untrusted_match = _first_scoped_match(UNTRUSTED_CONTEXT, text, risk_scope_blocks) if has_ai else None
    has_untrusted = untrusted_match is not None
    secret_match = _ai_secret_match(text, risk_scope_blocks) if has_ai else None
    has_secret = secret_match is not None
    write_permission = _ai_write_permission(text, risk_scope_blocks) if has_ai else None
    has_permissions_block = _has_ai_permissions_block(text, risk_scope_blocks) if has_ai else False
    has_pull_request_target = bool(PULL_REQUEST_TARGET.search(text))
    has_workflow_run = bool(WORKFLOW_RUN.search(text))
    has_checkout_head_ref = bool(CHECKOUT_HEAD_REF.search(text))
    shell_match = _first_scoped_match(RUNS_SHELL, text, risk_scope_blocks) if has_ai else None
    has_shell = shell_match is not None
    checkout_credentials_match = _checkout_credentials_match(risk_scope_blocks) if has_ai else None
    ai_output_shell_match = _ai_output_to_shell_match(risk_scope_blocks) if has_ai else None
    repository_mutation_match = _ai_repository_mutation_match(risk_scope_blocks) if has_ai else None

    for match in USES_ACTION.finditer(text):
        action = match.group(1)
        if AI_HINTS.search(action):
            profile = _curated_action_profile(action)
            if profile is not None:
                findings.append(
                    _finding(
                        "info",
                        "CURATED_AI_ACTION_DETECTED",
                        path,
                        text,
                        match.start(),
                        f"Workflow uses a known AI maintainer action: {profile.name}.",
                        action,
                        profile.recommendation,
                    )
                )
                if not _is_pinned_action_ref(action):
                    findings.append(
                        _finding(
                            "medium",
                            "UNPINNED_AI_ACTION_REF",
                            path,
                            text,
                            match.start(),
                            "Workflow uses an AI maintainer action without an immutable commit SHA pin.",
                            action,
                            "Pin AI maintainer actions to a reviewed full-length commit SHA and update intentionally.",
                        )
                    )
                continue
            findings.append(
                _finding(
                    "info",
                    "AI_ACTION_DETECTED",
                    path,
                    text,
                    match.start(),
                    "Workflow uses an AI or agent-like action.",
                    action,
                    "Review the action's permissions, prompt inputs, and secret exposure before enabling it on public events.",
                )
            )
            if not _is_pinned_action_ref(action):
                findings.append(
                    _finding(
                        "medium",
                        "UNPINNED_AI_ACTION_REF",
                        path,
                        text,
                        match.start(),
                        "Workflow uses an AI or agent-like action without an immutable commit SHA pin.",
                        action,
                        "Pin AI maintainer actions to a reviewed full-length commit SHA and update intentionally.",
                    )
                )

    if has_ai and has_untrusted and has_secret:
        match_text, match_offset = untrusted_match
        findings.append(
            _finding(
                "critical",
                "UNTRUSTED_INPUT_WITH_SECRETS",
                path,
                text,
                match_offset,
                "AI-agent workflow appears to combine untrusted GitHub event text with secrets or privileged tokens.",
                match_text,
                "Separate untrusted text analysis from privileged actions; avoid secrets in jobs that consume issue, PR, discussion, or comment content.",
            )
        )
    elif has_ai and has_untrusted:
        match_text, match_offset = untrusted_match
        findings.append(
            _finding(
                "high",
                "UNTRUSTED_INPUT_TO_AGENT",
                path,
                text,
                match_offset,
                "AI-agent workflow consumes untrusted event text or caller-supplied workflow input.",
                match_text,
                "Treat event text and workflow inputs as hostile; quarantine them from tool-capable prompts and require maintainer approval for write actions.",
            )
        )

    if has_ai and write_permission is not None:
        match_text, match_offset = write_permission
        findings.append(
            _finding(
                "high",
                "AGENT_WITH_WRITE_TOKEN",
                path,
                text,
                match_offset,
                "AI-agent workflow has write permissions.",
                match_text,
                "Use least-privilege permissions and split read-only analysis from write operations.",
            )
        )

    if has_ai and not has_permissions_block:
        match_offset = _first_ai_match_offset(text, risk_scope_blocks)
        if match_offset is None:
            match_offset = ai_matches[0].start()
        findings.append(
            _finding(
                "medium",
                "MISSING_EXPLICIT_PERMISSIONS",
                path,
                text,
                match_offset,
                "AI-agent workflow does not declare an explicit permissions block.",
                _line_at(text, match_offset),
                "Declare top-level or job-level permissions explicitly, preferably `contents: read` for analysis jobs.",
            )
        )

    if has_ai and has_pull_request_target:
        match = PULL_REQUEST_TARGET.search(text)
        assert match is not None
        severity = "critical" if has_checkout_head_ref else "high"
        findings.append(
            _finding(
                severity,
                "PULL_REQUEST_TARGET_AGENT",
                path,
                text,
                match.start(),
                "AI-agent workflow runs on pull_request_target.",
                _line_at(text, match.start()),
                "Avoid running agent code on pull_request_target; never check out untrusted fork code with privileged tokens.",
            )
        )

    if has_ai and has_workflow_run and (write_permission is not None or has_secret):
        match = WORKFLOW_RUN.search(text)
        assert match is not None
        findings.append(
            _finding(
                "high",
                "WORKFLOW_RUN_AGENT_HANDOFF",
                path,
                text,
                match.start(),
                "AI-agent workflow runs on workflow_run with privileged follow-up context.",
                _line_at(text, match.start()),
                "Treat workflow_run artifacts and upstream outputs as a trust boundary; validate handoff data and keep privileged writes in a maintainer-approved job.",
            )
        )

    if has_ai and has_shell:
        match_text, match_offset = shell_match
        findings.append(
            _finding(
                "medium",
                "AGENT_JOB_RUNS_SHELL",
                path,
                text,
                match_offset,
                "AI-related workflow contains shell execution.",
                match_text,
                "Constrain shell steps, avoid interpolating model output into commands, and require human approval for mutations.",
            )
        )

    if has_ai and write_permission is not None and repository_mutation_match is not None:
        match_text, match_offset = repository_mutation_match
        findings.append(
            _finding(
                "high",
                "AI_GENERATED_CHANGES_PUSHED",
                path,
                text,
                match_offset,
                "AI-related workflow appears able to push, merge, publish, or comment repository changes.",
                match_text,
                "Move repository mutation into a maintainer-approved stage and keep AI-generated patches as review artifacts.",
            )
        )

    if has_ai and ai_output_shell_match is not None:
        match_text, match_offset = ai_output_shell_match
        findings.append(
            _finding(
                "high",
                "AI_OUTPUT_TO_SHELL",
                path,
                text,
                match_offset,
                "AI step output appears to be interpolated into shell execution.",
                match_text,
                "Write AI output to a file or structured artifact, validate it against an allowlist, and require maintainer approval before shell execution.",
            )
        )

    if has_ai and checkout_credentials_match is not None:
        match_text, match_offset = checkout_credentials_match
        findings.append(
            _finding(
                "medium",
                "CHECKOUT_CREDENTIALS_IN_AGENT_JOB",
                path,
                text,
                match_offset,
                "AI-related job checks out repository contents without disabling persisted Git credentials.",
                match_text,
                "Set `persist-credentials: false` on checkout steps in AI jobs unless that job is explicitly trusted to push.",
            )
        )

    return findings


def _curated_action_profile(action: str) -> CuratedActionProfile | None:
    normalized = action.strip().lower()
    for profile in CURATED_AI_ACTION_PROFILES:
        if profile.pattern.search(normalized):
            return profile
    return None


def _is_pinned_action_ref(action: str) -> bool:
    return bool(FULL_COMMIT_SHA_REF.search(action.strip()))


def _is_ai_job_block(block: TextBlock) -> bool:
    if AI_HINTS.search(block.name):
        return True

    for line in block.text.splitlines():
        if re.match(r"^\s*name:\s*", line, re.IGNORECASE) and AI_HINTS.search(line):
            return True
        if re.match(r"^\s*uses:\s*", line, re.IGNORECASE) and AI_HINTS.search(line):
            return True
        if JOB_LEVEL_PROMPT_INPUT.search(line):
            return True

    for match in STEP_START.finditer(block.text):
        if AI_HINTS.search(_step_text_at(block.text, match.start())):
            return True

    return False


def _first_ai_match_offset(text: str, ai_job_blocks: list[TextBlock]) -> int | None:
    if not ai_job_blocks:
        match = AI_HINTS.search(text)
        return match.start() if match is not None else None
    first_offset: int | None = None
    for block in ai_job_blocks:
        match = AI_HINTS.search(block.text)
        if match is None:
            continue
        absolute_offset = block.start_offset + match.start()
        if first_offset is None or absolute_offset < first_offset:
            first_offset = absolute_offset
    return first_offset


def _job_blocks(text: str) -> list[TextBlock]:
    lines = text.splitlines(keepends=True)
    offsets: list[int] = []
    offset = 0
    for line in lines:
        offsets.append(offset)
        offset += len(line)

    jobs_index: int | None = None
    jobs_indent = 0
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)jobs:\s*(#.*)?$", line)
        if match:
            jobs_index = index
            jobs_indent = len(match.group(1))
            break
    if jobs_index is None:
        return []

    child_indent: int | None = None
    job_starts: list[tuple[str, int]] = []
    jobs_end_index = len(lines)
    for index in range(jobs_index + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= jobs_indent:
            jobs_end_index = index
            break
        if child_indent is None:
            child_indent = indent
        if indent != child_indent:
            continue
        match = re.match(r"^\s*(?:([A-Za-z0-9_.-]+)|['\"]([A-Za-z0-9_.-]+)['\"]):\s*(#.*)?$", line)
        if match:
            job_starts.append((match.group(1) or match.group(2), index))

    blocks: list[TextBlock] = []
    for position, (name, start_index) in enumerate(job_starts):
        end_index = job_starts[position + 1][1] if position + 1 < len(job_starts) else jobs_end_index
        blocks.append(TextBlock(name=name, text="".join(lines[start_index:end_index]), start_offset=offsets[start_index]))
    return blocks


def _first_scoped_match(pattern: re.Pattern[str], text: str, scoped_blocks: list[TextBlock]) -> tuple[str, int] | None:
    if scoped_blocks:
        for block in scoped_blocks:
            match = pattern.search(block.text)
            if match is not None:
                return _line_at(block.text, match.start()), block.start_offset + match.start()
        return None
    match = pattern.search(text)
    if match is None:
        return None
    return _line_at(text, match.start()), match.start()


def _ai_secret_match(text: str, ai_job_blocks: list[TextBlock]) -> tuple[str, int] | None:
    scoped_match = _first_scoped_match(SECRET_CONTEXT, text, ai_job_blocks)
    if scoped_match is not None:
        return scoped_match

    top_level_env = _top_level_block(text, "env")
    if top_level_env is None:
        return None
    match = SECRET_CONTEXT.search(top_level_env.text)
    if match is None:
        return None
    return _line_at(top_level_env.text, match.start()), top_level_env.start_offset + match.start()


def _checkout_credentials_match(ai_job_blocks: list[TextBlock]) -> tuple[str, int] | None:
    for block in ai_job_blocks:
        for match in CHECKOUT_ACTION.finditer(block.text):
            step_text = _step_text_at(block.text, match.start())
            if CHECKOUT_PERSIST_CREDENTIALS_FALSE.search(step_text):
                continue
            return _line_at(block.text, match.start()), block.start_offset + match.start()
    return None


def _ai_output_to_shell_match(ai_job_blocks: list[TextBlock]) -> tuple[str, int] | None:
    for block in ai_job_blocks:
        ai_step_ids = _ai_step_ids(block.text)
        if not ai_step_ids:
            continue
        output_patterns = [
            re.compile(rf"steps\.{re.escape(step_id)}\.outputs\.[A-Za-z0-9_.-]+", re.IGNORECASE)
            for step_id in ai_step_ids
        ]
        for match in RUNS_SHELL.finditer(block.text):
            step_text = _step_text_at(block.text, match.start())
            if any(pattern.search(step_text) for pattern in output_patterns):
                return _line_at(block.text, match.start()), block.start_offset + match.start()
    return None


def _ai_repository_mutation_match(ai_job_blocks: list[TextBlock]) -> tuple[str, int] | None:
    for block in ai_job_blocks:
        for match in RUNS_SHELL.finditer(block.text):
            step_text = _step_text_at(block.text, match.start())
            mutation_match = REPOSITORY_MUTATION_COMMAND.search(step_text)
            if mutation_match is not None:
                return _line_at(step_text, mutation_match.start()), block.start_offset + match.start() + mutation_match.start()
    return None


def _ai_step_ids(text: str) -> set[str]:
    step_ids: set[str] = set()
    for match in STEP_START.finditer(text):
        step_text = _step_text_at(text, match.start())
        if not AI_HINTS.search(step_text):
            continue
        id_match = STEP_ID.search(step_text)
        if id_match is not None:
            step_ids.add(id_match.group(1))
    return step_ids


def _step_text_at(text: str, offset: int) -> str:
    lines = text.splitlines(keepends=True)
    current_offset = 0
    start_index = 0
    for index, line in enumerate(lines):
        next_offset = current_offset + len(line)
        if current_offset <= offset < next_offset:
            start_index = index
            break
        current_offset = next_offset

    current_line = lines[start_index]
    match = re.match(r"^(\s*)-\s+", current_line)
    if match:
        step_indent = len(match.group(1))
    else:
        step_indent = len(current_line) - len(current_line.lstrip(" "))

    end_index = len(lines)
    for index in range(start_index + 1, len(lines)):
        line = lines[index]
        if re.match(rf"^\s{{0,{step_indent}}}-\s+", line):
            end_index = index
            break
    return "".join(lines[start_index:end_index])


def _has_top_level_permissions(text: str) -> bool:
    return bool(re.search(r"^permissions:\s*(\n|$|read-all\s*$|write-all\s*$)", text, re.IGNORECASE | re.MULTILINE))


def _top_level_write_permission(text: str) -> tuple[str, int] | None:
    block = _top_level_block(text, "permissions")
    if block is None:
        return None
    match = WRITE_ALL_PERMISSION.search(block.text) or WRITE_PERMISSION.search(block.text)
    if match is None:
        return None
    return _line_at(block.text, match.start()), block.start_offset + match.start()


def _top_level_block(text: str, key: str) -> TextBlock | None:
    lines = text.splitlines(keepends=True)
    offset = 0
    for index, line in enumerate(lines):
        if re.match(rf"^{re.escape(key)}:\s*(read-all|write-all)?\s*(#.*)?$", line, re.IGNORECASE):
            start_offset = offset
            end_index = len(lines)
            for next_index in range(index + 1, len(lines)):
                next_line = lines[next_index]
                if next_line.strip() and not next_line.startswith((" ", "\t")):
                    end_index = next_index
                    break
            return TextBlock(name=key, text="".join(lines[index:end_index]), start_offset=start_offset)
        offset += len(line)
    return None


def _ai_write_permission(text: str, ai_job_blocks: list[TextBlock]) -> tuple[str, int] | None:
    top_level = _top_level_write_permission(text)
    if top_level is not None:
        return top_level
    for block in ai_job_blocks:
        match = WRITE_ALL_PERMISSION.search(block.text) or WRITE_PERMISSION.search(block.text)
        if match is not None:
            return _line_at(block.text, match.start()), block.start_offset + match.start()
    if not ai_job_blocks:
        match = WRITE_ALL_PERMISSION.search(text) or WRITE_PERMISSION.search(text)
        if match is not None:
            return _line_at(text, match.start()), match.start()
    return None


def _has_ai_permissions_block(text: str, ai_job_blocks: list[TextBlock]) -> bool:
    if _has_top_level_permissions(text):
        return True
    if ai_job_blocks:
        return any(PERMISSIONS_BLOCK.search(block.text) for block in ai_job_blocks)
    return bool(PERMISSIONS_BLOCK.search(text))


def _finding(
    severity: str,
    rule: str,
    path: str,
    text: str,
    offset: int,
    message: str,
    evidence: str,
    recommendation: str,
) -> Finding:
    return Finding(
        severity=severity,
        rule=rule,
        path=path,
        line=_line_number(text, offset),
        message=message,
        evidence=evidence.strip(),
        recommendation=recommendation,
    )


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_at(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    return text[start:end].strip()
