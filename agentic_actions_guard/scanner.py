from __future__ import annotations

from dataclasses import dataclass
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
    "UNTRUSTED_INPUT_WITH_SECRETS": {
        "name": "Untrusted input with secrets",
        "help": "Separate untrusted event text analysis from privileged jobs that have secrets or write tokens.",
    },
    "UNTRUSTED_INPUT_TO_AGENT": {
        "name": "Untrusted input to agent",
        "help": "Treat issue, pull request, comment, review, and commit text as hostile input to AI agents.",
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
}

WORKFLOW_EXTENSIONS = {".yml", ".yaml"}

AI_HINTS = re.compile(
    r"(ai|agent|codex|openai|claude|anthropic|gemini|copilot|aider|llm|gpt|reviewdog|autofix|triage)",
    re.IGNORECASE,
)
UNTRUSTED_CONTEXT = re.compile(
    r"github\.event\.(issue|comment|pull_request|review|review_comment|head_commit)"
    r"\.(title|body|body_text|message|ref|head\.ref)",
    re.IGNORECASE,
)
SECRET_CONTEXT = re.compile(r"(\$\{\{\s*secrets\.|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN)", re.IGNORECASE)
WRITE_PERMISSION = re.compile(
    r"^\s*(contents|issues|pull-requests|actions|checks|deployments|id-token|packages|statuses):\s*write\s*$",
    re.IGNORECASE | re.MULTILINE,
)
PERMISSIONS_BLOCK = re.compile(r"^\s*permissions:\s*(\n|$)", re.IGNORECASE | re.MULTILINE)
PULL_REQUEST_TARGET = re.compile(r"pull_request_target\s*:", re.IGNORECASE)
CHECKOUT_HEAD_REF = re.compile(
    r"actions/checkout@[\w.\-]+[\s\S]{0,500}(github\.event\.pull_request\.head\.(sha|ref)|ref:\s*\$\{\{)",
    re.IGNORECASE,
)
RUNS_SHELL = re.compile(r"^\s*run:\s*(\||>|[^\n]+)", re.IGNORECASE | re.MULTILINE)
USES_ACTION = re.compile(r"^\s*uses:\s*([^\s#]+)", re.IGNORECASE | re.MULTILINE)


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
class ScanReport:
    root: str
    workflow_count: int
    findings: list[Finding]

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "workflow_count": self.workflow_count,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": summarize_findings(self.findings),
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
                    },
                }
            ],
        }

    def to_markdown(self) -> str:
        summary = summarize_findings(self.findings)
        lines = [
            "# Agentic Actions Guard Report",
            "",
            f"- Root: `{self.root}`",
            f"- Workflows scanned: `{self.workflow_count}`",
            f"- Findings: `{len(self.findings)}`",
            "",
            "## Summary",
            "",
        ]
        for severity in ("critical", "high", "medium", "low", "info"):
            lines.append(f"- {severity}: `{summary.get(severity, 0)}`")
        if not self.findings:
            lines.extend(["", "No risky AI-agent workflow patterns were detected."])
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
        return "\n".join(lines).rstrip()


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    summary = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        summary[finding.severity] += 1
    return summary


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


def scan_repository(path: Path) -> ScanReport:
    root = path.resolve()
    workflows = list(_iter_workflows(root))
    findings: list[Finding] = []
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8", errors="replace")
        rel_path = str(workflow.relative_to(root if root.is_dir() else root.parent))
        findings.extend(_scan_workflow(rel_path, text))
    return ScanReport(root=str(root), workflow_count=len(workflows), findings=findings)


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
    ai_matches = list(AI_HINTS.finditer(text))
    untrusted_matches = list(UNTRUSTED_CONTEXT.finditer(text))
    has_ai = bool(ai_matches)
    has_untrusted = bool(untrusted_matches)
    has_secret = bool(SECRET_CONTEXT.search(text))
    has_write_permission = bool(WRITE_PERMISSION.search(text))
    has_permissions_block = bool(PERMISSIONS_BLOCK.search(text))
    has_pull_request_target = bool(PULL_REQUEST_TARGET.search(text))
    has_checkout_head_ref = bool(CHECKOUT_HEAD_REF.search(text))
    has_shell = bool(RUNS_SHELL.search(text))

    for match in USES_ACTION.finditer(text):
        action = match.group(1)
        if AI_HINTS.search(action):
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

    if has_ai and has_untrusted and has_secret:
        match = untrusted_matches[0]
        findings.append(
            _finding(
                "critical",
                "UNTRUSTED_INPUT_WITH_SECRETS",
                path,
                text,
                match.start(),
                "AI-agent workflow appears to combine untrusted GitHub event text with secrets or privileged tokens.",
                _line_at(text, match.start()),
                "Separate untrusted text analysis from privileged actions; avoid secrets in jobs that consume issue, PR, or comment content.",
            )
        )
    elif has_ai and has_untrusted:
        match = untrusted_matches[0]
        findings.append(
            _finding(
                "high",
                "UNTRUSTED_INPUT_TO_AGENT",
                path,
                text,
                match.start(),
                "AI-agent workflow consumes untrusted issue, PR, comment, or commit text.",
                _line_at(text, match.start()),
                "Treat event text as hostile input; quarantine it from tool-capable prompts and require maintainer approval for write actions.",
            )
        )

    if has_ai and has_write_permission:
        match = WRITE_PERMISSION.search(text)
        assert match is not None
        findings.append(
            _finding(
                "high",
                "AGENT_WITH_WRITE_TOKEN",
                path,
                text,
                match.start(),
                "AI-agent workflow has write permissions.",
                _line_at(text, match.start()),
                "Use least-privilege permissions and split read-only analysis from write operations.",
            )
        )

    if has_ai and not has_permissions_block:
        match = ai_matches[0]
        findings.append(
            _finding(
                "medium",
                "MISSING_EXPLICIT_PERMISSIONS",
                path,
                text,
                match.start(),
                "AI-agent workflow does not declare an explicit permissions block.",
                _line_at(text, match.start()),
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

    if has_ai and has_shell:
        match = RUNS_SHELL.search(text)
        assert match is not None
        findings.append(
            _finding(
                "medium",
                "AGENT_JOB_RUNS_SHELL",
                path,
                text,
                match.start(),
                "AI-related workflow contains shell execution.",
                _line_at(text, match.start()),
                "Constrain shell steps, avoid interpolating model output into commands, and require human approval for mutations.",
            )
        )

    return findings


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
