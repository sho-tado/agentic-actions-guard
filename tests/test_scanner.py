from pathlib import Path

from agentic_actions_guard.scanner import scan_repository


def test_flags_untrusted_agent_with_secret(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """
name: ai triage
on:
  issues:
    types: [opened]
permissions:
  issues: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        with:
          prompt: ${{ github.event.issue.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    rules = {finding.rule for finding in report.findings}
    assert "UNTRUSTED_INPUT_WITH_SECRETS" in rules
    assert "AGENT_WITH_WRITE_TOKEN" in rules


def test_clean_non_ai_workflow_has_no_findings(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        """
name: ci
on:
  push:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: python -m pytest
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert report.workflow_count == 1
    assert report.findings == []


def test_main_branch_name_does_not_trigger_ai_detection(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        """
name: ci
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "ordinary shell step"
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert report.findings == []


def test_sarif_output_maps_high_severity_finding_to_workflow_line(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: ai triage
on:
  issues:
    types: [opened]
permissions:
  issues: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
""",
        encoding="utf-8",
    )

    sarif = scan_repository(tmp_path).to_sarif()

    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]
    high_result = next(result for result in results if result["ruleId"] == "UNTRUSTED_INPUT_TO_AGENT")
    location = high_result["locations"][0]["physicalLocation"]

    assert sarif["version"] == "2.1.0"
    assert any(rule["id"] == "UNTRUSTED_INPUT_TO_AGENT" for rule in rules)
    assert high_result["level"] == "error"
    assert location["artifactLocation"]["uri"] == ".github/workflows/triage.yml"
    assert location["region"]["startLine"] == 13


def test_review_output_is_maintainer_facing(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: ai triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
""",
        encoding="utf-8",
    )

    review = scan_repository(tmp_path).to_review_markdown(target="example/repo")

    assert "# Agentic Actions Guard Review" in review
    assert "Target: `example/repo`" in review
    assert "UNTRUSTED_INPUT_TO_AGENT" in review
    assert "Recommended Next Steps" in review


def test_allowlist_suppresses_matching_finding(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: ai triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
""",
        encoding="utf-8",
    )
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "path": ".github/workflows/triage.yml",
      "reason": "Accepted for test fixture."
    }
  ]
}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path, allowlist_path=policy)

    assert "UNTRUSTED_INPUT_TO_AGENT" not in {finding.rule for finding in report.findings}
    assert "MISSING_EXPLICIT_PERMISSIONS" in {finding.rule for finding in report.findings}
    assert [finding.rule for finding in report.suppressed_findings] == ["UNTRUSTED_INPUT_TO_AGENT"]
    assert "Suppressed findings: `1`" in report.to_markdown()


def test_github_annotations_output_emits_workflow_commands(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: ai triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
""",
        encoding="utf-8",
    )

    annotations = scan_repository(tmp_path).to_github_annotations()

    assert "::error file=.github/workflows/triage.yml,line=11,title=HIGH UNTRUSTED_INPUT_TO_AGENT::" in annotations
    assert "Recommendation:" in annotations


def test_non_ai_write_job_does_not_flag_agent_write_token(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: split ai triage
on:
  issues:
    types: [opened]
jobs:
  analyze:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
  label:
    permissions:
      issues: write
    runs-on: ubuntu-latest
    steps:
      - run: echo "maintainer-approved write job"
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    rules = {finding.rule for finding in report.findings}
    assert "AGENT_WITH_WRITE_TOKEN" not in rules
    assert "MISSING_EXPLICIT_PERMISSIONS" not in rules
    assert "UNTRUSTED_INPUT_TO_AGENT" in rules


def test_ai_job_level_write_permission_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: ai triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    permissions:
      issues: write
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    write_finding = next(finding for finding in report.findings if finding.rule == "AGENT_WITH_WRITE_TOKEN")
    rules = {finding.rule for finding in report.findings}
    assert "MISSING_EXPLICIT_PERMISSIONS" not in rules
    assert write_finding.line == 8
    assert write_finding.evidence == "issues: write"


def test_top_level_write_all_permission_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: ai triage
on:
  issues:
    types: [opened]
permissions: write-all
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    write_finding = next(finding for finding in report.findings if finding.rule == "AGENT_WITH_WRITE_TOKEN")
    rules = {finding.rule for finding in report.findings}
    assert "MISSING_EXPLICIT_PERMISSIONS" not in rules
    assert write_finding.line == 5
    assert write_finding.evidence == "permissions: write-all"


def test_non_ai_shell_before_ai_job_does_not_move_shell_finding_line(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: split ai triage
on:
  issues:
    types: [opened]
jobs:
  prepare:
    runs-on: ubuntu-latest
    steps:
      - run: echo "setup only"
  triage:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
      - run: echo "analyze output"
env:
  SAFE_TOP_LEVEL: "true"
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    shell_finding = next(finding for finding in report.findings if finding.rule == "AGENT_JOB_RUNS_SHELL")
    assert shell_finding.line == 18
    assert shell_finding.evidence == '- run: echo "analyze output"'


def test_curated_ai_action_detects_known_maintainer_action(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "claude.yml").write_text(
        """name: claude review
on:
  issue_comment:
    types: [created]
permissions:
  contents: read
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: ${{ github.event.comment.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    curated = next(finding for finding in report.findings if finding.rule == "CURATED_AI_ACTION_DETECTED")
    assert curated.line == 11
    assert curated.evidence == "anthropics/claude-code-action@v1"
    assert "Claude" in curated.message
    assert "maintainer approval" in curated.recommendation


def test_curated_action_rule_is_available_in_sarif(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "qwen.yml").write_text(
        """name: qwen triage
on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  qwen:
    runs-on: ubuntu-latest
    steps:
      - uses: QwenLM/qwen-code-action@v0.1.1
        with:
          prompt: ${{ github.event.issue.body }}
""",
        encoding="utf-8",
    )

    sarif = scan_repository(tmp_path).to_sarif()

    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    result = next(result for result in sarif["runs"][0]["results"] if result["ruleId"] == "CURATED_AI_ACTION_DETECTED")
    assert any(rule["id"] == "CURATED_AI_ACTION_DETECTED" for rule in rules)
    assert result["level"] == "note"
    assert result["properties"]["evidence"] == "QwenLM/qwen-code-action@v0.1.1"


def test_ai_job_checkout_without_persist_credentials_false_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "review.yml").write_text(
        """name: ai review
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    checkout_finding = next(finding for finding in report.findings if finding.rule == "CHECKOUT_CREDENTIALS_IN_AGENT_JOB")
    assert checkout_finding.line == 10
    assert checkout_finding.evidence == "- uses: actions/checkout@v4"


def test_ai_job_checkout_with_persist_credentials_false_is_not_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "review.yml").write_text(
        """name: ai review
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert "CHECKOUT_CREDENTIALS_IN_AGENT_JOB" not in {finding.rule for finding in report.findings}
