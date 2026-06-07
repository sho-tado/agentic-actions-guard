from pathlib import Path

import pytest

from agentic_actions_guard.scanner import load_allowlist, scan_repository


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


def test_top_level_env_secret_applies_to_ai_job(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: ai triage
on:
  issues:
    types: [opened]
env:
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
permissions:
  contents: read
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

    critical = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_WITH_SECRETS")
    assert critical.severity == "critical"
    assert critical.evidence == "prompt: ${{ github.event.issue.body }}"


def test_github_token_context_applies_to_ai_job(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "token-review.yml").write_text(
        """name: ai token review
on:
  issues:
    types: [opened]
permissions:
  issues: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: clouatre-labs/aptu@v1
        with:
          reference: ${{ github.event.issue.body }}
          github-token: ${{ github.token }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    critical = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_WITH_SECRETS")
    assert critical.severity == "critical"
    assert critical.evidence == "reference: ${{ github.event.issue.body }}"


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


def test_workflow_dispatch_input_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "manual-review.yml").write_text(
        """name: manual ai review
on:
  workflow_dispatch:
    inputs:
      prompt:
        required: true
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.inputs.prompt }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.inputs.prompt }}"


def test_repository_dispatch_payload_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "dispatch-review.yml").write_text(
        """name: dispatch ai review
on:
  repository_dispatch:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.client_payload.prompt }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.client_payload.prompt }}"


def test_github_head_ref_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "branch-review.yml").write_text(
        """name: branch ai review
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.head_ref }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.head_ref }}"


def test_pull_request_head_label_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "branch-label-review.yml").write_text(
        """name: branch label ai review
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.pull_request.head.label }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.pull_request.head.label }}"


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


def test_allowlist_requires_reason(tmp_path: Path) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "path": ".github/workflows/triage.yml"
    }
  ]
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="non-empty 'reason'"):
        load_allowlist(policy)


def test_allowlist_rejects_blank_reason(tmp_path: Path) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "path": ".github/workflows/triage.yml",
      "reason": "   "
    }
  ]
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="non-empty 'reason'"):
        load_allowlist(policy)


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


def test_step_summary_output_is_actions_summary_friendly(tmp_path: Path) -> None:
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

    summary = scan_repository(tmp_path).to_step_summary()

    assert "## Agentic Actions Guard Summary" in summary
    assert "| Severity | Count |" in summary
    assert "| high | `1` |" in summary
    assert "### Recommended Gate" in summary
    assert "### Rule Breakdown" in summary
    assert "| `UNTRUSTED_INPUT_TO_AGENT` | `1` |" in summary
    assert "### Suggested Next Actions" in summary
    assert "Review high findings" in summary
    assert "UNTRUSTED_INPUT_TO_AGENT" in summary


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


def test_ai_step_output_to_shell_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "review.yml").write_text(
        """name: ai output shell
on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - id: ai_review
        uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
      - run: gh issue comment "$NUMBER" --body "${{ steps.ai_review.outputs.summary }}"
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "AI_OUTPUT_TO_SHELL")
    assert finding.severity == "high"
    assert finding.line == 15
    assert finding.evidence == '- run: gh issue comment "$NUMBER" --body "${{ steps.ai_review.outputs.summary }}"'


def test_non_ai_step_output_to_shell_is_not_flagged_as_ai_output(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "review.yml").write_text(
        """name: ai output shell
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - id: metadata
        run: echo "summary=static" >> "$GITHUB_OUTPUT"
      - uses: openai/agent-action@1234567890abcdef1234567890abcdef12345678
        with:
          prompt: summarize only
      - run: echo "${{ steps.metadata.outputs.summary }}"
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert "AI_OUTPUT_TO_SHELL" not in {finding.rule for finding in report.findings}


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


def test_unpinned_ai_action_ref_is_flagged(tmp_path: Path) -> None:
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
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNPINNED_AI_ACTION_REF")
    assert finding.severity == "medium"
    assert finding.evidence == "openai/agent-action@v1"


def test_full_sha_pinned_ai_action_ref_is_not_flagged(tmp_path: Path) -> None:
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
      - uses: openai/agent-action@1234567890abcdef1234567890abcdef12345678
        with:
          prompt: ${{ github.event.pull_request.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert "UNPINNED_AI_ACTION_REF" not in {finding.rule for finding in report.findings}


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


def test_additional_curated_action_profiles_detect_known_actions(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "additional-curated.yml").write_text(
        """name: additional curated ai actions
on:
  issues:
    types: [opened]
permissions:
  issues: write
jobs:
  labeler:
    runs-on: ubuntu-latest
    steps:
      - uses: github/ai-assessment-comment-labeler@v1
        with:
          issue_body: ${{ github.event.issue.body }}
  issue-agent:
    runs-on: ubuntu-latest
    steps:
      - uses: alexyan0431/issue-ai-agent@v1
  aptu:
    runs-on: ubuntu-latest
    steps:
      - uses: clouatre-labs/aptu@v1
        with:
          github-token: ${{ github.token }}
          reference: ${{ github.event.issue.number }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    curated = [finding for finding in report.findings if finding.rule == "CURATED_AI_ACTION_DETECTED"]
    evidence = {finding.evidence for finding in curated}
    messages = "\n".join(finding.message for finding in curated)
    recommendations = "\n".join(finding.recommendation for finding in curated)

    assert "github/ai-assessment-comment-labeler@v1" in evidence
    assert "alexyan0431/issue-ai-agent@v1" in evidence
    assert "clouatre-labs/aptu@v1" in evidence
    assert "AI Assessment Comment Labeler" in messages
    assert "Issue AI Agent" in messages
    assert "Aptu" in messages
    assert "prompt files" in recommendations
    assert "duplicate detection" in recommendations
    assert "dry-run" in recommendations


def test_additional_curated_action_profiles_are_in_sarif(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "aptu.yml").write_text(
        """name: aptu triage
on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  aptu:
    runs-on: ubuntu-latest
    steps:
      - uses: clouatre-labs/aptu@v1
        with:
          reference: ${{ github.event.issue.number }}
""",
        encoding="utf-8",
    )

    sarif = scan_repository(tmp_path).to_sarif()

    result = next(result for result in sarif["runs"][0]["results"] if result["ruleId"] == "CURATED_AI_ACTION_DETECTED")
    assert result["level"] == "note"
    assert result["properties"]["evidence"] == "clouatre-labs/aptu@v1"


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


def test_review_output_summarizes_findings_beyond_top_five(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    for index in range(6):
        (workflows / f"triage-{index}.yml").write_text(
            f"""name: ai triage {index}
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{{{ github.event.issue.body }}}}
""",
            encoding="utf-8",
        )

    review = scan_repository(tmp_path).to_review_markdown(target="example/repo")

    assert "## Additional Findings Summary" in review
    assert "`UNTRUSTED_INPUT_TO_AGENT`:" in review
    assert "additional finding(s)" in review


def test_workflow_run_agent_handoff_with_write_token_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "handoff.yml").write_text(
        """name: ai workflow run handoff
on:
  workflow_run:
    workflows: ["ai-pr-analysis"]
    types: [completed]
permissions:
  contents: write
jobs:
  apply:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: apply upstream artifact
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    handoff = next(finding for finding in report.findings if finding.rule == "WORKFLOW_RUN_AGENT_HANDOFF")
    assert handoff.severity == "high"
    assert handoff.evidence == "workflow_run:"


def test_ai_generated_changes_pushed_with_write_token_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "autofix.yml").write_text(
        """name: ai autofix
on:
  pull_request:
permissions:
  contents: write
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/autofix-agent@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
      - run: |
          git add .
          git commit -m "Apply AI fix"
          git push
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "AI_GENERATED_CHANGES_PUSHED")
    assert finding.severity == "high"
    assert finding.evidence == 'git commit -m "Apply AI fix"'


def test_ai_generated_changes_artifact_without_write_token_is_not_flagged_as_push(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "plan.yml").write_text(
        """name: ai fix plan
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/autofix-agent@1234567890abcdef1234567890abcdef12345678
        with:
          prompt: summarize only
      - run: |
          mkdir -p out
          echo "review patch manually" > out/plan.md
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert "AI_GENERATED_CHANGES_PUSHED" not in {finding.rule for finding in report.findings}
