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


def test_bracket_notation_issue_body_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: bracket issue ai triage
on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event['issue']['body'] }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event['issue']['body'] }}"


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


def test_whole_issue_event_object_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "issue-object-review.yml").write_text(
        """name: issue object ai triage
on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ toJson(github.event.issue) }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ toJson(github.event.issue) }}"


def test_whole_pull_request_event_object_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "pull-request-object-review.yml").write_text(
        """name: pull request object ai review
on:
  pull_request:
    types: [opened]
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ toJSON(github.event.pull_request) }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ toJSON(github.event.pull_request) }}"


def test_whole_comment_event_object_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "comment-object-review.yml").write_text(
        """name: comment object ai triage
on:
  issue_comment:
    types: [created]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.comment }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.comment }}"


def test_github_event_path_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "event-path-review.yml").write_text(
        """name: event path ai triage
on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt-file: ${{ github.event_path }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt-file: ${{ github.event_path }}"


def test_github_event_path_shell_handoff_in_ai_job_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "event-path-shell-review.yml").write_text(
        """name: event path shell ai triage
on:
  pull_request:
    types: [opened]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: cat "$GITHUB_EVENT_PATH" > prompt.json
      - uses: openai/agent-action@v1
        with:
          prompt-file: prompt.json
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == '- run: cat "$GITHUB_EVENT_PATH" > prompt.json'


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


def test_workflow_level_ai_name_does_not_make_normal_job_agentic(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release-notes.yml").write_text(
        """name: safer ai release notes
on:
  workflow_dispatch:
    inputs:
      release_ref:
        required: true
permissions:
  contents: write
jobs:
  draft:
    runs-on: ubuntu-latest
    steps:
      - run: |
          git log --oneline -n 25 > release-context.txt
          echo "${{ inputs.release_ref }}" >> release-context.txt
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert report.findings == []


def test_needs_ai_named_dependency_does_not_make_job_agentic(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "deploy.yml").write_text(
        """name: deploy after ai build
on:
  push:
permissions:
  contents: write
jobs:
  build:
    name: AI build context
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: summarize release notes
  deploy:
    needs: ai-build
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - run: echo "ordinary deploy"
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    write_findings = [finding for finding in report.findings if finding.rule == "AGENT_WITH_WRITE_TOKEN"]
    shell_findings = [finding for finding in report.findings if finding.rule == "AGENT_JOB_RUNS_SHELL"]
    assert len(write_findings) == 1
    assert write_findings[0].evidence == "contents: write"
    assert write_findings[0].line == 5
    assert shell_findings == []


def test_reusable_ai_workflow_job_without_steps_is_scoped_as_agentic(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "reusable-ai-review.yml").write_text(
        """name: reusable ai review
on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  review:
    uses: owner/ai-review/.github/workflows/review.yml@v1
    with:
      prompt: ${{ github.event.issue.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.issue.body }}"


def test_reusable_ai_workflow_with_secrets_inherit_is_critical(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "reusable-ai-review.yml").write_text(
        """name: reusable ai review
on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  review:
    uses: owner/ai-review/.github/workflows/review.yml@v1
    with:
      prompt: ${{ github.event.issue.body }}
    secrets: inherit
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_WITH_SECRETS")
    assert finding.severity == "critical"
    assert finding.evidence == "prompt: ${{ github.event.issue.body }}"


def test_reusable_ai_workflow_with_commented_secrets_inherit_is_critical(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "reusable-ai-review.yml").write_text(
        """name: reusable ai review
on:
  issues:
    types: [opened]
permissions:
  contents: read
jobs:
  review:
    uses: owner/ai-review/.github/workflows/review.yml@v1
    with:
      prompt: ${{ github.event.issue.body }}
    secrets: inherit # passes caller secrets into the reusable workflow
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_WITH_SECRETS")
    assert finding.severity == "critical"
    assert finding.evidence == "prompt: ${{ github.event.issue.body }}"


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


def test_top_level_workflow_dispatch_input_to_agent_is_untrusted(tmp_path: Path) -> None:
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
          prompt: ${{ inputs.prompt }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ inputs.prompt }}"


def test_bracket_notation_workflow_dispatch_input_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "manual-review.yml").write_text(
        """name: manual bracket ai review
on:
  workflow_dispatch:
    inputs:
      prompt:
        description: Review prompt
        required: true
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ inputs['prompt'] }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ inputs['prompt'] }}"


def test_workflow_call_input_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "reusable-review.yml").write_text(
        """name: reusable ai review
on:
  workflow_call:
    inputs:
      prompt:
        type: string
        required: true
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ inputs.prompt }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ inputs.prompt }}"


def test_bracket_notation_workflow_call_input_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "reusable-review.yml").write_text(
        """name: reusable bracket ai review
on:
  workflow_call:
    inputs:
      instructions:
        type: string
        required: true
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ inputs["instructions"] }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == 'prompt: ${{ inputs["instructions"] }}'


def test_separator_style_workflow_input_name_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "manual-review.yml").write_text(
        """name: manual separator ai review
on:
  workflow_dispatch:
    inputs:
      issue_body:
        required: true
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ inputs.issue_body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ inputs.issue_body }}"


def test_bracket_separator_style_workflow_input_name_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "manual-review.yml").write_text(
        """name: manual bracket separator ai review
on:
  workflow_dispatch:
    inputs:
      review_prompt:
        required: true
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ inputs['review_prompt'] }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ inputs['review_prompt'] }}"


def test_non_prompt_workflow_input_name_to_agent_is_not_untrusted_by_name(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "manual-release.yml").write_text(
        """name: manual ai release summary
on:
  workflow_dispatch:
    inputs:
      release_ref:
        required: true
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@1234567890abcdef1234567890abcdef12345678
        with:
          prompt: ${{ inputs.release_ref }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert "UNTRUSTED_INPUT_TO_AGENT" not in {finding.rule for finding in report.findings}


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


def test_bracket_notation_repository_dispatch_payload_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "dispatch-review.yml").write_text(
        """name: bracket dispatch ai review
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
          prompt: ${{ github.event['client_payload']['prompt'] }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event['client_payload']['prompt'] }}"


def test_discussion_body_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "discussion-review.yml").write_text(
        """name: discussion ai triage
on:
  discussion:
    types: [created]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.discussion.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.discussion.body }}"


def test_discussion_title_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "discussion-title-review.yml").write_text(
        """name: discussion title ai triage
on:
  discussion:
    types: [created]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.discussion.title }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.discussion.title }}"


def test_discussion_comment_body_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "discussion-comment-review.yml").write_text(
        """name: discussion comment ai triage
on:
  discussion_comment:
    types: [created]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.discussion_comment.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.discussion_comment.body }}"


def test_discussion_comment_event_comment_body_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "discussion-comment-review.yml").write_text(
        """name: discussion comment ai triage
on:
  discussion_comment:
    types: [created]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.comment.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.comment.body }}"


def test_discussion_answer_body_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "discussion-answer-review.yml").write_text(
        """name: discussion answer ai triage
on:
  discussion:
    types: [answered]
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.answer.body }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.answer.body }}"


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


def test_github_ref_name_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "branch-name-review.yml").write_text(
        """name: branch name ai review
on:
  push:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.ref_name }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.ref_name }}"


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


def test_bracket_notation_pull_request_body_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "pr-review.yml").write_text(
        """name: bracket pr ai review
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
          prompt: ${{ github['event']['pull_request']['body'] }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github['event']['pull_request']['body'] }}"


def test_push_commit_array_message_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "commit-message-review.yml").write_text(
        """name: commit message ai review
on:
  push:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.commits[0].message }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.commits[0].message }}"


def test_bracket_notation_push_commit_array_message_to_agent_is_untrusted(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "commit-message-review.yml").write_text(
        """name: bracket commit message ai review
on:
  push:
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.commits[0]['message'] }}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    finding = next(finding for finding in report.findings if finding.rule == "UNTRUSTED_INPUT_TO_AGENT")
    assert finding.severity == "high"
    assert finding.evidence == "prompt: ${{ github.event.commits[0]['message'] }}"


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
      "reason": "Accepted for test fixture.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Synthetic fixture keeps one accepted risk visible while other findings stay active.",
      "removal_condition": "Delete the accepted risk after the replacement workflow is merged."
    }
  ]
}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path, allowlist_path=policy)
    report_json = report.to_dict()
    sarif = report.to_sarif()
    markdown = report.to_markdown()
    review = report.to_review_markdown(target="example/repo")
    summary = report.to_step_summary()

    assert "UNTRUSTED_INPUT_TO_AGENT" not in {finding.rule for finding in report.findings}
    assert "MISSING_EXPLICIT_PERMISSIONS" in {finding.rule for finding in report.findings}
    assert [finding.rule for finding in report.suppressed_findings] == ["UNTRUSTED_INPUT_TO_AGENT"]
    assert report_json["suppressions"][0]["finding"]["rule"] == "UNTRUSTED_INPUT_TO_AGENT"
    assert report_json["suppressions"][0]["allowlist_entry"]["reason"] == "Accepted for test fixture."
    assert report_json["suppressions"][0]["allowlist_entry"]["owner"] == "maintainer-team"
    assert report_json["suppressions"][0]["allowlist_entry"]["expires"] == "2099-12-31"
    assert report_json["suppressions"][0]["allowlist_entry"]["rationale"] == (
        "Synthetic fixture keeps one accepted risk visible while other findings stay active."
    )
    assert report_json["suppressions"][0]["allowlist_entry"]["removal_condition"] == (
        "Delete the accepted risk after the replacement workflow is merged."
    )
    sarif_run = sarif["runs"][0]
    sarif_suppressions = sarif_run["properties"]["suppressions"]
    active_sarif_rules = {result["ruleId"] for result in sarif_run["results"]}
    assert "UNTRUSTED_INPUT_TO_AGENT" not in active_sarif_rules
    assert "MISSING_EXPLICIT_PERMISSIONS" in active_sarif_rules
    assert sarif_suppressions == [
        {
            "rule": "UNTRUSTED_INPUT_TO_AGENT",
            "severity": "high",
            "path": ".github/workflows/triage.yml",
            "line": 11,
            "evidence": "prompt: ${{ github.event.issue.body }}",
            "reason": "Accepted for test fixture.",
            "owner": "maintainer-team",
            "expires": "2099-12-31",
            "rationale": "Synthetic fixture keeps one accepted risk visible while other findings stay active.",
            "removalCondition": "Delete the accepted risk after the replacement workflow is merged.",
        }
    ]
    assert "Suppressed findings: `1`" in markdown
    assert "## Suppressed Findings" in markdown
    assert "Allowlist reason: Accepted for test fixture." in markdown
    assert "Owner: `maintainer-team`" in markdown
    assert "Expires: `2099-12-31`" in markdown
    assert "Rationale: Synthetic fixture keeps one accepted risk visible while other findings stay active." in markdown
    assert "Removal condition: Delete the accepted risk after the replacement workflow is merged." in markdown
    assert "Suppressed accepted risks:" in review
    assert (
        "`UNTRUSTED_INPUT_TO_AGENT` at `.github/workflows/triage.yml:11`: Accepted for test fixture. "
        "(owner: `maintainer-team`, expires: `2099-12-31`)"
    ) in review
    assert "Suppressed accepted risks:" in summary
    assert (
        "`UNTRUSTED_INPUT_TO_AGENT` at `.github/workflows/triage.yml:11`: Accepted for test fixture. "
        "(owner: `maintainer-team`, expires: `2099-12-31`)"
    ) in summary
    assert "Accepted risk review queue:" in markdown
    assert (
        "`2099-12-31` `UNTRUSTED_INPUT_TO_AGENT` at `.github/workflows/triage.yml:11` "
        "(owner: `maintainer-team`)"
    ) in markdown
    assert "Accepted risk review queue:" in review
    assert "Accepted risk review queue:" in summary


def test_accepted_risk_review_queue_is_sorted_by_expiry(tmp_path: Path) -> None:
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
      - run: echo "fixed shell command"
""",
        encoding="utf-8",
    )
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "AGENT_JOB_RUNS_SHELL",
      "path": ".github/workflows/triage.yml",
      "reason": "Fixed shell command accepted temporarily.",
      "owner": "workflow-team",
      "expires": "2099-12-31",
      "rationale": "Shell command is fixed while the team moves to an artifact-only report."
    },
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "path": ".github/workflows/triage.yml",
      "reason": "Prompt input accepted during review rollout.",
      "owner": "security-team",
      "expires": "2099-01-01",
      "rationale": "Read-only rollout keeps the prompt visible while maintainers evaluate the workflow."
    }
  ]
}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path, allowlist_path=policy)
    markdown = report.to_markdown()
    review = report.to_review_markdown(target="example/repo")
    summary = report.to_step_summary()

    early = "`2099-01-01` `UNTRUSTED_INPUT_TO_AGENT`"
    late = "`2099-12-31` `AGENT_JOB_RUNS_SHELL`"
    assert early in markdown
    assert late in markdown
    assert markdown.index(early) < markdown.index(late)
    assert review.index(early) < review.index(late)
    assert summary.index(early) < summary.index(late)


def test_allowlist_accepts_windows_path_matcher(tmp_path: Path) -> None:
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
      "path": ".github\\\\workflows\\\\triage.yml",
      "reason": "Accepted for test fixture.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Synthetic fixture keeps one accepted risk visible while other findings stay active."
    }
  ]
}
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path, allowlist_path=policy)

    assert [finding.rule for finding in report.suppressed_findings] == ["UNTRUSTED_INPUT_TO_AGENT"]


def test_allowlist_rejects_unknown_rule_id(tmp_path: Path) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "TOKEN",
      "path": ".github/workflows/triage.yml",
      "reason": "Accepted for test fixture.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Synthetic fixture."
    }
  ]
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown rule 'TOKEN'"):
        load_allowlist(policy)


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


def test_allowlist_rejects_reason_only_entry(tmp_path: Path) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "reason": "Accepted for test fixture."
    }
  ]
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="at least one matcher"):
        load_allowlist(policy)


def test_allowlist_requires_owner_expires_and_rationale(tmp_path: Path) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "reason": "Accepted for test fixture."
    }
  ]
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="non-empty 'owner'"):
        load_allowlist(policy)


def test_allowlist_rejects_invalid_expires_date(tmp_path: Path) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "reason": "Accepted for test fixture.",
      "owner": "maintainer-team",
      "expires": "31-12-2099",
      "rationale": "Synthetic fixture."
    }
  ]
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        load_allowlist(policy)


def test_allowlist_rejects_expired_entries(tmp_path: Path) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "reason": "Accepted for test fixture.",
      "owner": "maintainer-team",
      "expires": "2000-01-01",
      "rationale": "Synthetic fixture."
    }
  ]
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="expired on 2000-01-01"):
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


def test_quoted_ai_job_name_does_not_scope_non_ai_write_job(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "quoted-job.yml").write_text(
        """name: quoted ai triage
on:
  issues:
    types: [opened]
jobs:
  "ai-review":
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
  publish:
    permissions:
      contents: write
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


def test_commented_top_level_named_write_permission_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release-review.yml").write_text(
        """name: ai release review
on:
  issues:
    types: [opened]
permissions:
  contents: write # required for release upload
jobs:
  review:
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
    assert write_finding.line == 6
    assert write_finding.evidence == "contents: write # required for release upload"


def test_top_level_inline_named_write_permission_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release-review.yml").write_text(
        """name: ai release review
on:
  issues:
    types: [opened]
permissions: { contents: write, issues: read }
jobs:
  review:
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
    assert write_finding.evidence == "permissions: { contents: write, issues: read }"


def test_quoted_top_level_named_write_permission_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release-review.yml").write_text(
        """name: ai release review
on:
  issues:
    types: [opened]
permissions:
  "contents": "write"
jobs:
  review:
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
    assert write_finding.line == 6
    assert write_finding.evidence == '"contents": "write"'


def test_quoted_top_level_inline_named_write_permission_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release-review.yml").write_text(
        """name: ai release review
on:
  issues:
    types: [opened]
permissions: { "contents": "write", issues: read }
jobs:
  review:
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
    assert write_finding.evidence == 'permissions: { "contents": "write", issues: read }'


def test_commented_write_all_permission_is_flagged_and_counts_as_explicit(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: ai triage
on:
  issues:
    types: [opened]
permissions: write-all # temporary broad token
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
    assert write_finding.evidence == "permissions: write-all # temporary broad token"


def test_quoted_write_all_permission_is_flagged_and_counts_as_explicit(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "triage.yml").write_text(
        """name: ai triage
on:
  issues:
    types: [opened]
permissions: "write-all"
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
    assert write_finding.evidence == 'permissions: "write-all"'


def test_commented_job_level_named_write_permission_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "label-review.yml").write_text(
        """name: ai label review
on:
  issues:
    types: [opened]
jobs:
  review:
    permissions:
      issues: write # temporary label rollout
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
    assert write_finding.evidence == "issues: write # temporary label rollout"


def test_job_level_inline_named_write_permission_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "label-review.yml").write_text(
        """name: ai label review
on:
  issues:
    types: [opened]
jobs:
  review:
    permissions: { issues: write, contents: read }
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
    assert write_finding.line == 7
    assert write_finding.evidence == "permissions: { issues: write, contents: read }"


def test_quoted_job_level_inline_named_write_permission_is_flagged(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "label-review.yml").write_text(
        """name: ai label review
on:
  issues:
    types: [opened]
jobs:
  review:
    permissions: { "issues": "write", contents: read }
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
    assert write_finding.line == 7
    assert write_finding.evidence == 'permissions: { "issues": "write", contents: read }'


def test_non_ai_job_inline_write_permission_does_not_scope_ai_job(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "split-review.yml").write_text(
        """name: split ai review
on:
  issues:
    types: [opened]
jobs:
  analyze:
    permissions: { contents: read }
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
  label:
    permissions: { issues: write }
    runs-on: ubuntu-latest
    steps:
      - run: echo "maintainer-approved label"
""",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    rules = {finding.rule for finding in report.findings}
    assert "AGENT_WITH_WRITE_TOKEN" not in rules
    assert "MISSING_EXPLICIT_PERMISSIONS" not in rules
    assert "UNTRUSTED_INPUT_TO_AGENT" in rules


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
