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
    assert {finding.rule for finding in report.findings} == {"MISSING_EXPLICIT_PERMISSIONS"}
    assert [finding.rule for finding in report.suppressed_findings] == ["UNTRUSTED_INPUT_TO_AGENT"]
    assert "Suppressed findings: `1`" in report.to_markdown()
