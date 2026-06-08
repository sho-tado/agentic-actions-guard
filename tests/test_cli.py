from pathlib import Path
import json

from agentic_actions_guard.cli import main


def test_validate_allowlist_cli_accepts_valid_policy(tmp_path: Path, capsys) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "path": ".github/workflows/triage.yml",
      "reason": "Accepted for a short rollout window.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Read-only rollout while maintainers replace the workflow."
    }
  ]
}
""",
        encoding="utf-8",
    )

    exit_code = main(["validate-allowlist", str(policy)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.strip() == "allowlist ok: 1 entry"
    assert captured.err == ""


def test_validate_allowlist_cli_rejects_invalid_policy(tmp_path: Path, capsys) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "reason": "Too broad."
    }
  ]
}
""",
        encoding="utf-8",
    )

    exit_code = main(["validate-allowlist", str(policy)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "allowlist error:" in captured.err
    assert "at least one matcher" in captured.err


def test_validate_allowlist_cli_rejects_unknown_rule(tmp_path: Path, capsys) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "TOKEN",
      "path": ".github/workflows/triage.yml",
      "reason": "Accepted for a short rollout window.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Read-only rollout while maintainers replace the workflow."
    }
  ]
}
""",
        encoding="utf-8",
    )

    exit_code = main(["validate-allowlist", str(policy)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "allowlist error:" in captured.err
    assert "unknown rule 'TOKEN'" in captured.err


def test_validate_allowlist_cli_rejects_expiry_beyond_max_window(tmp_path: Path, capsys) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "path": ".github/workflows/triage.yml",
      "reason": "Accepted for a short rollout window.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Read-only rollout while maintainers replace the workflow."
    }
  ]
}
""",
        encoding="utf-8",
    )

    exit_code = main(["validate-allowlist", str(policy), "--max-expiry-days", "30"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "allowlist error:" in captured.err
    assert "beyond the allowed 30 day window" in captured.err


def test_validate_allowlist_cli_requires_removal_condition_when_requested(tmp_path: Path, capsys) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "path": ".github/workflows/triage.yml",
      "reason": "Accepted for a short rollout window.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Read-only rollout while maintainers replace the workflow."
    }
  ]
}
""",
        encoding="utf-8",
    )

    exit_code = main(["validate-allowlist", str(policy), "--require-removal-condition"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "allowlist error:" in captured.err
    assert "non-empty 'removal_condition'" in captured.err


def test_validate_allowlist_cli_accepts_required_removal_condition(tmp_path: Path, capsys) -> None:
    policy = tmp_path / "agentic-actions-guard.allowlist.json"
    policy.write_text(
        """{
  "allowlist": [
    {
      "rule": "UNTRUSTED_INPUT_TO_AGENT",
      "path": ".github/workflows/triage.yml",
      "reason": "Accepted for a short rollout window.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Read-only rollout while maintainers replace the workflow.",
      "removal_condition": "The replacement workflow lands and this accepted risk is deleted."
    }
  ]
}
""",
        encoding="utf-8",
    )

    exit_code = main(["validate-allowlist", str(policy), "--require-removal-condition"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.strip() == "allowlist ok: 1 entry"
    assert captured.err == ""


def test_rules_cli_emits_markdown_catalog(capsys) -> None:
    exit_code = main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "| Rule | Severity | Name | Help |" in captured.out
    assert "`UNTRUSTED_INPUT_WITH_SECRETS` | critical" in captured.out
    assert "`PULL_REQUEST_TARGET_AGENT` | high or critical" in captured.out
    assert captured.err == ""


def test_rules_cli_emits_json_catalog(capsys) -> None:
    exit_code = main(["rules", "--format", "json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    rules = {rule["rule"]: rule for rule in payload["rules"]}
    assert exit_code == 0
    assert rules["UNTRUSTED_INPUT_WITH_SECRETS"]["severity"] == "critical"
    assert "untrusted event text" in rules["UNTRUSTED_INPUT_WITH_SECRETS"]["help"]
    assert rules["PULL_REQUEST_TARGET_AGENT"]["severity"] == "high or critical"
    assert captured.err == ""


def test_scan_json_output_keeps_machine_readable_contract(tmp_path: Path, capsys) -> None:
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

    exit_code = main(["scan", str(tmp_path), "--format", "json", "--fail-on", "critical"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    finding = payload["findings"][0]
    assert exit_code == 0
    assert {
        "root",
        "workflow_count",
        "findings",
        "suppressed_findings",
        "suppressions",
        "allowlist_entries",
        "summary",
        "suppressed_summary",
    } <= set(payload)
    assert {"severity", "rule", "path", "line", "message", "evidence", "recommendation"} <= set(finding)
    assert payload["summary"]["high"] == 1
    assert set(payload["summary"]) == {"info", "low", "medium", "high", "critical"}
    assert set(payload["suppressed_summary"]) == {"info", "low", "medium", "high", "critical"}
    assert captured.err == ""


def test_scan_sarif_output_keeps_suppression_contract(tmp_path: Path, capsys) -> None:
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
      "reason": "Accepted for CLI schema test.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Synthetic test keeps accepted-risk metadata stable.",
      "removal_condition": "Delete this test policy after the fixture changes."
    }
  ]
}
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scan",
            str(tmp_path),
            "--format",
            "sarif",
            "--allowlist",
            str(policy),
            "--fail-on",
            "critical",
        ]
    )

    captured = capsys.readouterr()
    sarif = json.loads(captured.out)
    run = sarif["runs"][0]
    suppressions = run["properties"]["suppressions"]
    active_rules = {result["ruleId"] for result in run["results"]}
    assert exit_code == 0
    assert sarif["version"] == "2.1.0"
    assert "UNTRUSTED_INPUT_TO_AGENT" not in active_rules
    assert suppressions[0]["rule"] == "UNTRUSTED_INPUT_TO_AGENT"
    assert suppressions[0]["reason"] == "Accepted for CLI schema test."
    assert suppressions[0]["owner"] == "maintainer-team"
    assert suppressions[0]["expires"] == "2099-12-31"
    assert suppressions[0]["rationale"] == "Synthetic test keeps accepted-risk metadata stable."
    assert suppressions[0]["removalCondition"] == "Delete this test policy after the fixture changes."
    assert set(run["properties"]["summary"]) == {"info", "low", "medium", "high", "critical"}
    assert set(run["properties"]["suppressedSummary"]) == {"info", "low", "medium", "high", "critical"}
    assert captured.err == ""


def test_scan_allowlist_rejects_expiry_beyond_max_window(tmp_path: Path, capsys) -> None:
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
      "reason": "Accepted for a short rollout window.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Synthetic fixture."
    }
  ]
}
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scan",
            str(tmp_path),
            "--allowlist",
            str(policy),
            "--allowlist-max-expiry-days",
            "30",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "scan error:" in captured.err
    assert "beyond the allowed 30 day window" in captured.err


def test_scan_allowlist_requires_removal_condition_when_requested(tmp_path: Path, capsys) -> None:
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
      "reason": "Accepted for a short rollout window.",
      "owner": "maintainer-team",
      "expires": "2099-12-31",
      "rationale": "Synthetic fixture."
    }
  ]
}
""",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scan",
            str(tmp_path),
            "--allowlist",
            str(policy),
            "--allowlist-require-removal-condition",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "scan error:" in captured.err
    assert "non-empty 'removal_condition'" in captured.err
