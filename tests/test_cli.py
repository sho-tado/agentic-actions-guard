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
