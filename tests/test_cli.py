from pathlib import Path

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
