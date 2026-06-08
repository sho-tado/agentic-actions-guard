from pathlib import Path

from agentic_actions_guard.scanner import scan_repository


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_risky_examples_have_high_or_critical_findings() -> None:
    risky_examples = sorted(EXAMPLES.glob("risky-*.yml"))
    assert risky_examples

    for example in risky_examples:
        report = scan_repository(example)
        severities = {finding.severity for finding in report.findings}
        assert severities & {"high", "critical"}, example.name


def test_safer_examples_have_no_high_or_critical_findings() -> None:
    safer_examples = sorted(EXAMPLES.glob("safer-*.yml"))
    assert safer_examples

    for example in safer_examples:
        report = scan_repository(example)
        severities = {finding.severity for finding in report.findings}
        assert not (severities & {"high", "critical"}), example.name


def test_risky_ai_output_shell_fixture_exercises_specific_rule() -> None:
    report = scan_repository(EXAMPLES / "risky-ai-output-shell.yml")

    rules = {finding.rule for finding in report.findings}
    assert "AI_OUTPUT_TO_SHELL" in rules


def test_safer_release_notes_fixture_stays_review_only() -> None:
    report = scan_repository(EXAMPLES / "safer-release-notes.yml")

    severities = {finding.severity for finding in report.findings}
    rules = {finding.rule for finding in report.findings}

    assert not (severities & {"high", "critical"})
    assert "AGENT_WITH_WRITE_TOKEN" not in rules
    assert "UNTRUSTED_INPUT_TO_AGENT" not in rules


def test_ai_autofix_fixture_pair_exercises_write_boundary() -> None:
    risky_report = scan_repository(EXAMPLES / "risky-ai-autofix.yml")
    safer_report = scan_repository(EXAMPLES / "safer-ai-autofix.yml")

    risky_rules = {finding.rule for finding in risky_report.findings}
    safer_severities = {finding.severity for finding in safer_report.findings}
    safer_rules = {finding.rule for finding in safer_report.findings}

    assert "PULL_REQUEST_TARGET_AGENT" in risky_rules
    assert "UNTRUSTED_INPUT_WITH_SECRETS" in risky_rules
    assert "AGENT_WITH_WRITE_TOKEN" in risky_rules
    assert "AI_GENERATED_CHANGES_PUSHED" in risky_rules
    assert not (safer_severities & {"high", "critical"})
    assert "AGENT_WITH_WRITE_TOKEN" not in safer_rules
    assert "AI_GENERATED_CHANGES_PUSHED" not in safer_rules


def test_workflow_run_handoff_fixture_pair_exercises_handoff_boundary() -> None:
    risky_report = scan_repository(EXAMPLES / "risky-workflow-run-handoff.yml")
    safer_report = scan_repository(EXAMPLES / "safer-workflow-run-handoff.yml")

    risky_rules = {finding.rule for finding in risky_report.findings}
    safer_severities = {finding.severity for finding in safer_report.findings}

    assert "WORKFLOW_RUN_AGENT_HANDOFF" in risky_rules
    assert "AGENT_WITH_WRITE_TOKEN" in risky_rules
    assert not (safer_severities & {"high", "critical"})


def test_comment_triggered_fixture_pair_exercises_comment_boundary() -> None:
    risky_report = scan_repository(EXAMPLES / "risky-comment-triggered-review.yml")
    safer_report = scan_repository(EXAMPLES / "safer-comment-triggered-review.yml")

    risky_rules = {finding.rule for finding in risky_report.findings}
    safer_severities = {finding.severity for finding in safer_report.findings}
    safer_rules = {finding.rule for finding in safer_report.findings}

    assert "UNTRUSTED_INPUT_WITH_SECRETS" in risky_rules
    assert "AGENT_WITH_WRITE_TOKEN" in risky_rules
    assert "AI_OUTPUT_TO_SHELL" in risky_rules
    assert "AI_GENERATED_CHANGES_PUSHED" in risky_rules
    assert not (safer_severities & {"high", "critical"})
    assert "UNTRUSTED_INPUT_TO_AGENT" not in safer_rules


def test_scheduled_batch_triage_fixture_pair_exercises_batch_boundary() -> None:
    risky_report = scan_repository(EXAMPLES / "risky-scheduled-batch-triage.yml")
    safer_report = scan_repository(EXAMPLES / "safer-scheduled-batch-triage.yml")

    risky_rules = {finding.rule for finding in risky_report.findings}
    safer_severities = {finding.severity for finding in safer_report.findings}
    safer_rules = {finding.rule for finding in safer_report.findings}

    assert "UNTRUSTED_INPUT_WITH_SECRETS" in risky_rules
    assert "AGENT_WITH_WRITE_TOKEN" in risky_rules
    assert "AI_OUTPUT_TO_SHELL" in risky_rules
    assert "AI_GENERATED_CHANGES_PUSHED" in risky_rules
    assert not (safer_severities & {"high", "critical"})
    assert "AGENT_WITH_WRITE_TOKEN" not in safer_rules


def test_reusable_workflow_input_fixture_exercises_inputs_boundary() -> None:
    report = scan_repository(EXAMPLES / "risky-reusable-workflow-input.yml")

    rules = {finding.rule for finding in report.findings}
    assert "UNTRUSTED_INPUT_TO_AGENT" in rules
    assert "AGENT_WITH_WRITE_TOKEN" in rules
