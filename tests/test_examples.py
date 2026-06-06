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
