from pathlib import Path

from agentic_actions_guard.scanner import RULE_METADATA


ROOT = Path(__file__).resolve().parents[1]


def test_rule_reference_documents_all_rule_ids() -> None:
    reference = (ROOT / "docs" / "rule-reference.md").read_text(encoding="utf-8")

    for rule_id in RULE_METADATA:
        assert f"`{rule_id}`" in reference


def test_example_review_report_matches_current_fixture_counts() -> None:
    example_report = (ROOT / "docs" / "example-review-report.md").read_text(encoding="utf-8")

    assert "- Findings: `5`" in example_report
    assert "- critical: `1`" in example_report
    assert "- high: `1`" in example_report
    assert "- medium: `2`" in example_report
    assert "- info: `1`" in example_report
