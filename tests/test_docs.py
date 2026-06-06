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


def test_action_pinning_guide_documents_unpinned_rule() -> None:
    guide = (ROOT / "docs" / "action-pinning.md").read_text(encoding="utf-8")
    checklist = (ROOT / "docs" / "ai-github-actions-safety-checklist.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "`UNPINNED_AI_ACTION_REF`" in guide
    assert "full-length commit SHA" in guide
    assert "action-pinning.md" in checklist
    assert "docs/action-pinning.md" in readme


def test_maintainer_review_playbook_is_linked_from_entrypoints() -> None:
    playbook = (ROOT / "docs" / "maintainer-review-playbook.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    request_docs = (ROOT / "docs" / "request-workflow-review.md").read_text(encoding="utf-8")
    checklist = (ROOT / "docs" / "ai-github-actions-safety-checklist.md").read_text(encoding="utf-8")

    assert "15 Minute Review" in playbook
    assert "AI output to shell" in playbook
    assert "docs/maintainer-review-playbook.md" in readme
    assert "maintainer-review-playbook.md" in request_docs
    assert "maintainer-review-playbook.md" in checklist


def test_adoption_recipes_are_linked_from_entrypoints() -> None:
    recipes = (ROOT / "docs" / "adoption-recipes.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    code_scanning = (ROOT / "docs" / "github-code-scanning.md").read_text(encoding="utf-8")
    request_docs = (ROOT / "docs" / "request-workflow-review.md").read_text(encoding="utf-8")

    assert "Recipe 1: Local Maintainer Review" in recipes
    assert "Recipe 3: Code Scanning SARIF" in recipes
    assert "sho-tado/agentic-actions-guard@v1.7.1" in recipes
    assert "docs/adoption-recipes.md" in readme
    assert "adoption-recipes.md" in code_scanning
    assert "adoption-recipes.md" in request_docs
