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


def test_curated_action_docs_list_known_profile_examples() -> None:
    curated = (ROOT / "docs" / "curated-ai-actions.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    reference = (ROOT / "docs" / "rule-reference.md").read_text(encoding="utf-8")

    assert "anthropics/claude-code-action@v1" in curated
    assert "google-github-actions/run-gemini-cli@v1" in curated
    assert "QwenLM/qwen-code-action@v0.1.1" in curated
    assert "iflow-ai/iflow-cli-action@v1" in curated
    assert "github/ai-assessment-comment-labeler@v1" in curated
    assert "alexyan0431/issue-ai-agent@v1" in curated
    assert "clouatre-labs/aptu@v1" in curated
    assert "`CURATED_AI_ACTION_DETECTED`" in curated
    assert "docs/curated-ai-actions.md" in readme
    assert "`CURATED_AI_ACTION_DETECTED`" in reference


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
    assert "sho-tado/agentic-actions-guard@v1.10.14" in recipes
    assert "docs/adoption-recipes.md" in readme
    assert "adoption-recipes.md" in code_scanning
    assert "adoption-recipes.md" in request_docs


def test_risk_matrix_documents_all_rule_ids_and_is_linked() -> None:
    matrix = (ROOT / "docs" / "risk-matrix.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    reference = (ROOT / "docs" / "rule-reference.md").read_text(encoding="utf-8")
    playbook = (ROOT / "docs" / "maintainer-review-playbook.md").read_text(encoding="utf-8")

    for rule_id in RULE_METADATA:
        assert f"`{rule_id}`" in matrix
    assert "Release Gate Guidance" in matrix
    assert "docs/risk-matrix.md" in readme
    assert "risk-matrix.md" in reference
    assert "risk-matrix.md" in playbook


def test_two_stage_workflow_pattern_is_linked_from_entrypoints() -> None:
    pattern = (ROOT / "docs" / "two-stage-ai-workflows.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    checklist = (ROOT / "docs" / "ai-github-actions-safety-checklist.md").read_text(encoding="utf-8")
    recipes = (ROOT / "docs" / "adoption-recipes.md").read_text(encoding="utf-8")
    playbook = (ROOT / "docs" / "maintainer-review-playbook.md").read_text(encoding="utf-8")

    assert "Two-Stage AI Workflow Pattern" in pattern
    assert "workflow_dispatch" in pattern
    assert "rule-reference.md" in pattern
    assert "ai-github-actions-safety-checklist.md" in pattern
    assert "docs/two-stage-ai-workflows.md" in readme
    assert "two-stage-ai-workflows.md" in checklist
    assert "two-stage-ai-workflows.md" in recipes
    assert "two-stage-ai-workflows.md" in playbook


def test_review_response_flow_is_linked_from_entrypoints() -> None:
    flow = (ROOT / "docs" / "review-response-flow.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    request_docs = (ROOT / "docs" / "request-workflow-review.md").read_text(encoding="utf-8")
    playbook = (ROOT / "docs" / "maintainer-review-playbook.md").read_text(encoding="utf-8")

    assert "Maintainer Opt-In Review Response Flow" in flow
    assert "Do not include" in flow or "Reports should not include" in flow
    assert "proof of exploitability" in flow
    assert "docs/review-response-flow.md" in readme
    assert "review-response-flow.md" in request_docs
    assert "review-response-flow.md" in playbook


def test_accepted_risk_cadence_is_linked_from_entrypoints() -> None:
    cadence = (ROOT / "docs" / "accepted-risk-cadence.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    allowlist = (ROOT / "docs" / "allowlist-policy.md").read_text(encoding="utf-8")
    matrix = (ROOT / "docs" / "risk-matrix.md").read_text(encoding="utf-8")
    response = (ROOT / "docs" / "review-response-flow.md").read_text(encoding="utf-8")

    assert "Accepted Risk Review Cadence" in cadence
    assert "owner" in cadence
    assert "expires date" in cadence
    assert "removal condition" in cadence
    assert "docs/accepted-risk-cadence.md" in readme
    assert "accepted-risk-cadence.md" in allowlist
    assert "accepted-risk-cadence.md" in matrix
    assert "accepted-risk-cadence.md" in response


def test_allowlist_policy_documents_reviewed_examples() -> None:
    allowlist = (ROOT / "docs" / "allowlist-policy.md").read_text(encoding="utf-8")
    cadence = (ROOT / "docs" / "accepted-risk-cadence.md").read_text(encoding="utf-8")

    assert "Reviewed Examples" in allowlist
    assert "`AGENT_WITH_WRITE_TOKEN`" in allowlist or '"rule": "AGENT_WITH_WRITE_TOKEN"' in allowlist
    assert '"rule": "CHECKOUT_CREDENTIALS_IN_AGENT_JOB"' in allowlist
    assert "Owner: maintainer-team" in allowlist
    assert "Expires: 2026-06-14" in allowlist
    assert "Expires: 2026-07-07" in allowlist
    assert '"owner": "maintainer-team"' in allowlist
    assert '"expires": "2026-06-14"' in allowlist
    assert '"rationale":' in allowlist
    assert "Removal condition" in allowlist
    assert "Avoid broad entries" in allowlist
    assert "at least one matcher" in allowlist
    assert "unknown `rule`" in allowlist
    assert "Windows `\\` separators are normalized to `/`" in allowlist
    assert "Reason-only entries are rejected" in allowlist
    assert "suppressions" in allowlist
    assert "expiry dates" in allowlist
    assert "--max-expiry-days 30" in allowlist
    assert "--require-removal-condition" in allowlist
    assert '"removal_condition":' in allowlist
    assert "allowlist-policy.md#reviewed-examples" in cadence


def test_workflow_run_handoff_hardening_is_linked_from_entrypoints() -> None:
    handoff = (ROOT / "docs" / "workflow-run-handoff.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    checklist = (ROOT / "docs" / "ai-github-actions-safety-checklist.md").read_text(encoding="utf-8")
    matrix = (ROOT / "docs" / "risk-matrix.md").read_text(encoding="utf-8")
    playbook = (ROOT / "docs" / "maintainer-review-playbook.md").read_text(encoding="utf-8")

    assert "Workflow Run Handoff Hardening" in handoff
    assert "`WORKFLOW_RUN_AGENT_HANDOFF`" in handoff
    assert "upstream artifacts and outputs" in handoff
    assert "rule-reference.md" in handoff
    assert "risk-matrix.md" in handoff
    assert "two-stage-ai-workflows.md" in handoff
    assert "docs/workflow-run-handoff.md" in readme
    assert "workflow-run-handoff.md" in checklist
    assert "workflow-run-handoff.md" in matrix
    assert "workflow-run-handoff.md" in playbook


def test_ai_patch_handoff_recipe_is_linked_from_entrypoints() -> None:
    handoff = (ROOT / "docs" / "ai-patch-handoff.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    recipes = (ROOT / "docs" / "adoption-recipes.md").read_text(encoding="utf-8")
    pattern = (ROOT / "docs" / "two-stage-ai-workflows.md").read_text(encoding="utf-8")
    playbook = (ROOT / "docs" / "maintainer-review-playbook.md").read_text(encoding="utf-8")

    assert "AI Patch Handoff Recipe" in handoff
    assert "`AI_GENERATED_CHANGES_PUSHED`" in handoff
    assert "pull_request_target" in handoff
    assert "persist-credentials: false" in handoff
    assert "accepted-risk-cadence.md" in handoff
    assert "docs/ai-patch-handoff.md" in readme
    assert "ai-patch-handoff.md" in recipes
    assert "ai-patch-handoff.md" in pattern
    assert "ai-patch-handoff.md" in playbook


def test_workflow_templates_are_linked_from_entrypoints() -> None:
    templates = (ROOT / "docs" / "workflow-templates.md").read_text(encoding="utf-8")
    step_summary = (ROOT / "docs" / "step-summary-example.md").read_text(encoding="utf-8")
    annotations = (ROOT / "docs" / "workflow-templates" / "agentic-actions-guard-annotations.yml").read_text(
        encoding="utf-8"
    )
    sarif = (ROOT / "docs" / "workflow-templates" / "agentic-actions-guard-sarif.yml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    recipes = (ROOT / "docs" / "adoption-recipes.md").read_text(encoding="utf-8")
    code_scanning = (ROOT / "docs" / "github-code-scanning.md").read_text(encoding="utf-8")
    request_docs = (ROOT / "docs" / "request-workflow-review.md").read_text(encoding="utf-8")

    assert "Workflow Templates" in templates
    assert "agentic-actions-guard-annotations.yml" in templates
    assert "agentic-actions-guard-sarif.yml" in templates
    assert "format: annotations" in annotations
    assert "format: sarif" in sarif
    assert "step-summary" in annotations
    assert "step-summary" in sarif
    assert "step-summary-example.md" in templates
    assert "Agentic Actions Guard Summary" in step_summary
    assert "risky-ai-output-shell.yml" in step_summary
    assert "security-events: write" in sarif
    assert "docs/workflow-templates.md" in readme
    assert "workflow-templates.md" in recipes
    assert "workflow-templates.md" in code_scanning
    assert "workflow-templates.md" in request_docs


def test_adoption_decision_report_is_linked_from_entrypoints() -> None:
    decision = (ROOT / "docs" / "adoption-decision-report.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Maintainer Adoption Decision Report" in decision
    assert "Decision Table" in decision
    assert "report-only" in decision
    assert "annotations" in decision
    assert "SARIF" in decision
    assert "fail-on: high" in decision
    assert "workflow-templates.md" in decision
    assert "adoption-recipes.md" in decision
    assert "risk-matrix.md" in decision
    assert "docs/adoption-decision-report.md" in readme


def test_openssf_scorecard_comparison_is_linked_from_entrypoints() -> None:
    comparison = (ROOT / "docs" / "openssf-scorecard-comparison.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "OpenSSF Scorecard Comparison" in comparison
    assert "complement OpenSSF Scorecard" in comparison
    assert "Comparison Table" in comparison
    assert "Risk Matrix" in comparison
    assert "github-code-scanning.md" in comparison
    assert "adoption-recipes.md" in comparison
    assert "scorecard/blob/main/docs/checks.md" in comparison
    assert "docs/openssf-scorecard-comparison.md" in readme


def test_step_summary_example_is_linked_from_entrypoints() -> None:
    step_summary = (ROOT / "docs" / "step-summary-example.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    recipes = (ROOT / "docs" / "adoption-recipes.md").read_text(encoding="utf-8")

    assert "GitHub Actions Step Summary Example" in step_summary
    assert "Agentic Actions Guard Summary" in step_summary
    assert "sho-tado/agentic-actions-guard@v1.10.14" in step_summary
    assert "docs/step-summary-example.md" in readme
    assert "step-summary-example.md" in recipes


def test_workflow_review_request_form_documents_consent_and_scope() -> None:
    form = (ROOT / ".github" / "ISSUE_TEMPLATE" / "workflow_review_request.yml").read_text(encoding="utf-8")
    request_docs = (ROOT / "docs" / "request-workflow-review.md").read_text(encoding="utf-8")

    assert "workflow_scope" in form
    assert "report_location" in form
    assert "maintainer of this repository or have permission" in form
    assert "public best-effort report" in form
    assert "Do not paste secrets" in form
    assert "optional workflow paths" in request_docs
    assert "preferred public report location" in request_docs
    assert "public-report consent" in request_docs
