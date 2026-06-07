# Workflow Templates

Use these templates when adopting `agentic-actions-guard` in a public repository.

Start with annotations when you want lightweight pull request feedback. Move to SARIF when the repository is ready to track findings in GitHub code scanning.

## Annotation Template

Copy [`workflow-templates/agentic-actions-guard-annotations.yml`](workflow-templates/agentic-actions-guard-annotations.yml) to:

```text
.github/workflows/agentic-actions-guard-annotations.yml
```

This template:

- runs only when workflow files change
- uses read-only repository permissions
- emits GitHub Actions annotations
- writes a compact step summary with severity counts, rule breakdowns, and next actions by default
- starts with `fail-on: critical`

## SARIF Template

Copy [`workflow-templates/agentic-actions-guard-sarif.yml`](workflow-templates/agentic-actions-guard-sarif.yml) to:

```text
.github/workflows/agentic-actions-guard.yml
```

This template:

- scans workflow changes on pull requests
- scans the default branch on pushes to `main`
- uploads SARIF to GitHub code scanning
- writes a compact step summary with severity counts, rule breakdowns, and next actions by default
- grants only `contents: read` and `security-events: write`

## Rollout

1. Add the annotation template first.
2. Review any critical findings.
3. Fix or document expected findings.
4. Switch to the SARIF template when code scanning history is useful.
5. Move from `fail-on: critical` to `fail-on: high` after expected high findings are fixed or accepted.

For the rule model, see [Rule Reference](rule-reference.md). For local review commands, see [Adoption Recipes](adoption-recipes.md). For the first-run summary shown in Actions, see [GitHub Actions Step Summary Example](step-summary-example.md).
