# Adoption Recipes

Use these copy-paste recipes when adding `agentic-actions-guard` to a public repository. Start with the least disruptive mode, then tighten the gate after maintainers understand expected findings.

For drop-in workflow files, see [Workflow Templates](workflow-templates.md).

## Recipe 1: Local Maintainer Review

Use this before opening a workflow hardening issue or pull request.

```powershell
python -m pip install git+https://github.com/sho-tado/agentic-actions-guard.git@v1.10.32
agentic-actions-guard scan . --format review --review-target owner/repo --fail-on critical
```

Good for:

- first review before adding CI
- public review request reproduction
- maintainer handoff notes

For the compact Actions UI output used by the workflow recipes below, see [GitHub Actions Step Summary Example](step-summary-example.md).

## Recipe 2: Pull Request Annotations

Use annotations when you want lightweight feedback in workflow-changing pull requests without enabling SARIF upload yet.

```yaml
name: agentic-actions-guard-annotations

on:
  pull_request:
    paths:
      - ".github/workflows/**"

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: sho-tado/agentic-actions-guard@v1.10.32
        with:
          path: .
          format: annotations
          fail-on: critical
          output: agentic-actions-guard.annotations
          step-summary: "true"
```

Good for:

- early rollout
- repositories without code scanning enabled
- keeping review comments close to workflow changes

## Recipe 3: Code Scanning SARIF

Use SARIF when the repository already uses GitHub code scanning or wants a persistent security view.

```yaml
name: agentic-actions-guard

on:
  pull_request:
    paths:
      - ".github/workflows/**"
  push:
    branches: [main]
    paths:
      - ".github/workflows/**"

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: sho-tado/agentic-actions-guard@v1.10.32
        with:
          path: .
          format: sarif
          fail-on: critical
          output: agentic-actions-guard.sarif
          step-summary: "true"
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: agentic-actions-guard.sarif
```

Good for:

- security review history
- default-branch monitoring
- maintainer teams that already review code scanning alerts

## Recipe 4: Reviewed Risk Allowlist

Use an allowlist only when a finding is reviewed, documented, scoped, and time-bound.

```powershell
agentic-actions-guard scan . --allowlist agentic-actions-guard.allowlist.json --fail-on high
```

For stricter accepted-risk hygiene in CI:

```powershell
agentic-actions-guard scan . --allowlist agentic-actions-guard.allowlist.json --allowlist-max-expiry-days 30 --allowlist-require-removal-condition --fail-on high
```

Good for:

- temporary accepted risks
- staged migrations from high findings
- documenting why a workflow boundary remains in place

Do not use allowlists to hide unknown AI workflow behavior.

## Rollout Path

1. Run local review.
2. Add pull request annotations with `fail-on: critical`.
3. Fix or document critical findings.
4. Enable SARIF upload on the default branch.
5. Move to `fail-on: high` after expected high findings are fixed or explicitly accepted.

When a workflow needs AI analysis and repository writes, use the [Two-Stage AI Workflow Pattern](two-stage-ai-workflows.md) to keep public event input separate from maintainer-approved mutation.

When a workflow drafts fixes, use the [AI Patch Handoff Recipe](ai-patch-handoff.md) to keep generated patches as review artifacts before any commit, push, merge, release, or comment action.
