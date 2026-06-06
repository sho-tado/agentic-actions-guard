# Two-Stage AI Workflow Pattern

Use this pattern when an AI workflow reads public issue, pull request, comment, branch, or dispatch input and may later update repository state.

The core rule is simple: let AI analysis read untrusted input, but make repository writes happen in a separate maintainer-approved stage.

## When To Use It

Use a two-stage workflow for:

- issue triage and labeling
- pull request review summaries
- release-note drafts
- auto-fix suggestions
- dependency or security report summaries

This pattern is most important when a workflow would otherwise combine untrusted GitHub event text with secrets, write permissions, `pull_request_target`, checkout credentials, or shell execution.

## Stage 1: Read-Only AI Analysis

The analysis stage should:

- run with `contents: read`
- avoid repository write permissions
- avoid release, package, cloud, or deployment secrets
- write a report artifact, Markdown summary, SARIF file, or constrained JSON plan
- treat issue bodies, PR bodies, comments, commit messages, branch names, and dispatch payloads as untrusted

## Stage 2: Maintainer-Controlled Write

The write stage should:

- require an explicit maintainer action, such as a label, manual dispatch, environment approval, or reviewed pull request
- use the smallest write scope needed, such as `issues: write`
- consume only a constrained plan, not arbitrary model output
- validate labels, commands, paths, package names, branches, and shell parameters against allowlists
- keep release, deploy, publish, and merge actions outside the AI analysis job

## Compact Example

```yaml
name: two-stage-ai-triage

on:
  issues:
    types: [opened]
  workflow_dispatch:
    inputs:
      issue_number:
        required: true
        type: string

permissions:
  contents: read

jobs:
  analyze:
    if: github.event_name == 'issues'
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - name: Build triage report
        run: |
          mkdir -p out
          echo "# Triage report" > out/triage.md
          echo "Review this report before applying labels." >> out/triage.md
      - uses: actions/upload-artifact@v4
        with:
          name: triage-report
          path: out/triage.md

  apply-reviewed-label:
    if: github.event_name == 'workflow_dispatch'
    permissions:
      contents: read
      issues: write
    runs-on: ubuntu-latest
    steps:
      - name: Apply allowlisted label after maintainer review
        env:
          GH_TOKEN: ${{ github.token }}
          ISSUE_NUMBER: ${{ inputs.issue_number }}
        run: gh issue edit "$ISSUE_NUMBER" --add-label "needs-maintainer-review"
```

The example keeps the public `issues` event read-only. The write operation moves to a manual stage with a fixed label and explicit `issues: write` permission.

## Scanner Rules This Pattern Reduces

Two-stage designs reduce or eliminate findings from:

- [`UNTRUSTED_INPUT_WITH_SECRETS`](rule-reference.md)
- [`UNTRUSTED_INPUT_TO_AGENT`](rule-reference.md)
- [`AGENT_WITH_WRITE_TOKEN`](rule-reference.md)
- [`PULL_REQUEST_TARGET_AGENT`](rule-reference.md)
- [`AI_OUTPUT_TO_SHELL`](rule-reference.md)
- [`AI_GENERATED_CHANGES_PUSHED`](rule-reference.md)

They also make medium-severity hardening easier to review:

- [`MISSING_EXPLICIT_PERMISSIONS`](rule-reference.md)
- [`CHECKOUT_CREDENTIALS_IN_AGENT_JOB`](rule-reference.md)
- [`AGENT_JOB_RUNS_SHELL`](rule-reference.md)
- [`UNPINNED_AI_ACTION_REF`](rule-reference.md)

## Review Checklist

Before enabling the workflow, verify:

- untrusted GitHub event text is processed only in read-only jobs
- AI output is stored as a report or constrained plan
- write permissions appear only in the maintainer-approved stage
- shell commands do not interpolate AI output
- AI-generated patches are reviewed before commit, push, merge, release, or comment actions
- checkout uses `persist-credentials: false` in AI-related jobs that do not push
- AI action refs are pinned to reviewed full-length commit SHAs
- accepted risks are documented with a scoped allowlist entry

See [AI GitHub Actions Safety Checklist](ai-github-actions-safety-checklist.md), [Rule Reference](rule-reference.md), and [Risk Matrix](risk-matrix.md) for the full review model.

For AI auto-fix workflows, see [AI Patch Handoff Recipe](ai-patch-handoff.md).
