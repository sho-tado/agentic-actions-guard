# Workflow Run Handoff Hardening

Use this guide when `agentic-actions-guard` reports `WORKFLOW_RUN_AGENT_HANDOFF`.

The finding means an AI-related workflow appears to trigger a privileged `workflow_run` follow-up. The follow-up may have secrets or write permissions while consuming artifacts, outputs, logs, branch names, commit metadata, or other context produced by the upstream AI workflow.

The core boundary is the handoff. Treat upstream artifacts and outputs as untrusted until a maintainer reviews or validates them.

## Why It Matters

`workflow_run` is often used to separate an untrusted first stage from a privileged second stage. That can be a good pattern, but only if the second stage does not blindly trust the first stage.

Risky examples include:

- a first workflow asks an AI tool to produce a release plan, shell script, patch, package name, label, or deployment target
- a second workflow downloads that plan after `workflow_run`
- the second workflow has `contents: write`, `issues: write`, release permissions, deployment credentials, or package tokens
- the second workflow applies the plan without a maintainer approval gate or strict allowlist

In that shape, the first workflow output becomes a trust boundary even when the two stages are in separate workflow files.

## Maintainer Response

When this rule appears:

1. Identify what the upstream workflow can write as artifacts, summaries, outputs, or logs.
2. Identify what the `workflow_run` follow-up can mutate: issues, pull requests, repository contents, releases, packages, deployments, or external systems.
3. Keep the follow-up read-only unless it has an explicit maintainer approval gate.
4. Validate any handoff file as constrained data, not as commands or free-form instructions.
5. Use allowlists for labels, paths, branches, package names, environments, and command arguments.
6. Store AI output as a report artifact when possible, then let a maintainer trigger the write stage manually.

See [Rule Reference](rule-reference.md), [Risk Matrix](risk-matrix.md), and [Two-Stage AI Workflow Pattern](two-stage-ai-workflows.md) for the rule wording and broader design pattern.

## Synthetic Risky Shape

```yaml
name: apply ai plan

on:
  workflow_run:
    workflows: ["ai planning"]
    types: [completed]

permissions:
  contents: write

jobs:
  apply:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: ai-plan
      - name: Apply handoff plan
        run: bash ai-plan.sh
```

This is risky because the follow-up workflow has write permission and executes a handoff file from the upstream AI workflow.

## Safer Shape

```yaml
name: review ai plan

on:
  workflow_run:
    workflows: ["ai planning"]
    types: [completed]
  workflow_dispatch:
    inputs:
      approved_issue:
        required: true
        type: string

permissions:
  contents: read

jobs:
  review-handoff:
    if: github.event_name == 'workflow_run'
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: ai-plan
      - name: Convert handoff to review note
        run: |
          mkdir -p out
          {
            echo "# AI plan review"
            echo
            echo "A maintainer must review this artifact before any write step runs."
          } > out/handoff-review.md
      - uses: actions/upload-artifact@v4
        with:
          name: handoff-review
          path: out/handoff-review.md

  apply-approved-label:
    if: github.event_name == 'workflow_dispatch'
    permissions:
      contents: read
      issues: write
    runs-on: ubuntu-latest
    steps:
      - name: Apply fixed label after maintainer approval
        env:
          GH_TOKEN: ${{ github.token }}
          ISSUE_NUMBER: ${{ inputs.approved_issue }}
        run: gh issue edit "$ISSUE_NUMBER" --add-label "maintainer-reviewed"
```

The safer shape keeps the `workflow_run` stage read-only and turns upstream AI output into review evidence. The write operation moves to a maintainer-triggered stage with a fixed, constrained action.

## Review Checklist

Before accepting the risk, confirm:

- the `workflow_run` job has only the permissions it needs
- the job does not execute downloaded artifacts, AI output, or generated shell
- the job does not pass free-form AI output into release, deployment, package, or repository write commands
- every write operation has an explicit maintainer approval gate
- every accepted exception has an owner, review date, and removal condition

For time-bound exceptions, see [Accepted Risk Review Cadence](accepted-risk-cadence.md).
