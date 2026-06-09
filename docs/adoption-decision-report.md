# Maintainer Adoption Decision Report

Use this example after a local review to decide whether `agentic-actions-guard` should run in report-only, annotations, SARIF, or stricter CI gating mode.

This page uses synthetic scan output only. It is not based on a third-party repository.

Related setup guides:

- [Workflow Templates](workflow-templates.md)
- [Adoption Recipes](adoption-recipes.md)
- [Risk Matrix](risk-matrix.md)

## Synthetic Review Summary

```text
Target: example-org/example-repo
Workflows scanned: 4
Findings: 6

critical: 1
high: 2
medium: 3
low: 0
info: 0
```

Synthetic finding themes:

- `UNTRUSTED_INPUT_WITH_SECRETS`: issue text reaches an AI job that also has a provider API key.
- `AGENT_WITH_WRITE_TOKEN`: the AI review job can write pull request comments.
- `AI_OUTPUT_TO_SHELL`: generated text is interpolated into a shell step.
- `MISSING_EXPLICIT_PERMISSIONS`: one workflow relies on repository token defaults.
- `CHECKOUT_CREDENTIALS_IN_AGENT_JOB`: checkout keeps persisted credentials in an AI-related job.

## Decision Table

| Current finding set | Suggested mode | Why | Next maintainer action |
|---|---|---|---|
| Any `critical` finding | Report-only local review or annotations with `fail-on: critical` | Critical findings usually mean untrusted public text can influence a job with secrets or privileged tokens. | Separate secret use from public event text before enabling SARIF as a default-branch signal. |
| No critical findings, expected `high` findings remain | SARIF with `fail-on: critical` | Maintainers get durable code scanning history without blocking the staged migration. | Open hardening tasks for write-token, `pull_request_target`, `workflow_run`, or AI-output-to-shell boundaries. |
| No critical findings and high findings are fixed or explicitly accepted | SARIF or annotations with `fail-on: high` | CI now blocks new high-risk AI workflow boundaries while allowing medium hardening work to continue. | Keep accepted risks owned, dated, and tied to removal conditions. |
| Only medium or info findings remain | Annotations or SARIF with `fail-on: high` | Medium findings are useful hardening tasks, but usually do not need to stop every workflow change. | Track owners for permission declarations, checkout credentials, and action pinning. |

## Example Decision

For the synthetic summary above, start with:

```powershell
agentic-actions-guard scan . --format review --review-target example-org/example-repo --fail-on critical
```

Then add the annotation template in report-only rollout mode:

```yaml
- uses: sho-tado/agentic-actions-guard@v1.10.29
  with:
    path: .
    format: annotations
    fail-on: critical
    output: agentic-actions-guard.annotations
    step-summary: "true"
```

Recommended decision:

1. Fix the critical secret exposure before making the workflow a required check.
2. Keep annotations enabled so workflow-changing pull requests show findings close to the diff.
3. Add SARIF after the critical finding is fixed, so the default branch has a durable security history.
4. Move to `fail-on: high` only after write-token and AI-output-to-shell findings are fixed or documented as time-bound accepted risks.

## Maintainer Notes

Do not treat a lower `fail-on` threshold as proof that a workflow is safe. It is a rollout control that lets maintainers sequence fixes without hiding risk.

Do not use broad allowlists during first adoption. If a finding must be accepted temporarily, document the owner, expiry date, rationale, and removal condition before suppressing it.

For rule-by-rule prioritization, use the [Risk Matrix](risk-matrix.md). For copy-paste CI files, use [Workflow Templates](workflow-templates.md). For staged rollout commands, use [Adoption Recipes](adoption-recipes.md).
