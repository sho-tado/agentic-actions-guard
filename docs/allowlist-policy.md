# Allowlist Policy

Use an allowlist policy when a repository has reviewed and accepted a finding temporarily, but still wants CI to fail on new or unreviewed findings.

Policies are JSON files with an `allowlist` array.

```json
{
  "allowlist": [
    {
      "rule": "AGENT_JOB_RUNS_SHELL",
      "path": ".github/workflows/ai-review.yml",
      "reason": "Shell step uses fixed commands and does not consume model output."
    }
  ]
}
```

Run with:

```powershell
agentic-actions-guard scan . --allowlist agentic-actions-guard.allowlist.json --fail-on high
```

## Matching

Each allowlist entry must include a non-empty `reason` and can narrow the match with:

- `rule`: exact rule ID
- `path`: exact workflow path or path substring
- `evidence`: exact evidence text or evidence substring
- `reason`: required human-readable reason for accepting the finding

All provided match fields must match. Omitted match fields match any value, but avoid broad entries without `path` or `evidence` unless the accepted risk has been reviewed explicitly.

## Output

Suppressed findings are excluded from active findings and CI failure decisions. Reports include suppressed counts so accepted risks stay visible. Policies with a missing or blank `reason` are rejected.

Review allowlists periodically. Prefer fixing findings over suppressing them permanently.

For a practical owner and review-date process, see [Accepted Risk Review Cadence](accepted-risk-cadence.md).

## Reviewed Examples

Use narrow matches. These examples are synthetic and show how to suppress a reviewed finding while keeping the acceptance reason explicit.

High finding example:

```json
{
  "allowlist": [
    {
      "rule": "AGENT_WITH_WRITE_TOKEN",
      "path": ".github/workflows/ai-review.yml",
      "evidence": "pull-requests: write",
      "reason": "Temporarily accepted while the team moves PR comments into a maintainer-approved follow-up workflow."
    }
  ]
}
```

Tracking note:

```markdown
Accepted risk:

- Rule: AGENT_WITH_WRITE_TOKEN
- Path: .github/workflows/ai-review.yml
- Evidence: pull-requests: write
- Owner: maintainer-team
- Review date: 2026-06-14
- Removal condition: comments move to a separate workflow that runs after maintainer approval
```

Medium finding example:

```json
{
  "allowlist": [
    {
      "rule": "CHECKOUT_CREDENTIALS_IN_AGENT_JOB",
      "path": ".github/workflows/ai-summary.yml",
      "evidence": "actions/checkout",
      "reason": "Temporarily accepted for a read-only summary job while persist-credentials is changed to false."
    }
  ]
}
```

Tracking note:

```markdown
Accepted risk:

- Rule: CHECKOUT_CREDENTIALS_IN_AGENT_JOB
- Path: .github/workflows/ai-summary.yml
- Evidence: actions/checkout
- Owner: maintainer-team
- Review date: 2026-07-07
- Removal condition: checkout step sets persist-credentials: false
```

Avoid broad entries such as `{ "rule": "AGENT_WITH_WRITE_TOKEN" }` because they suppress every matching finding across every workflow. Scope accepted risks by workflow path and evidence whenever possible.
