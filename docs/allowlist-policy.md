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

Each allowlist entry can contain:

- `rule`: exact rule ID
- `path`: exact workflow path or path substring
- `evidence`: exact evidence text or evidence substring
- `reason`: human-readable reason for accepting the finding

All provided fields must match. Omitted fields match any value.

## Output

Suppressed findings are excluded from active findings and CI failure decisions. Reports include suppressed counts so accepted risks stay visible.

Review allowlists periodically. Prefer fixing findings over suppressing them permanently.

For a practical owner and review-date process, see [Accepted Risk Review Cadence](accepted-risk-cadence.md).
