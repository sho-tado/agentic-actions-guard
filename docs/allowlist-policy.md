# Allowlist Policy

Use an allowlist policy when a repository has reviewed and accepted a finding temporarily, but still wants CI to fail on new or unreviewed findings.

Policies are JSON files with an `allowlist` array.

```json
{
  "allowlist": [
    {
      "rule": "AGENT_JOB_RUNS_SHELL",
      "path": ".github/workflows/ai-review.yml",
      "reason": "Shell step uses fixed commands and does not consume model output.",
      "owner": "maintainer-team",
      "expires": "2026-07-01",
      "rationale": "Temporary while the team replaces the shell step with a report artifact upload."
    }
  ]
}
```

Run with:

```powershell
agentic-actions-guard scan . --allowlist agentic-actions-guard.allowlist.json --fail-on high
```

## Matching

Each allowlist entry must include a non-empty `reason`, `owner`, `expires`, and `rationale`, plus at least one matcher:

- `rule`: exact rule ID
- `path`: exact workflow path or path substring
- `evidence`: exact evidence text or evidence substring
- `reason`: required human-readable reason for accepting the finding
- `owner`: required person, team, or maintainer group responsible for review
- `expires`: required `YYYY-MM-DD` date; expired entries are rejected
- `rationale`: required explanation of why the risk is temporarily accepted instead of fixed now

All provided match fields must match. Omitted match fields match any value, so a broad rule-only entry suppresses every matching rule across every workflow. Reason-only entries are rejected because they would suppress every finding.

## Output

Suppressed findings are excluded from active findings and CI failure decisions. Reports include suppressed counts, matched rules, locations, evidence, reasons, owners, expiry dates, and rationales so accepted risks stay visible. Markdown reports, maintainer review reports, and GitHub Actions step summaries also include an accepted-risk review queue sorted by expiry date. JSON output keeps `suppressed_findings` for compatibility and also includes `suppressions` with the matched allowlist entry. SARIF output keeps suppressed findings out of active `results`, but records accepted-risk metadata in `run.properties.suppressions` for downstream audit trails. Policies with a missing or blank required field, an invalid or expired `expires` date, or no `rule`, `path`, or `evidence` matcher, are rejected.

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
      "reason": "Temporarily accepted while the team moves PR comments into a maintainer-approved follow-up workflow.",
      "owner": "maintainer-team",
      "expires": "2026-06-14",
      "rationale": "The existing workflow is needed for launch triage, but writes are limited to PR comments while the two-stage design is implemented."
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
- Expires: 2026-06-14
- Rationale: The existing workflow is needed for launch triage, but writes are limited to PR comments while the two-stage design is implemented.
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
      "reason": "Temporarily accepted for a read-only summary job while persist-credentials is changed to false.",
      "owner": "maintainer-team",
      "expires": "2026-07-07",
      "rationale": "The job only writes a summary, but checkout credentials should still be removed during the next maintenance window."
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
- Expires: 2026-07-07
- Rationale: The job only writes a summary, but checkout credentials should still be removed during the next maintenance window.
- Removal condition: checkout step sets persist-credentials: false
```

Avoid broad entries such as `{ "rule": "AGENT_WITH_WRITE_TOKEN", "reason": "accepted temporarily", "owner": "team", "expires": "2026-06-14", "rationale": "temporary launch exception" }` because they suppress every matching finding across every workflow. Scope accepted risks by workflow path and evidence whenever possible.
