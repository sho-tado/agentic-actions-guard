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
      "rationale": "Temporary while the team replaces the shell step with a report artifact upload.",
      "removal_condition": "The workflow uploads a report artifact instead of running a shell step."
    }
  ]
}
```

Run with:

```powershell
agentic-actions-guard scan . --allowlist agentic-actions-guard.allowlist.json --fail-on high
```

Apply stricter accepted-risk checks during the scan itself:

```powershell
agentic-actions-guard scan . --allowlist agentic-actions-guard.allowlist.json --allowlist-max-expiry-days 30 --allowlist-require-removal-condition --fail-on high
```

The composite GitHub Action exposes the same controls:

```yaml
- uses: sho-tado/agentic-actions-guard@v1.10.19
  with:
    allowlist: agentic-actions-guard.allowlist.json
    allowlist-max-expiry-days: "30"
    allowlist-require-removal-condition: "true"
```

Validate a policy file before adding it to CI:

```powershell
agentic-actions-guard validate-allowlist agentic-actions-guard.allowlist.json
```

For stricter review cadence checks, reject accepted risks whose expiry is too far in the future:

```powershell
agentic-actions-guard validate-allowlist agentic-actions-guard.allowlist.json --max-expiry-days 30
```

Require every accepted risk to document how it will be removed:

```powershell
agentic-actions-guard validate-allowlist agentic-actions-guard.allowlist.json --require-removal-condition
```

## Matching

Each allowlist entry must include a non-empty `reason`, `owner`, `expires`, and `rationale`, plus at least one matcher:

- `rule`: exact known rule ID; unknown rule IDs are rejected so typos cannot create silent no-op policies
- `path`: exact workflow path or path substring; Windows `\` separators are normalized to `/`
- `evidence`: exact evidence text or evidence substring
- `reason`: required human-readable reason for accepting the finding
- `owner`: required person, team, or maintainer group responsible for review
- `expires`: required `YYYY-MM-DD` date; expired entries are rejected
- `rationale`: required explanation of why the risk is temporarily accepted instead of fixed now
- `removal_condition`: optional by default; required when `scan --allowlist-require-removal-condition` or `validate-allowlist --require-removal-condition` is used

All provided match fields must match. Omitted match fields match any value, so a broad rule-only entry suppresses every matching rule across every workflow. Reason-only entries are rejected because they would suppress every finding.

## Output

Suppressed findings are excluded from active findings and CI failure decisions. Reports include suppressed counts, matched rules, locations, evidence, reasons, owners, expiry dates, rationales, and removal conditions so accepted risks stay visible. Markdown reports, maintainer review reports, and GitHub Actions step summaries also include an accepted-risk review queue sorted by expiry date. JSON output keeps `suppressed_findings` for compatibility and also includes `suppressions` with the matched allowlist entry. SARIF output keeps suppressed findings out of active `results`, but records accepted-risk metadata in `runs[0].properties.suppressions` for downstream audit trails. Policies with a missing or blank required field, an unknown `rule`, an invalid or expired `expires` date, an expiry beyond `scan --allowlist-max-expiry-days` or `validate-allowlist --max-expiry-days`, a missing removal condition when `--allowlist-require-removal-condition` or `--require-removal-condition` is used, or no `rule`, `path`, or `evidence` matcher, are rejected. `validate-allowlist` and `scan --allowlist` use the same validation path and return exit code `2` for invalid policy files.

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
      "rationale": "The existing workflow is needed for launch triage, but writes are limited to PR comments while the two-stage design is implemented.",
      "removal_condition": "Comments move to a separate workflow that runs after maintainer approval."
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
      "rationale": "The job only writes a summary, but checkout credentials should still be removed during the next maintenance window.",
      "removal_condition": "The checkout step sets persist-credentials: false."
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

Avoid broad entries such as `{ "rule": "AGENT_WITH_WRITE_TOKEN", "reason": "accepted temporarily", "owner": "team", "expires": "2026-06-14", "rationale": "temporary launch exception", "removal_condition": "later" }` because they suppress every matching finding across every workflow. Scope accepted risks by workflow path and evidence whenever possible.
