# Accepted Risk Review Cadence

Use this cadence when a maintainer temporarily allowlists an AI workflow finding instead of fixing it immediately.

Accepted risk should stay visible, owned, and time-bound. An allowlist entry is not a permanent exception.

## Minimum Record

For each accepted risk, record:

- rule ID
- workflow path
- evidence or matching scope
- reason for accepting the risk
- owner
- expires date
- rationale for accepting the risk temporarily instead of fixing it now
- removal condition

The allowlist policy supports `rule`, `path`, `evidence`, `reason`, `owner`, `expires`, and `rationale`. Expired entries are rejected so accepted risks cannot suppress findings indefinitely. Track the removal condition next to the policy in an issue, pull request, or security review note.

For concrete high and medium examples, see [Allowlist Policy](allowlist-policy.md#reviewed-examples).

## Suggested Cadence

Use this default schedule:

- critical findings: do not allowlist unless there is a short emergency window and a named owner
- high findings: review within 7 days
- medium findings: review within 30 days
- info findings: review when the AI workflow changes

Shorten the interval when the workflow has secrets, write permissions, `pull_request_target`, `workflow_run` handoffs, shell execution, release automation, package publishing, or deployment credentials.

## Review Questions

Before each expiry date, ask:

- Does the finding still exist?
- Has the workflow gained new secrets, write permissions, shell steps, or privileged events?
- Is the allowlist match still narrow enough?
- Is there now a safer two-stage design?
- Can the accepted risk be removed instead of renewed?
- Is the owner still responsible for the workflow?

## Example Tracking Note

```markdown
Accepted risk:

- Rule: AGENT_JOB_RUNS_SHELL
- Path: .github/workflows/ai-review.yml
- Evidence: run: ./scripts/fixed-review.sh
- Reason: Shell step uses fixed commands and does not consume model output.
- Owner: maintainer-team
- Expires: 2026-07-01
- Rationale: The shell step is fixed and reviewed, but the team plans to replace it with a report artifact upload.
- Removal condition: replace shell step with report artifact upload
```

## CI Use

Run allowlisted scans with an explicit policy file:

```powershell
agentic-actions-guard scan . --allowlist agentic-actions-guard.allowlist.json --fail-on high
```

Suppressed findings stay out of CI failure decisions, but reports include suppressed counts, owners, expiry dates, rationales, and reasons so accepted risks remain visible.

Markdown reports, maintainer review reports, and GitHub Actions step summaries include an accepted-risk review queue sorted by expiry date. Use that queue during maintenance windows to renew, narrow, or remove accepted risks before they expire.

See [Allowlist Policy](allowlist-policy.md), [Risk Matrix](risk-matrix.md), and [Maintainer Opt-In Review Response Flow](review-response-flow.md).
