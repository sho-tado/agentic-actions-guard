# Maintainer Opt-In Review Response Flow

Use this flow after a maintainer explicitly agrees to receive a public workflow safety review.

The goal is to make the review useful without surprising maintainers, disclosing sensitive material, or framing workflow-boundary findings as proven vulnerabilities.

## 1. Confirm Scope

Before sharing a report, confirm:

- repository owner and name
- workflow files or pull requests included in scope
- whether the maintainer wants the report in a public issue, private channel, or pull request
- whether follow-up should be a docs note, issue, or proposed patch

If scope is unclear, share only a short summary and ask where the maintainer wants the full report.

## 2. Share Only Public Evidence

Reports should include:

- workflow path and line number
- rule ID and severity
- short public evidence snippet
- why the boundary matters
- a practical fix or safer target shape
- reproduction command

Reports should not include:

- secrets, tokens, or credentials
- private workflow files
- private prompts
- private repository content
- exploit payloads
- assumptions about maintainer intent

## 3. Frame Severity Carefully

Use severity as review priority, not as proof of exploitation:

- critical: untrusted GitHub event text appears near secrets or privileged tokens
- high: write permissions, `pull_request_target`, AI output to shell, or AI-generated repository mutation need maintainer review
- medium: hardening work such as explicit permissions, checkout credentials, shell usage, or mutable action refs
- info: known AI maintainer action detected for context

State that the scanner does not execute workflows, inspect secrets, call external APIs, or prove exploitability.

## 4. Offer Follow-Up Options

After sharing the report, offer one of these paths:

- maintainer applies fixes independently
- open a focused issue for workflow-boundary hardening
- open a small pull request with docs or workflow changes
- add `agentic-actions-guard` as report-only CI with `fail-on: critical`
- document a reviewed accepted risk with a scoped allowlist entry

Avoid pushing for broad refactors. Keep follow-up changes limited to the reviewed workflow boundary.

## 5. Close The Loop

When the maintainer responds:

- answer questions with links to rule docs and examples
- update the report if the workflow changed
- mark accepted risks as time-bound
- avoid reposting the same finding after a maintainer declines
- record public adoption or feedback only when it is visible or explicitly approved

## Report Template

````markdown
Thanks for opting in. I reviewed only the public workflow files in scope:

- Repository: owner/repo
- Scope: .github/workflows/example.yml
- Tool: agentic-actions-guard vX.Y.Z

Summary:

- critical: N
- high: N
- medium: N
- info: N

Top boundary to review:

- Rule: RULE_ID
- Location: path:line
- Evidence: short public snippet
- Why it matters: concise boundary explanation
- Suggested fix: practical maintainer action

Reproduce:

```powershell
agentic-actions-guard scan . --format review --review-target owner/repo --fail-on critical
```

This is a best-effort workflow safety review, not proof of exploitability or a full security audit.
````

For the review model, see [Request a Workflow Safety Review](request-workflow-review.md), [Maintainer Review Playbook](maintainer-review-playbook.md), [Finding Lifecycle And Output Contract](finding-lifecycle.md), [Risk Matrix](risk-matrix.md), and [Accepted Risk Review Cadence](accepted-risk-cadence.md).
