# Finding Lifecycle And Output Contract

This document describes how `agentic-actions-guard` turns workflow files into findings, accepted-risk suppressions, and maintainer-facing output. Use it when deciding whether a report is ready to share, whether an allowlist entry is scoped enough, or whether a CI gate should fail.

## Finding Lifecycle

1. **Input collection**: the scanner reads workflow YAML files and public workflow text from the target path. It does not execute workflows, call models, call external APIs, or inspect repository secrets.
2. **Rule evaluation**: rules look for risky workflow boundaries such as untrusted GitHub event text, AI or agent steps, secrets, broad tokens, `pull_request_target`, checkout credentials, mutable AI action refs, AI output to shell, privileged `workflow_run` handoffs, and AI-generated repository mutation.
3. **Finding normalization**: each finding receives a stable rule ID, severity, workflow path, line number when available, public evidence, and remediation guidance.
4. **Accepted-risk policy application**: allowlist entries suppress only matching findings after policy validation. Entries need a reason, owner, expires date, rationale, and at least one matcher. `removal_condition` is optional by default and required when `validate-allowlist --require-removal-condition` is used.
5. **Output rendering**: active findings and accepted risks are rendered for the requested surface: Markdown, maintainer review, summary, annotations, JSON, or SARIF.
6. **CI gate decision**: `--fail-on` evaluates only active findings at or above the selected severity. Suppressed accepted risks remain visible in reports but do not fail the gate.
7. **Maintainer decision**: maintainers fix the workflow boundary, accept a narrow time-bound risk, lower the gate while fixes are planned, or decline a finding. A declined finding should not be reposted unchanged.
8. **Re-scan after workflow changes**: workflow edits, allowlist expiry, or removal-condition completion should trigger another scan and allowlist validation.

## Output Contract

| Surface | Intended use | Includes | Does not imply |
| --- | --- | --- | --- |
| Markdown | local triage and issue notes | active findings, severity summary, accepted-risk review queue | proof of exploitability |
| Review | maintainer-facing public report | scope, counts, top findings, fixes, reproduction command, accepted risks | maintainer opt-in or vulnerability confirmation |
| Summary | GitHub Actions step summary | compact counts, active findings, accepted-risk queue | complete audit trail |
| Annotations | lightweight pull request feedback | active findings as workflow log annotations | accepted risks as active alerts |
| JSON | downstream automation | `findings`, `suppressed_findings`, `suppressions`, `allowlist_entries`, summary fields | schema stability beyond documented fields |
| SARIF | GitHub code scanning and security tooling | active `runs[].results`, rule metadata, accepted-risk metadata in `runs[0].properties.suppressions` | suppressed accepted risks as active alerts |

Suppressed accepted risks are excluded from active findings and CI failure decisions. They stay visible through review queues and suppression metadata so accepted risk does not become invisible risk.

## Severity Contract

Severity is review priority, not proof of exploitation.

- `critical`: untrusted GitHub event text appears near secrets or privileged tokens.
- `high`: write permissions, `pull_request_target`, AI output to shell, privileged handoffs, or AI-generated repository mutation need maintainer review.
- `medium`: hardening work such as explicit permissions, checkout credentials, shell usage, or mutable AI action refs.
- `info`: known AI maintainer action context or other low-priority review notes.

Stable rule IDs are listed in [Rule Reference](rule-reference.md). The scanner may add new rules over time, but existing rule IDs should remain stable enough for allowlist and report automation.

## Accepted Risk Contract

An accepted risk is a reviewed, time-bound decision. It is not a way to hide warnings.

Allowlist entries must include:

- `reason`: short human-readable acceptance reason
- `owner`: person, team, or maintainer group responsible for review
- `expires`: `YYYY-MM-DD` date that has not expired
- `rationale`: why the risk is accepted instead of fixed now
- at least one matcher: exact known `rule`, workflow `path`, or `evidence`

When stricter review discipline is needed, require:

- `removal_condition`: the workflow state that lets maintainers remove the accepted risk
- `validate-allowlist --max-expiry-days N`: maximum review window
- `validate-allowlist --require-removal-condition`: every entry documents the exit condition

Matcher behavior is intentionally conservative: unknown `rule` IDs are rejected, `rule` matching is exact, and Windows `\` path separators are normalized to `/` before path matching. See [Allowlist Policy](allowlist-policy.md) and [Accepted Risk Review Cadence](accepted-risk-cadence.md).

## Public Review Contract

Public reports should be consent-first and scoped to public evidence.

- Do not publish third-party repository-specific findings before maintainer opt-in.
- Do not include secrets, tokens, private prompts, private repository content, or exploit payloads.
- Include workflow path, line number when available, rule ID, severity, short public evidence, why the boundary matters, a practical fix, and a reproduction command.
- Frame findings as workflow-boundary hardening advice, not as proof of compromise.
- Record accepted risks with owner, expiry date, rationale, and removal condition.

See [Maintainer Opt-In Review Response Flow](review-response-flow.md) for the report process.

## Non-Goals

`agentic-actions-guard` does not:

- execute workflows
- call AI models or external APIs
- inspect secrets, tokens, private prompts, or private repositories
- prove exploitability
- replace a full security audit
- infer maintainer intent
- publish findings without review consent

## Design Checks

Before publishing a release or report:

- run the test suite
- run a self-scan of this repository
- validate any allowlist with the intended strictness flags
- check that report text does not contain non-public evidence
- verify that public issue, release, wiki, or X URLs are reachable before recording them as evidence
