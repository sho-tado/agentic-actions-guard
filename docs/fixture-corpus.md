# Fixture Corpus

The `examples/` directory contains public-safe workflow fixtures used by the test suite and documentation. These files are synthetic. They are designed to exercise scanner behavior without copying private repository workflows or disclosing real maintainer prompts.

## Risky Fixtures

| Fixture | Pattern covered |
|---|---|
| `risky-ai-triage.yml` | Issue triage workflow that combines untrusted issue text, an AI action, secrets, write permissions, and shell execution. |
| `risky-ai-autofix.yml` | Auto-fix workflow that combines `pull_request_target`, fork-controlled checkout, AI patching, secrets, write permissions, and direct commit/push mutation. |
| `risky-ai-output-shell.yml` | AI step output interpolated into a shell command that writes back to an issue. |
| `risky-comment-triggered-review.yml` | Comment-triggered AI review workflow that sends public comment text to AI automation near secrets, write permissions, and shell comment output. |
| `risky-pr-review.yml` | PR review workflow pattern for untrusted pull request text and AI review automation. |
| `risky-release-notes.yml` | Release-note automation pattern where commit or event text can reach AI automation. |
| `risky-workflow-run-handoff.yml` | `workflow_run` handoff pattern where an upstream AI plan is consumed by a privileged follow-up job. |

Risky fixtures should produce at least one high or critical finding.

## Safer Fixtures

| Fixture | Pattern covered |
|---|---|
| `safer-readonly-review.yml` | Read-only AI review job with explicit permissions. |
| `safer-ai-autofix.yml` | Maintainer-dispatched auto-fix planning workflow that produces a review artifact instead of pushing changes. |
| `safer-ai-output-report.yml` | AI-style analysis output written as a report artifact instead of interpolated into shell execution. |
| `safer-comment-triggered-review.yml` | Comment-triggered review workflow that keeps permissions read-only and writes only a synthetic review artifact. |
| `safer-release-notes.yml` | Maintainer-dispatched release note draft that keeps credentials read-only and writes an artifact for review. |
| `safer-two-stage-triage.yml` | Two-stage pattern that separates AI analysis from maintainer-controlled write operations. |
| `safer-workflow-run-handoff.yml` | `workflow_run` handoff pattern that keeps permissions read-only and turns upstream output into a review artifact. |

Safer fixtures should not produce high or critical findings.

## Policy Fixture

| Fixture | Pattern covered |
|---|---|
| `agentic-actions-guard.allowlist.json` | Example allowlist entry for reviewed accepted risk. |

## Maintenance Rules

When adding a fixture:

1. Keep it synthetic and public-safe.
2. Avoid secrets, private prompts, private repository names, or real exploit payloads.
3. Add or update tests so risky fixtures produce high or critical findings and safer fixtures do not.
4. Update this page when the fixture represents a new workflow family.

The fixture corpus is intentionally small. It should grow only when a new example clarifies a maintainer decision or prevents a scanner regression.
