# Rule Reference

This page documents the stable rule IDs emitted by `agentic-actions-guard`.

Rule IDs are intended to be safe for CI policy, SARIF filtering, GitHub annotations, review reports, and allowlist entries. New rules may be added in minor releases. Existing rule meanings should only change when the safer interpretation is strictly narrower or less noisy.

## Rules

| Rule ID | Default severity | Meaning | Typical fix |
|---|---:|---|---|
| `UNTRUSTED_INPUT_WITH_SECRETS` | critical | An AI workflow appears to combine untrusted GitHub event text with secrets or privileged tokens. | Keep secrets out of jobs that process issue, PR, comment, review, or commit text. Split privileged operations into a separate trusted job. |
| `UNTRUSTED_INPUT_TO_AGENT` | high | Untrusted GitHub event text is passed into AI or agent automation. | Treat event text as hostile input. Sanitize, summarize, or isolate it before agent use. |
| `AGENT_WITH_WRITE_TOKEN` | high | An AI-related workflow has write permissions. | Use least-privilege permissions and split read-only analysis from write operations. |
| `PULL_REQUEST_TARGET_AGENT` | high or critical | An AI-related workflow runs on `pull_request_target`. It becomes critical when it appears to check out fork-controlled content. | Prefer `pull_request` for read-only analysis. Use privileged follow-up jobs only after explicit maintainer approval. |
| `AI_OUTPUT_TO_SHELL` | high | An AI step output appears to be interpolated into shell execution. | Write AI output to a file or structured artifact, validate it against an allowlist, and require maintainer approval before shell execution. |
| `AGENT_JOB_RUNS_SHELL` | medium | An AI-related job contains shell execution. | Keep shell commands fixed, avoid executing model output, and validate parameters against allowlists. |
| `CHECKOUT_CREDENTIALS_IN_AGENT_JOB` | medium | An AI-related job checks out repository contents without disabling persisted Git credentials. | Set `persist-credentials: false` on checkout steps in AI jobs unless that job is explicitly trusted to push. |
| `UNPINNED_AI_ACTION_REF` | medium | An AI or curated maintainer action is referenced by a mutable tag, branch, or other non-SHA ref. | Pin AI maintainer actions to a reviewed full-length commit SHA and update intentionally. |
| `MISSING_EXPLICIT_PERMISSIONS` | medium | An AI-related workflow or AI job does not declare explicit `permissions`. | Declare workflow or job permissions explicitly, preferably `contents: read` for AI analysis jobs. |
| `CURATED_AI_ACTION_DETECTED` | info | A known AI maintainer action was found. | Review the action-specific guidance and check whether other risk rules also apply. |
| `AI_ACTION_DETECTED` | info | A generic AI or agent-like action was found. | Review permissions, prompt inputs, and secret exposure before enabling it on public events. |

## CI Policy

Recommended rollout:

```powershell
agentic-actions-guard scan . --fail-on critical
```

After expected critical findings are fixed or documented, move to:

```powershell
agentic-actions-guard scan . --fail-on high
```

Use an allowlist only for reviewed, temporary accepted risks. See [Allowlist Policy](allowlist-policy.md) and [AI Action Pinning Guide](action-pinning.md).

## Output Surfaces

Rules appear consistently in:

- Markdown reports
- maintainer-facing review reports
- JSON output
- SARIF output
- GitHub Actions annotations
- allowlist entries

## Scope Limits

The scanner does not execute workflows, call model providers, inspect secrets, or prove exploitability. It flags risky combinations in workflow text so maintainers can review AI automation boundaries before enabling privileged behavior.
