# Rule Reference

This page documents the stable rule IDs emitted by `agentic-actions-guard`.

Rule IDs are intended to be safe for CI policy, SARIF filtering, GitHub annotations, review reports, and allowlist entries. New rules may be added in minor releases. Existing rule meanings should only change when the safer interpretation is strictly narrower or less noisy.

For maintainer-facing risk boundaries and release gate guidance, see [Risk Matrix](risk-matrix.md).

The same rule catalog is available from the CLI:

```powershell
agentic-actions-guard rules
agentic-actions-guard rules --format json
```

## Rules

| Rule ID | Default severity | Meaning | Typical fix |
|---|---:|---|---|
| `UNTRUSTED_INPUT_WITH_SECRETS` | critical | An AI workflow appears to combine untrusted GitHub event text with secrets or privileged tokens such as `${{ github.token }}`. | Keep secrets and privileged token contexts out of jobs that process issue, PR, comment, discussion, review, or commit text. Split privileged operations into a separate trusted job. |
| `UNTRUSTED_INPUT_TO_AGENT` | high | Untrusted GitHub event text, selected serialized event objects, or workflow input such as issue text, PR text, comments, discussion text, discussion answers, branch names, dispatch inputs, reusable workflow inputs, or commit messages is passed into AI or agent automation. | Treat event text and workflow inputs as hostile input. Sanitize, summarize, or isolate them before agent use. |
| `AGENT_WITH_WRITE_TOKEN` | high | An AI-related workflow has write permissions. | Use least-privilege permissions and split read-only analysis from write operations. |
| `PULL_REQUEST_TARGET_AGENT` | high or critical | An AI-related workflow runs on `pull_request_target`. It becomes critical when it appears to check out fork-controlled content. | Prefer `pull_request` for read-only analysis. Use privileged follow-up jobs only after explicit maintainer approval. |
| `WORKFLOW_RUN_AGENT_HANDOFF` | high | An AI-related `workflow_run` follow-up appears to run with secrets or write permissions. | Treat upstream artifacts and outputs as a trust boundary. Validate handoff data and keep privileged writes in a maintainer-approved job. |
| `AI_OUTPUT_TO_SHELL` | high | An AI step output appears to be interpolated into shell execution. | Write AI output to a file or structured artifact, validate it against an allowlist, and require maintainer approval before shell execution. |
| `AI_GENERATED_CHANGES_PUSHED` | high | An AI-related job appears able to commit, push, merge, publish a release, or write comments while it has repository write permissions. | Keep AI-generated patches as review artifacts. Move repository mutation into a maintainer-approved job or manual workflow. |
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

Use an allowlist only for reviewed, temporary accepted risks. Rule matchers must use exact known rule IDs. See [Allowlist Policy](allowlist-policy.md) and [AI Action Pinning Guide](action-pinning.md).

## Output Surfaces

Rules appear consistently in:

- Markdown reports
- maintainer-facing review reports
- JSON output
- SARIF output
- GitHub Actions annotations
- allowlist entries

For stable JSON and SARIF fields, see [Output Schema Contract](output-schema.md).

## Scope Limits

The scanner does not execute workflows, call model providers, inspect secrets, or prove exploitability. It flags risky combinations in workflow text so maintainers can review AI automation boundaries before enabling privileged behavior.
