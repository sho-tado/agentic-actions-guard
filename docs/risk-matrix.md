# Risk Matrix

This matrix maps `agentic-actions-guard` rules to the maintainer boundary they review. Use it when deciding whether a finding is a release blocker, a workflow hardening task, or an accepted risk.

| Rule ID | Boundary reviewed | Maintainer question | Primary fix |
|---|---|---|---|
| `UNTRUSTED_INPUT_WITH_SECRETS` | Untrusted event text plus secrets or privileged tokens | Can outside-authored text influence a job that has secrets or explicit token contexts such as `${{ github.token }}`? | Move secrets and privileged token use into a separate trusted job. |
| `UNTRUSTED_INPUT_TO_AGENT` | Untrusted event text into AI automation | Can an issue, PR, comment, review, commit, branch, or dispatch payload shape the agent prompt? | Treat the text as hostile; isolate, summarize, or constrain it before agent use. |
| `AGENT_WITH_WRITE_TOKEN` | AI job write permissions | Can the AI-related job mutate issues, PRs, contents, checks, statuses, packages, or deployments? | Keep AI analysis read-only and move writes into a maintainer-approved job. |
| `PULL_REQUEST_TARGET_AGENT` | Privileged event context | Does agent automation run on `pull_request_target`, especially near fork checkout? | Prefer read-only `pull_request`; use privileged follow-up only after approval. |
| `WORKFLOW_RUN_AGENT_HANDOFF` | Artifact and workflow handoff boundary | Can an upstream AI workflow artifact or output influence a privileged `workflow_run` follow-up? | Validate handoff data and require maintainer approval before writes. |
| `AI_OUTPUT_TO_SHELL` | Model output to command execution | Can AI output become shell arguments or commands? | Store AI output as a report artifact, validate it, and gate shell execution. |
| `AI_GENERATED_CHANGES_PUSHED` | Repository mutation after AI generation | Can an AI-related job commit, push, merge, publish a release, or write comments with repository permissions? | Keep AI-generated patches as review artifacts and move mutation into a maintainer-approved stage. |
| `AGENT_JOB_RUNS_SHELL` | Shell execution in AI-related jobs | Does a job near AI automation execute shell commands? | Keep shell commands fixed and validate all parameters against allowlists. |
| `CHECKOUT_CREDENTIALS_IN_AGENT_JOB` | Git credential persistence | Does an AI-related job checkout code while keeping push-capable credentials? | Set `persist-credentials: false` unless the AI job is explicitly trusted to push. |
| `UNPINNED_AI_ACTION_REF` | Mutable AI action supply chain | Can a tag or branch update change reviewed AI workflow behavior? | Pin AI actions to reviewed full-length commit SHAs. |
| `MISSING_EXPLICIT_PERMISSIONS` | Implicit `GITHUB_TOKEN` scope | Does the workflow rely on repository defaults for token permissions? | Declare workflow or job `permissions`, preferably `contents: read`. |
| `CURATED_AI_ACTION_DETECTED` | Known AI maintainer action profile | Is a known AI maintainer action present? | Review action-specific guidance and check whether higher-severity rules apply. |
| `AI_ACTION_DETECTED` | Generic AI or agent action profile | Is a generic AI or agent-like action present? | Review prompts, permissions, event inputs, and secret exposure before enabling it. |

## Release Gate Guidance

Use this default priority:

1. Block on `critical` while separating secrets from untrusted event text.
2. Review `high` findings before enabling write behavior or shell execution.
3. Track `medium` findings as hardening tasks with owners and revisit dates.
4. Treat `info` findings as inventory that points maintainers to action-specific guidance.

For rollout commands, see [Adoption Recipes](adoption-recipes.md). For stable rule wording, see [Rule Reference](rule-reference.md).

For the `WORKFLOW_RUN_AGENT_HANDOFF` response flow, see [Workflow Run Handoff Hardening](workflow-run-handoff.md).

For time-bound accepted risks, see [Accepted Risk Review Cadence](accepted-risk-cadence.md).
