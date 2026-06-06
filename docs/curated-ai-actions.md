# Curated AI Action Checks

`agentic-actions-guard` recognizes a small curated set of AI maintainer actions so reports can include action-specific review advice instead of only generic AI workflow findings.

The scanner does not claim that these actions are unsafe. The rule means the workflow should be reviewed with the same care as other tool-capable maintainer automation, especially on public issue, pull request, or comment events.

## Current Profiles

| Action family | Example `uses:` value | Review focus |
|---|---|---|
| Anthropic Claude Code Action | `anthropics/claude-code-action@v1` | Keep issue and PR automation read-only by default. Require maintainer approval before file writes, tool expansion, or privileged token use. |
| Google Gemini CLI Action | `google-github-actions/run-gemini-cli@v1` | Review prompts, command arguments, and token scope together. Isolate untrusted issue or PR text from secrets and write permissions. |
| Qwen Code Action | `QwenLM/qwen-code-action@v0.1.1` | Keep review and triage jobs read-only unless a separate trusted workflow performs the write step. |
| iFlow CLI Action | `iflow-ai/iflow-cli-action@v1` | Treat commands as tool-capable agent execution. Keep public-event inputs away from secrets, write tokens, and broad shell mutation steps. |
| OpenAI or Codex agent action patterns | `openai/agent-action@v1` | Split agent analysis from repository mutation and explicitly document accepted token and secret exposure. |

## Rule Behavior

Curated action matches emit:

- Rule: `CURATED_AI_ACTION_DETECTED`
- Severity: `info`
- Evidence: the matched `uses:` action reference

Other risk rules still apply independently. For example, a curated action can also produce `UNTRUSTED_INPUT_TO_AGENT`, `AGENT_WITH_WRITE_TOKEN`, `UNTRUSTED_INPUT_WITH_SECRETS`, or `PULL_REQUEST_TARGET_AGENT` when the workflow combines the action with risky inputs or permissions.

Curated and generic AI action references also produce `UNPINNED_AI_ACTION_REF` when they use mutable refs such as tags or branches instead of a full-length commit SHA.

## Review Guidance

For public repositories, prefer this shape:

```yaml
permissions:
  contents: read

jobs:
  ai-analysis:
    permissions:
      contents: read
    # AI action runs here.

  maintainer-write:
    # Write operations happen separately after trusted review.
```

Avoid placing secrets, broad write tokens, and untrusted issue or pull request bodies in the same job.
