# Example Review Report

This page shows what a maintainer-facing `agentic-actions-guard` review looks like on a deliberately risky fixture workflow.

The scanner only reads public workflow files. It does not execute workflows, call external APIs, read secrets, or require private repository access.

## Command

```powershell
agentic-actions-guard scan .\examples\risky-ai-triage.yml --format review --review-target examples/risky-ai-triage --fail-on critical
```

Expected exit code: `1`, because a critical finding is present.

## Fixture Pattern

The risky fixture combines:

- untrusted issue text: `${{ github.event.issue.body }}`
- repository write permission: `issues: write`
- an agent-like workflow step
- an API key exposed to the same job
- shell execution in the same AI-related job

## Example Output

````text
# Agentic Actions Guard Review

## Scope

- Target: `examples/risky-ai-triage`
- Workflows scanned: `1`
- Findings: `4`
- Suppressed findings: `0`

## Severity Summary

- critical: `1`
- high: `1`
- medium: `1`
- low: `0`
- info: `1`

## Maintainer Takeaway

This workflow set has high-impact AI-agent automation risks. Prioritize separating untrusted GitHub event text from jobs that have secrets, write permissions, privileged events, or shell execution.

## Top Findings

### CRITICAL UNTRUSTED_INPUT_WITH_SECRETS

- Location: `risky-ai-triage.yml:21`
- Evidence: `${{ github.event.issue.body }}`
- Risk: AI-agent workflow appears to combine untrusted GitHub event text with secrets or privileged tokens.
- Suggested fix: Separate untrusted text analysis from privileged actions; avoid secrets in jobs that consume issue, PR, or comment content.

### HIGH AGENT_WITH_WRITE_TOKEN

- Location: `risky-ai-triage.yml:8`
- Evidence: `issues: write`
- Risk: AI-agent workflow has write permissions.
- Suggested fix: Use least-privilege permissions and split read-only analysis from write operations.

### MEDIUM AGENT_JOB_RUNS_SHELL

- Location: `risky-ai-triage.yml:22`
- Evidence: `- run: echo "agent result would be used here"`
- Risk: AI-related workflow contains shell execution.
- Suggested fix: Constrain shell steps, avoid interpolating model output into commands, and require human approval for mutations.

### INFO CURATED_AI_ACTION_DETECTED

- Location: `risky-ai-triage.yml:15`
- Evidence: `openai/agent-action@v1`
- Risk: Workflow uses a known AI maintainer action: OpenAI or Codex agent action.
- Suggested fix: Split OpenAI/Codex agent analysis from repository mutation and explicitly document accepted token and secret exposure.

## Recommended Next Steps

1. Keep AI analysis jobs at `contents: read` whenever possible.
2. Move write actions into a separate maintainer-approved job or workflow.
3. Do not expose secrets to jobs that process issue, PR, comment, review, or commit text.
4. Avoid `pull_request_target` for agent workflows unless the privileged path is tightly constrained.
5. Start CI gating at `--fail-on critical`, then move to `high` after expected findings are fixed.

## Reproduce

```powershell
python -m agentic_actions_guard scan . --format review --fail-on critical
```
````

## Recommended Shape

For public repositories, keep AI analysis jobs read-only by default:

```yaml
permissions:
  contents: read
```

Then move issue labels, comments, branch pushes, or other write operations into a separate maintainer-approved job or workflow. Do not expose secrets to jobs that process issue, pull request, comment, review, or commit text.
