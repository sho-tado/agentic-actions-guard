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

## Example Output

```text
# Agentic Actions Guard Review

## Scope

- Target: `examples/risky-ai-triage`
- Workflows scanned: `1`
- Findings: `2`
- Suppressed findings: `0`

## Severity Summary

- critical: `1`
- high: `1`
- medium: `0`
- low: `0`
- info: `0`

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
```

## Recommended Shape

For public repositories, keep AI analysis jobs read-only by default:

```yaml
permissions:
  contents: read
```

Then move issue labels, comments, branch pushes, or other write operations into a separate maintainer-approved job or workflow. Do not expose secrets to jobs that process issue, pull request, comment, review, or commit text.
