# AI GitHub Actions Safety Checklist

Use this checklist before adding AI issue triage, PR review, release note generation, auto-fix, or maintainer-assistant workflows to a public repository.

For a short end-to-end review flow, see [Maintainer Review Playbook](maintainer-review-playbook.md).

## 1. Classify Inputs

Treat these as untrusted:

- issue titles and bodies
- pull request titles and bodies
- PR review comments
- issue comments
- commit messages
- branch names from forks
- files from forked pull requests

Use them only in read-only analysis jobs unless a maintainer explicitly approves the next action.

## 2. Split Read and Write Jobs

Prefer two jobs:

- read-only AI analysis job with `contents: read`
- separate write job for labels, comments, branches, or commits

The write job should consume structured, constrained output and should run after a human approval gate for risky actions.

See [Two-Stage AI Workflow Pattern](two-stage-ai-workflows.md) for a maintainer-facing example.

## 3. Declare Permissions Explicitly

Do not rely on implicit `GITHUB_TOKEN` permissions.

Start with:

```yaml
permissions:
  contents: read
```

Add write permissions only for the smallest required scope, such as `issues: write` for label/comment automation.

## 4. Isolate Secrets

Do not expose model provider keys, package tokens, cloud credentials, or release secrets to jobs that consume untrusted event text.

If an AI job needs an API key, keep it read-only and prevent it from checking out or executing untrusted code.

## 5. Avoid `pull_request_target` for Agents

`pull_request_target` runs with privileges from the base repository. Avoid combining it with:

- AI/agent actions
- checkout of fork code
- secrets
- write permissions
- shell execution

Use `pull_request` for read-only checks, or require maintainer approval before privileged follow-up jobs.

## 6. Constrain Shell Execution

Never pass model output directly into shell commands.

Avoid shell steps in AI jobs when possible. If shell is required, keep commands fixed and validate all parameters against allowlists.

Do not interpolate AI step outputs such as `${{ steps.ai_review.outputs.summary }}` into `run:` commands. Store model output as a report artifact or comment body after validation instead.

## 7. Pin AI Action References

Avoid mutable refs such as `@main` or `@v1` for AI maintainer actions.

Prefer full-length commit SHA pins and update them intentionally after reviewing the upstream diff. This matters more for actions that consume untrusted GitHub event text, call model providers, execute tools, or run with repository tokens.

See [AI Action Pinning Guide](action-pinning.md).

## 8. Log Evidence, Not Secrets

Reports should include:

- workflow file
- line number
- rule ID
- severity
- short evidence snippet
- recommended fix

Reports should not include full secret values, private prompts, credentials, or private repository content.

## 9. Add a Failing Gate Gradually

Start with report-only mode. Then fail CI on critical findings. After the team has resolved expected findings, fail on high severity.

Example:

```powershell
python -m agentic_actions_guard scan . --format sarif --fail-on critical
```
