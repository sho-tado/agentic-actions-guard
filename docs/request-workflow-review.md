# Request a Workflow Safety Review

Maintainers can request a lightweight review of public GitHub Actions workflows that use AI agents for issue triage, PR review, release-note generation, auto-fix automation, or other repository maintenance.

The public review call is tracked in [issue #4](https://github.com/sho-tado/agentic-actions-guard/issues/4).

Open a [Workflow safety review issue](https://github.com/sho-tado/agentic-actions-guard/issues/new?template=workflow_review_request.yml) with a link to the public repository or workflow file.

## Scope

The review looks for risky combinations of:

- untrusted issue, pull request, comment, review, or commit text
- AI or agent actions
- broad `GITHUB_TOKEN` write permissions
- secrets in jobs that process untrusted text
- `pull_request_target` usage
- shell execution near agent automation

## What Not To Share

Do not paste:

- secrets or tokens
- private workflow files
- private prompts
- credentials
- private repository content
- exploit payloads

## Output

Reviews use the maintainer-facing report format:

```powershell
agentic-actions-guard scan . --format review --review-target owner/repo
```

A report includes scope, severity counts, top findings, suggested fixes, and reproduction steps.

## Limits

This is a best-effort workflow safety review, not a full security audit. The scanner is intentionally conservative and text-based. It does not execute workflows, call external services, inspect secrets, or require repository credentials.
