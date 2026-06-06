# Request a Workflow Safety Review

Maintainers can request a lightweight review of public GitHub Actions workflows that use AI agents for issue triage, PR review, release-note generation, auto-fix automation, or other repository maintenance.

The public review call is tracked in [issue #4](https://github.com/sho-tado/agentic-actions-guard/issues/4).

Open a [Workflow safety review issue](https://github.com/sho-tado/agentic-actions-guard/issues/new?template=workflow_review_request.yml) with a link to the public repository or workflow file.

If you want to self-review first, follow the [Maintainer Review Playbook](maintainer-review-playbook.md).

## Scope

The review looks for risky combinations of:

- untrusted issue, pull request, comment, review, or commit text
- AI or agent actions
- broad `GITHUB_TOKEN` write permissions
- secrets in jobs that process untrusted text
- `pull_request_target` usage
- shell execution near agent automation
- mutable AI action refs that are not pinned to full commit SHAs
- AI step outputs interpolated into shell commands

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

Self-service install:

```powershell
python -m pip install git+https://github.com/sho-tado/agentic-actions-guard.git@v1.7.1
agentic-actions-guard scan . --format review --review-target owner/repo --fail-on critical
```

## Limits

This is a best-effort workflow safety review, not a full security audit. The scanner is intentionally conservative and dependency-light. It uses lightweight workflow structure parsing, but it does not execute workflows, call external services, inspect secrets, or require repository credentials.
