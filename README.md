# Agentic Actions Guard

Audit GitHub Actions workflows for risky AI-agent automation patterns before they expose maintainers to prompt injection, overbroad tokens, or secret leaks.

This is an early OSS seed for the Codex for Open Source campaign. The project targets maintainers who are starting to add AI triage, PR review, release-note, or auto-fix workflows to public repositories.

## Why this exists

AI-assisted GitHub workflows are useful, but issue bodies, pull request descriptions, comments, and commit messages are attacker-controlled input. When those values are sent to an agent with write permissions, shell access, or repository secrets, the workflow becomes a new supply-chain risk.

`agentic-actions-guard` gives maintainers a fast local check that is easy to run in CI:

- flags AI/agent-related actions and scripts
- detects untrusted GitHub event context used in prompts or shell commands
- warns on broad or implicit `GITHUB_TOKEN` permissions
- highlights risky `pull_request_target` checkout patterns
- reports secret exposure in agent jobs
- emits Markdown or JSON for issue comments and release gates

## Install

No third-party runtime dependency is required.

```powershell
python -m agentic_actions_guard --help
```

From this repository:

```powershell
python -m agentic_actions_guard scan . --format markdown
```

## Example

```powershell
python -m agentic_actions_guard scan path\to\repo --format markdown --fail-on high
```

Scan one of the examples:

```powershell
python -m agentic_actions_guard scan examples\risky-ai-triage.yml --format markdown
```

Emit SARIF for GitHub code scanning or downstream security tooling:

```powershell
python -m agentic_actions_guard scan path\to\repo --format sarif --fail-on high > agentic-actions-guard.sarif
```

Exit codes:

- `0`: no finding at or above the fail threshold
- `1`: at least one finding at or above the fail threshold
- `2`: CLI usage or scan error

## Current Scope

The scanner is intentionally conservative and text-based in this first version. It does not execute workflows, does not call external APIs, and does not need repository credentials.

## Maintainer Checklist

See [AI GitHub Actions Safety Checklist](docs/ai-github-actions-safety-checklist.md) before adding AI triage, PR review, release-note, or auto-fix workflows to a public repository.

Planned next steps:

- YAML-aware parser while preserving dependency-light install
- allowlist policy file for accepted workflows
- curated checks for popular AI actions
- fixture corpus from real-world public workflows

## License

MIT
