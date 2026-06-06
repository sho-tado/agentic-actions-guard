# Agentic Actions Guard

[![CI](https://github.com/sho-tado/agentic-actions-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/sho-tado/agentic-actions-guard/actions/workflows/ci.yml)
[![Agentic Actions Guard](https://github.com/sho-tado/agentic-actions-guard/actions/workflows/agentic-actions-guard.yml/badge.svg)](https://github.com/sho-tado/agentic-actions-guard/actions/workflows/agentic-actions-guard.yml)
[![Latest release](https://img.shields.io/github/v/release/sho-tado/agentic-actions-guard)](https://github.com/sho-tado/agentic-actions-guard/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Audit GitHub Actions workflows for risky AI-agent automation patterns before they expose maintainers to prompt injection, overbroad tokens, or secret leaks.

The project targets maintainers who are starting to add AI triage, PR review, release-note, or auto-fix workflows to public repositories.

## Quick Start

Run a local review:

```powershell
python -m pip install git+https://github.com/sho-tado/agentic-actions-guard.git@v1.5.0
agentic-actions-guard scan . --format review --review-target owner/repo --fail-on critical
```

Use it in GitHub Actions:

```yaml
- uses: sho-tado/agentic-actions-guard@v1.5.0
  with:
    path: .
    format: sarif
    fail-on: critical
    output: agentic-actions-guard.sarif
```

This repository dogfoods the action in [`.github/workflows/agentic-actions-guard.yml`](.github/workflows/agentic-actions-guard.yml), including SARIF upload on `main`.

Request a public workflow safety review:

- [Join the public review call](https://github.com/sho-tado/agentic-actions-guard/issues/4)
- [Open a workflow review request](https://github.com/sho-tado/agentic-actions-guard/issues/new?template=workflow_review_request.yml)

## Why this exists

AI-assisted GitHub workflows are useful, but issue bodies, pull request descriptions, comments, and commit messages are attacker-controlled input. When those values are sent to an agent with write permissions, shell access, or repository secrets, the workflow becomes a new supply-chain risk.

See [AI GitHub Actions Threat Model](docs/ai-actions-threat-model.md) for the risk model behind the scanner rules.
See [Rule Reference](docs/rule-reference.md) for stable rule IDs, severities, and remediation guidance.

`agentic-actions-guard` gives maintainers a fast local check that is easy to run in CI:

- flags AI/agent-related actions and scripts
- recognizes curated profiles for common AI maintainer actions
- detects untrusted GitHub event context, branch refs, dispatch inputs, and client payloads used in prompts or shell commands
- warns on broad or implicit `GITHUB_TOKEN` permissions, scoped to AI jobs when possible
- highlights risky `pull_request_target` checkout patterns
- warns when AI jobs use checkout without `persist-credentials: false`
- reports secret exposure in agent jobs
- treats workflow top-level `env` secrets as available to AI jobs
- emits Markdown, JSON, SARIF, review reports, or GitHub annotations for issue comments, release gates, and code scanning
- summarizes additional review findings by rule after the top maintainer-facing findings

## CLI Usage

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

See [GitHub Code Scanning Setup](docs/github-code-scanning.md) for a full workflow.

Generate a maintainer-facing review report:

```powershell
python -m agentic_actions_guard scan path\to\repo --format review --review-target owner/repo
```

See [Example Review Report](docs/example-review-report.md) for a sample maintainer-facing report.

Emit GitHub Actions annotations directly in a workflow log:

```powershell
python -m agentic_actions_guard scan path\to\repo --format annotations --fail-on critical
```

Suppress reviewed findings with a JSON allowlist policy:

```powershell
python -m agentic_actions_guard scan path\to\repo --allowlist agentic-actions-guard.allowlist.json --fail-on high
```

See [Allowlist Policy](docs/allowlist-policy.md).

Exit codes:

- `0`: no finding at or above the fail threshold
- `1`: at least one finding at or above the fail threshold
- `2`: CLI usage or scan error

## Current Scope

The scanner is intentionally conservative and dependency-light. It uses lightweight workflow structure parsing for job-scoped permissions and shell detection, but it does not execute workflows, call external APIs, or need repository credentials.

## Maintainer Checklist

See [AI GitHub Actions Safety Checklist](docs/ai-github-actions-safety-checklist.md) before adding AI triage, PR review, release-note, or auto-fix workflows to a public repository.

See [Curated AI Action Checks](docs/curated-ai-actions.md) for currently recognized AI maintainer actions.
See [Fixture Corpus](docs/fixture-corpus.md) for the public-safe examples used by the test suite.

## Public Reviews

See [Request a Workflow Safety Review](docs/request-workflow-review.md) if you maintain a public repository and want a best-effort workflow safety review.

Planned next steps:

- broader real-world fixture coverage
- maintainer opt-in review report examples

See [ROADMAP.md](ROADMAP.md) for planned releases.

## License

MIT
