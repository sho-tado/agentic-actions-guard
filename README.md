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
python -m pip install git+https://github.com/sho-tado/agentic-actions-guard.git@v1.10.35
agentic-actions-guard scan . --format review --review-target owner/repo --fail-on critical
```

Use it in GitHub Actions:

```yaml
- uses: sho-tado/agentic-actions-guard@v1.10.35
  with:
    path: .
    format: sarif
    fail-on: critical
    output: agentic-actions-guard.sarif
    allowlist-max-expiry-days: "30"
    allowlist-require-removal-condition: "true"
    step-summary: "true"
```

This repository dogfoods the action in [`.github/workflows/agentic-actions-guard.yml`](.github/workflows/agentic-actions-guard.yml), including SARIF upload on `main`.

Request a public workflow safety review:

- [Join the public review call](https://github.com/sho-tado/agentic-actions-guard/issues/4)
- [Open a workflow review request](https://github.com/sho-tado/agentic-actions-guard/issues/new?template=workflow_review_request.yml)

## Why this exists

AI-assisted GitHub workflows are useful, but issue bodies, pull request descriptions, comments, discussions, and commit messages are attacker-controlled input. When those values are sent to an agent with write permissions, shell access, or repository secrets, the workflow becomes a new supply-chain risk.

See [AI GitHub Actions Threat Model](docs/ai-actions-threat-model.md) for the risk model behind the scanner rules.
See [Rule Reference](docs/rule-reference.md) for stable rule IDs, severities, and remediation guidance.
See [Risk Matrix](docs/risk-matrix.md) for the maintainer boundary each rule reviews.
See [Maintainer Review Playbook](docs/maintainer-review-playbook.md) for a short workflow review process.
See [Maintainer Opt-In Review Response Flow](docs/review-response-flow.md) for how public review reports are shared after maintainer consent.
See [Finding Lifecycle And Output Contract](docs/finding-lifecycle.md) for how findings, accepted risks, CI gates, and output formats are handled.
See [Output Schema Contract](docs/output-schema.md) for stable JSON and SARIF fields used by downstream automation.
See [Scanner Precision Notes](docs/scanner-precision.md) for how AI job scope is used to reduce workflow-level false positives.
See [Two-Stage AI Workflow Pattern](docs/two-stage-ai-workflows.md) for separating read-only AI analysis from maintainer-approved writes.
See [Workflow Run Handoff Hardening](docs/workflow-run-handoff.md) for responding to privileged `workflow_run` handoff findings.
See [AI Patch Handoff Recipe](docs/ai-patch-handoff.md) for keeping AI-generated fixes review-only before commit or push.
See [Adoption Recipes](docs/adoption-recipes.md) for copy-paste local, annotations, SARIF, and allowlist rollout examples.
See [Maintainer Adoption Decision Report](docs/adoption-decision-report.md) for choosing report-only, annotations, SARIF, or stricter gates after a review.
See [OpenSSF Scorecard Comparison](docs/openssf-scorecard-comparison.md) for how this tool complements broad repository health checks.
See [Workflow Templates](docs/workflow-templates.md) for copy-paste GitHub Actions files.
See [GitHub Actions Step Summary Example](docs/step-summary-example.md) for the compact first-run summary shown in Actions.
See [Accepted Risk Review Cadence](docs/accepted-risk-cadence.md) for keeping allowlisted findings owned and time-bound.
See [AI Action Pinning Guide](docs/action-pinning.md) for guidance on mutable action refs in AI maintainer workflows.

`agentic-actions-guard` gives maintainers a fast local check that is easy to run in CI:

- flags AI/agent-related actions and scripts
- recognizes curated profiles for common AI maintainer actions
- detects untrusted GitHub event context, Discussions text, branch refs, dispatch or reusable workflow inputs, and client payloads used in prompts or shell commands
- warns on broad or implicit `GITHUB_TOKEN` permissions, scoped to AI jobs when possible
- scopes risk rules to AI-like jobs when jobs can be parsed, so workflow titles or comments alone do not create agent findings
- highlights risky `pull_request_target` checkout patterns
- warns when AI jobs use checkout without `persist-credentials: false`
- warns when AI maintainer actions use mutable refs instead of full commit SHA pins
- warns when AI step outputs are interpolated into shell commands
- warns when privileged `workflow_run` follow-ups consume AI workflow handoff context
- warns when AI-related jobs with write permissions commit, push, merge, publish releases, or write comments
- reports secret exposure in agent jobs
- treats workflow top-level `env` secrets as available to AI jobs
- emits Markdown, JSON, SARIF, review reports, GitHub annotations, or short step summaries for issue comments, release gates, and code scanning
- summarizes additional review findings by rule after the top maintainer-facing findings
- shows allowlisted accepted risks as an expiry-sorted review queue in Markdown, review, and step summary output
- includes accepted-risk suppression metadata in SARIF `runs[0].properties.suppressions` for downstream audit trails

## CLI Usage

No third-party runtime dependency is required.

```powershell
python -m agentic_actions_guard --help
```

From this repository:

```powershell
python -m agentic_actions_guard scan . --format markdown
```

List the current rule catalog:

```powershell
python -m agentic_actions_guard rules
python -m agentic_actions_guard rules --format json
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

Emit a short Markdown summary for GitHub Actions step summaries or adoption notes:

```powershell
python -m agentic_actions_guard scan path\to\repo --format summary --fail-on critical
```

Suppress reviewed findings with a JSON allowlist policy:

```powershell
python -m agentic_actions_guard scan path\to\repo --allowlist agentic-actions-guard.allowlist.json --fail-on high
```

Apply stricter accepted-risk checks during the scan itself:

```powershell
python -m agentic_actions_guard scan path\to\repo --allowlist agentic-actions-guard.allowlist.json --allowlist-max-expiry-days 30 --allowlist-require-removal-condition --fail-on high
```

Validate an allowlist policy before using it in CI:

```powershell
python -m agentic_actions_guard validate-allowlist agentic-actions-guard.allowlist.json
```

Reject accepted risks with review windows that are too long:

```powershell
python -m agentic_actions_guard validate-allowlist agentic-actions-guard.allowlist.json --max-expiry-days 30
```

Require each accepted risk to document its removal condition:

```powershell
python -m agentic_actions_guard validate-allowlist agentic-actions-guard.allowlist.json --require-removal-condition
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

See [Maintainer Review Playbook](docs/maintainer-review-playbook.md) for a 15 minute review flow.
See [Maintainer Opt-In Review Response Flow](docs/review-response-flow.md) for consent-first public review handling.
See [Finding Lifecycle And Output Contract](docs/finding-lifecycle.md) before sharing reports or deciding how accepted risks should appear in CI output.
See [Output Schema Contract](docs/output-schema.md) when integrating JSON or SARIF output into downstream tooling.
See [Risk Matrix](docs/risk-matrix.md) when deciding which findings should block release.
See [Two-Stage AI Workflow Pattern](docs/two-stage-ai-workflows.md) when designing AI triage, PR review, release-note, or auto-fix workflows.
See [Workflow Run Handoff Hardening](docs/workflow-run-handoff.md) when a privileged follow-up consumes AI workflow artifacts or outputs.
See [AI Patch Handoff Recipe](docs/ai-patch-handoff.md) when AI-generated fixes might be committed, pushed, merged, released, or commented.
See [Adoption Recipes](docs/adoption-recipes.md) for copy-paste rollout examples.
See [Maintainer Adoption Decision Report](docs/adoption-decision-report.md) when deciding whether a repository is ready for annotations, SARIF, or stricter gates.
See [OpenSSF Scorecard Comparison](docs/openssf-scorecard-comparison.md) when combining broad repository health checks with AI workflow review.
See [Workflow Templates](docs/workflow-templates.md) for drop-in annotation and SARIF workflows.
See [GitHub Actions Step Summary Example](docs/step-summary-example.md) for the compact first-run summary shown in Actions.
See [Accepted Risk Review Cadence](docs/accepted-risk-cadence.md) before suppressing findings with an allowlist.
See [Curated AI Action Checks](docs/curated-ai-actions.md) for currently recognized AI maintainer actions.
See [AI Action Pinning Guide](docs/action-pinning.md) for the recommended update process when pinning AI action refs.
See [Fixture Corpus](docs/fixture-corpus.md) for the public-safe examples used by the test suite.

## Public Reviews

See [Request a Workflow Safety Review](docs/request-workflow-review.md) if you maintain a public repository and want a best-effort workflow safety review.

Planned next steps:

- broader real-world fixture coverage
- maintainer-approved patch handoff recipes for AI auto-fix workflows

See [ROADMAP.md](ROADMAP.md) for planned releases.

## License

MIT
