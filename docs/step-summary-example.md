# GitHub Actions Step Summary Example

`agentic-actions-guard` can write a compact Markdown report to the GitHub Actions step summary. This is useful during first adoption because maintainers can inspect severity counts, gate guidance, rule breakdowns, and next actions without opening SARIF alerts or reading the full workflow log.

The composite action enables this by default:

```yaml
- uses: sho-tado/agentic-actions-guard@v1.10.21
  with:
    path: .
    format: sarif
    fail-on: critical
    output: agentic-actions-guard.sarif
    step-summary: "true"
```

You can also generate the same summary locally:

```powershell
agentic-actions-guard scan examples\risky-ai-output-shell.yml --format summary --fail-on critical
```

## Synthetic Example Output

This sample is generated from `examples/risky-ai-output-shell.yml`. It is intentionally synthetic and does not include third-party repository findings.

```markdown
## Agentic Actions Guard Summary

- Workflows scanned: `1`
- Active findings: `7`
- Suppressed findings: `0`

| Severity | Count |
|---|---:|
| critical | `0` |
| high | `4` |
| medium | `2` |
| low | `0` |
| info | `1` |

### Recommended Gate

Run in report-only or annotations mode, review high findings, then move CI to `--fail-on high` after expected risks are fixed or explicitly accepted.

### Top Findings

- `high` `AGENT_WITH_WRITE_TOKEN` at `risky-ai-output-shell.yml:9`
- `high` `UNTRUSTED_INPUT_TO_AGENT` at `risky-ai-output-shell.yml:20`
- `high` `AI_GENERATED_CHANGES_PUSHED` at `risky-ai-output-shell.yml:21`

### Rule Breakdown

| Rule | Count |
|---|---:|
| `AGENT_JOB_RUNS_SHELL` | `1` |
| `AGENT_WITH_WRITE_TOKEN` | `1` |
| `AI_GENERATED_CHANGES_PUSHED` | `1` |
| `AI_OUTPUT_TO_SHELL` | `1` |
| `CURATED_AI_ACTION_DETECTED` | `1` |
| `UNPINNED_AI_ACTION_REF` | `1` |
| `UNTRUSTED_INPUT_TO_AGENT` | `1` |

### Suggested Next Actions

1. Review high findings for write tokens, privileged events, AI output to shell, or repository mutation.
2. Keep AI analysis read-only and move writes into maintainer-approved jobs.
3. Move to `--fail-on high` only after expected high findings are fixed or explicitly accepted.
```

## How To Use It

1. Start with `fail-on: critical` while maintainers review expected findings.
2. Fix or document high findings before changing the gate to `fail-on: high`.
3. Keep any allowlisted finding scoped, owned, dated, and tied to a removal condition.

For rollout choices, see [Maintainer Adoption Decision Report](adoption-decision-report.md). For copy-paste workflows, see [Workflow Templates](workflow-templates.md).
