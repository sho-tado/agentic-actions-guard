# Maintainer Review Playbook

Use this playbook when a repository already has, or is about to add, AI issue triage, PR review, release-note generation, labeling, auto-fix, or other agentic maintainer automation.

The goal is not to prove exploitability. The goal is to identify whether untrusted GitHub event text can reach AI automation with secrets, write permissions, privileged events, checkout credentials, or shell execution.

## 15 Minute Review

1. Find the relevant workflows:

```powershell
dir .github\workflows
```

2. Run a maintainer-facing report:

```powershell
agentic-actions-guard scan . --format review --review-target owner/repo --fail-on critical
```

3. Triage findings in this order:

- critical: separate untrusted event text from secrets or privileged tokens before enabling the workflow
- high: review write permissions, `pull_request_target`, and AI output to shell boundaries
- medium: tighten explicit permissions, checkout credential persistence, mutable action refs, and shell usage
- info: review action-specific guidance for known AI maintainer actions

4. Decide the rollout gate:

```powershell
agentic-actions-guard scan . --format sarif --fail-on critical
```

Start with `critical` so maintainers can see lower-severity hardening work without blocking every workflow change.

## Review Questions

Ask these questions before merging an AI workflow:

- What GitHub event text enters the prompt or tool arguments?
- Can an outside contributor write that text?
- Does the same job have secrets, `GITHUB_TOKEN`, or write permissions?
- Does the job run shell commands after AI output is produced?
- Does the workflow run on `pull_request_target`?
- Does checkout persist credentials in an AI-related job?
- Are AI action refs pinned to reviewed full commit SHAs?
- Are write operations separated from read-only AI analysis?

## Safer Target Shape

Prefer this boundary:

```yaml
permissions:
  contents: read

jobs:
  ai-analysis:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - name: Produce report artifact
        run: echo "analysis only"

  maintainer-write:
    needs: ai-analysis
    if: github.event.label.name == 'maintainer-approved'
    permissions:
      issues: write
    runs-on: ubuntu-latest
    steps:
      - name: Apply constrained write action
        run: echo "write only after approval"
```

This keeps untrusted input analysis separate from repository mutation.

## Public Review Etiquette

If you request or receive a public review:

- share only public workflow links
- do not paste secrets, private prompts, or private repository content
- treat findings as workflow-boundary hardening advice, not vulnerability proof
- use allowlists only for reviewed, time-bound accepted risks
- re-run the scanner when workflow automation changes
