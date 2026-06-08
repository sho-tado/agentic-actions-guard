# OpenSSF Scorecard Comparison

`agentic-actions-guard` is intended to complement OpenSSF Scorecard, not replace it.

OpenSSF Scorecard is a broad repository security health tool for open source projects. It helps maintainers and consumers evaluate project practices across checks such as maintained status, branch protection, dependency pinning, token permissions, dangerous workflow patterns, security policy, and SAST.

`agentic-actions-guard` focuses on a narrower boundary: AI and agentic GitHub Actions workflows that combine public event text with model prompts, secrets, write tokens, privileged events, shell execution, or repository mutation.

Sources:

- OpenSSF Scorecard project: https://github.com/ossf/scorecard
- OpenSSF Scorecard checks documentation: https://github.com/ossf/scorecard/blob/main/docs/checks.md
- OpenSSF Scorecard GitHub Action: https://github.com/ossf/scorecard-action

## Comparison Table

| Area | OpenSSF Scorecard | agentic-actions-guard |
|---|---|---|
| Main purpose | Broad open source security health checks. | Focused review of AI/agent GitHub Actions trust boundaries. |
| Repository hygiene | Reviews many project-level practices such as maintenance, branch protection, dependency pinning, security policy, and SAST. | Does not score general repository hygiene. |
| GitHub Actions token scope | Includes token-permission and dangerous-workflow style checks. | Reviews AI-related jobs for write tokens, implicit permissions, checkout credential persistence, and mutation paths. |
| Untrusted issue/PR/comment/discussion text | Not positioned as an AI prompt-boundary review tool. | Treats issue, PR, comment, discussion, review, commit, branch, and dispatch text as untrusted AI input. |
| AI/agent workflow detection | Not focused on AI maintainer actions or model prompt boundaries. | Detects AI/agent-like actions and curated AI maintainer action profiles. |
| Privileged events | Reviews dangerous workflow patterns broadly. | Adds AI-specific checks for `pull_request_target` and privileged `workflow_run` handoffs near agent automation. |
| AI output to shell | Not positioned as a model-output-to-command review tool. | Flags AI step outputs interpolated into shell commands. |
| Maintainer handoff | Provides automated check results and scoring. | Provides Markdown review reports, adoption decision guidance, allowlist policy, and fixture examples for maintainer rollout decisions. |
| SARIF/code scanning | Scorecard can be run in CI and through its GitHub Action ecosystem. | Emits SARIF directly for GitHub code scanning and annotations for lightweight workflow-change feedback. |

## Recommended Joint Use

Use both tools when reviewing AI maintainer automation:

1. Run OpenSSF Scorecard for broad repository security posture.
2. Run `agentic-actions-guard` for AI/agent workflow-specific trust boundaries.
3. Review any workflow findings together before enabling AI triage, PR review, release-note, or auto-fix automation.
4. Keep Scorecard results visible for general project hygiene, and use `agentic-actions-guard` reports for workflow-specific maintainer decisions.

## Example Rollout

Start with a local AI workflow review:

```powershell
agentic-actions-guard scan . --format review --review-target owner/repo --fail-on critical
```

Then add annotations or SARIF once maintainers understand the findings:

- [Adoption Recipes](adoption-recipes.md)
- [GitHub Code Scanning Setup](github-code-scanning.md)
- [Workflow Templates](workflow-templates.md)

For deciding which findings block release, see [Risk Matrix](risk-matrix.md).

## Maintainer Boundary

The key question for `agentic-actions-guard` is:

> Can public GitHub event text influence an AI-related job that has secrets, write permissions, privileged event context, shell execution, or a path to commit/push/comment/release?

That question is intentionally narrower than a general repository health score. It is meant to help maintainers adopt AI workflow automation without silently expanding the trust boundary of public issues, pull requests, comments, discussions, branches, reviews, or dispatch payloads.
