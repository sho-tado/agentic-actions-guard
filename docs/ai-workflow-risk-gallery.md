# AI Workflow Risk Gallery

These synthetic examples are meant to be shareable without exposing third-party repository findings. They show common AI GitHub Actions patterns that look routine during maintenance work but cross a trust boundary once public event text, secrets, write tokens, shell commands, or privileged events are combined.

Use this page when you need a quick "does my workflow do this?" pass before adding AI triage, PR review, release-note, or auto-fix automation.

## 1. The Friendly Issue Triage Bot

Looks normal: send the issue body to an AI action so it can label or summarize the report.

Why it bites: the issue body is attacker-controlled. If the same job also has secrets or write permissions, the model is reading hostile instructions in a privileged context.

Risky shape:

```yaml
on:
  issues:
    types: [opened]
permissions:
  issues: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
          token: ${{ secrets.OPENAI_API_KEY }}
```

Safer shape:

```yaml
permissions:
  contents: read
jobs:
  analyze:
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
```

Then move labels, comments, or writes into a separate maintainer-approved stage.

Scanner rules to expect: `UNTRUSTED_INPUT_WITH_SECRETS`, `UNTRUSTED_INPUT_TO_AGENT`, `AGENT_WITH_WRITE_TOKEN`.

## 2. The Env Variable That Hides The Boundary

Looks normal: put the issue body into top-level `env` so multiple steps can reuse it.

Why it bites: the value is still attacker-controlled even if the AI job only references `$ISSUE_BODY` or `${{ env.ISSUE_BODY }}` later.

Risky shape:

```yaml
env:
  ISSUE_BODY: ${{ github.event.issue.body }}
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ env.ISSUE_BODY }}
      - run: openai api responses.create --input "$ISSUE_BODY"
```

Safer shape:

```yaml
jobs:
  review:
    permissions:
      contents: read
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.issue.body }}
```

Keep the untrusted source visible at the use site, or write it to an artifact that a trusted stage validates before use.

Scanner rules to expect: `UNTRUSTED_INPUT_TO_AGENT`, `AGENT_JOB_RUNS_SHELL`.

## 3. The Model Output That Becomes A Command

Looks normal: ask the model for a summary and pass that summary into a shell command or GitHub CLI command.

Why it bites: model output is data, not a command argument you should trust. If the output lands inside `run:`, shell parsing and quoting become part of your security boundary.

Risky shape:

```yaml
steps:
  - id: ai_review
    uses: openai/agent-action@v1
    with:
      prompt: ${{ github.event.pull_request.body }}
  - run: gh issue comment "$NUMBER" --body "${{ steps.ai_review.outputs.summary }}"
```

Safer shape:

```yaml
steps:
  - id: ai_review
    uses: openai/agent-action@v1
    with:
      prompt: ${{ github.event.pull_request.body }}
      output-file: review-summary.md
  - uses: actions/upload-artifact@v4
    with:
      name: ai-review-summary
      path: review-summary.md
```

Publish the file only after validation, or keep the write step separate from the AI step.

Scanner rules to expect: `AI_OUTPUT_TO_SHELL`, `AGENT_JOB_RUNS_SHELL`.

## 4. The Pull Request Target Trap

Looks normal: use `pull_request_target` so the bot can comment on PRs from forks.

Why it bites: `pull_request_target` runs with the base repository context. Checking out fork code or running agent logic there can mix untrusted code with privileged tokens.

Risky shape:

```yaml
on:
  pull_request_target:
jobs:
  review:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
```

Safer shape:

```yaml
on:
  pull_request:
permissions:
  contents: read
jobs:
  review:
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
```

Use a second, trusted workflow for any write action after a maintainer reviews the result.

Scanner rules to expect: `PULL_REQUEST_TARGET_AGENT`, `CHECKOUT_CREDENTIALS_IN_AGENT_JOB`.

## 5. The Helpful Auto-Fix That Pushes

Looks normal: let an AI job generate a patch and push it back to the branch.

Why it bites: a public PR body, comment, branch name, or commit message can steer the model. If the same job can push, the generated change path becomes privileged.

Risky shape:

```yaml
permissions:
  contents: write
jobs:
  autofix:
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
      - run: |
          git commit -am "Apply AI fix"
          git push
```

Safer shape:

```yaml
permissions:
  contents: read
jobs:
  suggest:
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
      - uses: actions/upload-artifact@v4
        with:
          name: suggested-fix
          path: patch.diff
```

Require a maintainer-controlled workflow to apply or publish the patch.

Scanner rules to expect: `AI_GENERATED_CHANGES_PUSHED`, `AGENT_WITH_WRITE_TOKEN`.

## 6. The Workflow Run Handoff

Looks normal: a privileged follow-up runs after an AI analysis workflow completes.

Why it bites: upstream artifacts and outputs are a trust boundary. If the follow-up has write permissions, validate what it consumes before using it.

Risky shape:

```yaml
on:
  workflow_run:
    workflows: ["ai-pr-analysis"]
    types: [completed]
permissions:
  contents: write
jobs:
  apply:
    steps:
      - uses: openai/agent-action@v1
        with:
          prompt: apply upstream artifact
```

Safer shape:

```yaml
on:
  workflow_dispatch:
permissions:
  contents: write
jobs:
  apply:
    steps:
      - run: ./scripts/validate-reviewed-artifact.ps1
```

Make the handoff explicit, reviewed, and constrained before a privileged write runs.

Scanner rules to expect: `WORKFLOW_RUN_AGENT_HANDOFF`.

## Quick Share Copy

AI GitHub Actions risk is often not "AI is bad." It is "public text became an instruction inside a job that can read secrets, run shell, or write to the repo."

Run:

```powershell
agentic-actions-guard scan . --format review --fail-on critical
```

Then check whether any finding mixes these four ingredients:

- public event text
- secrets or provider tokens
- write-capable `GITHUB_TOKEN`
- shell or repository mutation

For copy-paste rollout workflows, see [Workflow Templates](workflow-templates.md). For remediation decisions, see [Risk Matrix](risk-matrix.md) and [Two-Stage AI Workflow Pattern](two-stage-ai-workflows.md).
