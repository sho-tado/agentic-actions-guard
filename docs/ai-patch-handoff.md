# AI Patch Handoff Recipe

Use this recipe when `agentic-actions-guard` reports `AI_GENERATED_CHANGES_PUSHED`, or when you are designing an AI auto-fix workflow for a public repository.

The safe default is to let AI produce a patch, plan, or review artifact, then require a maintainer to decide whether that artifact becomes a branch, pull request, merge, release, or comment.

## Boundary

AI-generated patches are untrusted until reviewed. This is true even when the workflow uses trusted actions, runs on the base repository, or produces a patch that looks small.

Treat these as review inputs, not commands:

- generated diffs
- generated shell scripts
- generated commit messages
- generated branch names
- generated package or release names
- generated labels and comments

## Risky Shape

```yaml
name: risky ai autofix

on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: write
  pull-requests: write

jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - uses: openai/autofix-agent@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
      - run: |
          git add .
          git commit -m "Apply AI autofix"
          git push
```

This combines a privileged event, write permissions, untrusted pull request text, AI patching, checkout credentials, and direct repository mutation.

## Safer Shape

```yaml
name: ai patch handoff

on:
  pull_request:
    types: [opened, synchronize]
  workflow_dispatch:
    inputs:
      reviewed_patch_artifact:
        required: true
        type: string

permissions:
  contents: read

jobs:
  draft-patch:
    if: github.event_name == 'pull_request'
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Produce patch for review
        run: |
          mkdir -p out
          {
            echo "# AI patch review"
            echo
            echo "Review the generated patch before applying it."
          } > out/patch-review.md
      - uses: actions/upload-artifact@v4
        with:
          name: ai-patch-review
          path: out/patch-review.md

  apply-reviewed-patch:
    if: github.event_name == 'workflow_dispatch'
    permissions:
      contents: write
      pull-requests: write
    runs-on: ubuntu-latest
    steps:
      - name: Apply reviewed patch in a maintainer-triggered workflow
        run: |
          echo "Download and apply only a reviewed, allowlisted patch artifact."
```

The safer shape keeps the public pull request stage read-only. The generated patch becomes a review artifact. Any write step moves to a maintainer-triggered workflow with a reviewed artifact name and constrained behavior.

## Maintainer Checklist

Before enabling AI auto-fix:

- keep pull request analysis on `pull_request`, not `pull_request_target`, unless there is a reviewed reason
- set AI analysis jobs to `contents: read`
- set `persist-credentials: false` on checkout in AI jobs
- upload generated patches as artifacts or summaries
- require maintainer approval before commit, push, merge, release, or comment actions
- validate artifact names, paths, branches, labels, and commands against allowlists
- document any exception with an owner, review date, and removal condition

Related rules and guides:

- [`AI_GENERATED_CHANGES_PUSHED`](rule-reference.md)
- [`PULL_REQUEST_TARGET_AGENT`](rule-reference.md)
- [`AI_OUTPUT_TO_SHELL`](rule-reference.md)
- [Two-Stage AI Workflow Pattern](two-stage-ai-workflows.md)
- [Accepted Risk Review Cadence](accepted-risk-cadence.md)
