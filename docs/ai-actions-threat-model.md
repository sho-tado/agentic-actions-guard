# AI GitHub Actions Threat Model

AI maintainer workflows are useful, but public repository events mix untrusted contributor input with automation that may have repository privileges.

`agentic-actions-guard` focuses on the failure mode where an AI or agent workflow consumes untrusted event text while also having access to secrets, write tokens, privileged events, or shell execution.

## Untrusted Inputs

Treat these values as attacker-controlled in public repositories:

- `github.event.issue.title`
- `github.event.issue.body`
- `github.event.pull_request.title`
- `github.event.pull_request.body`
- `github.event.comment.body`
- `github.event.review.body`
- `github.event.review_comment.body`
- `github.event.discussion.title`
- `github.event.discussion.body`
- `github.event.comment.body` on `discussion_comment` workflows
- `github.event.discussion_comment.body`
- `github.event.answer.body`
- `github.event.head_commit.message`
- `github.event.commits[0].message`
- `github.ref_name`
- `github.event.inputs.*`
- `inputs.*`
- `github.event.client_payload.*`
- `github.head_ref`
- `github.event.pull_request.head.label`
- serialized event objects such as `toJson(github.event.issue)`, `toJson(github.event.pull_request)`, or `github.event.comment`
- event payload files referenced through `github.event_path` or `$GITHUB_EVENT_PATH`
- fork branch names and refs
- files checked out from forked pull requests

These inputs are safe to inspect in read-only jobs. They become risky when the same job can mutate the repository, access secrets, or execute untrusted code.

## High-Risk Combinations

### Untrusted event text plus secrets

Risk: prompt injection can influence a job that has model provider keys, cloud credentials, package tokens, release secrets, inherited reusable-workflow secrets through `secrets: inherit`, or an explicit `${{ github.token }}` passed into AI tooling.

Safer shape: keep the AI analysis job read-only and keep secrets out of jobs that process issue, pull request, comment, discussion, review, or commit text.

Workflow top-level `env` is also in scope: a secret placed there is available to every job unless the workflow is restructured.

Reusable workflow jobs are also in scope: `secrets: inherit` passes caller secrets into the called workflow and should be separated from untrusted issue, pull request, comment, discussion, review, or commit text.

### AI workflow plus write token

Risk: a manipulated prompt can lead to labels, comments, branches, commits, workflow dispatches, or status changes that look maintainer-authored.

Safer shape: split write operations into a separate job or workflow with constrained inputs and maintainer approval for risky actions.

### `pull_request_target` plus agent workflow

Risk: `pull_request_target` runs with base repository privileges. Combining it with fork content checkout, secrets, write permissions, or shell execution can turn a PR into a privileged execution path.

Safer shape: use `pull_request` for read-only analysis. Use privileged follow-up jobs only after explicit maintainer approval.

### Shell execution near model output

Risk: model output, issue text, branch names, or generated patches can be interpolated into shell commands.

Safer shape: keep shell commands fixed, validate parameters against allowlists, and never execute raw model output.

### Checkout credentials in agent jobs

Risk: `actions/checkout` persists the workflow token in local Git config unless disabled. In an AI job with shell execution, generated patches, or untrusted prompt context, that credential path can make accidental or prompt-influenced git operations more damaging.

Safer shape: set `persist-credentials: false` on checkout steps inside AI jobs, and move any intended push behavior into a separate trusted job.

## Minimal Safe Baseline

Start AI workflow rollout with:

```yaml
permissions:
  contents: read
```

Then add write permissions only in separate, tightly scoped jobs.

## CI Rollout

Use report-only mode first:

```powershell
agentic-actions-guard scan . --format review --fail-on critical
```

After expected critical findings are fixed or documented, gate CI:

```powershell
agentic-actions-guard scan . --format annotations --fail-on critical
```

Then move to `--fail-on high` once the team has reviewed expected findings.
