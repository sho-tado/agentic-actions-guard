# Scanner Precision Notes

The scanner is intentionally conservative about high and critical findings. It should flag risky AI maintainer automation, but it should not treat every workflow that mentions "AI" in a title or comment as an agent workflow.

## AI Scope

When a workflow has parseable `jobs`, risk rules are evaluated against AI-like job blocks:

- job IDs, job display names, reusable workflow `uses` targets, step names, action references, prompts, models, or scripts that match AI/agent terms
- curated AI maintainer actions such as Claude, Gemini, Codex, Qwen, OpenAI, or similar agent actions
- AI output handoff patterns inside the same job

Workflow-level prose, such as `name: safer ai release notes`, is not enough by itself to make every job agentic. Job metadata-only references, such as `needs: ai-build`, also do not make the dependent job agentic unless the job ID, display name, reusable workflow target, prompt/model input, or one of its steps is AI-like. This reduces workflow-level false positives and keeps read-only artifact workflows and maintainer-dispatched release-note helpers from receiving unrelated write-token, shell, or untrusted-input findings.

## Fallback Behavior

If a workflow file cannot be split into job blocks, the scanner keeps a broad fallback and scans the full text. That fallback is useful for partial, generated, or malformed workflow snippets where the safer job-level boundary is unavailable.

## Commented Scalars

GitHub Actions scalar settings keep their security meaning when a line has a trailing comment. The scanner treats `secrets: inherit # ...` as reusable workflow secret exposure and `permissions: write-all # ...` as a write token. Named write permissions such as `contents: write # ...` and `issues: write # ...` are also treated as write tokens. Commented `permissions: read-all # ...` and `permissions: write-all # ...` count as explicit permissions declarations.

Inline permission maps keep the same meaning as block-style permissions. The scanner treats `permissions: { contents: write }` and AI job-level `permissions: { issues: write }` as write tokens, and inline maps count as explicit permissions declarations.

Quoted permission keys and values keep the same meaning as unquoted YAML. The scanner treats `"contents": "write"`, `permissions: { "issues": "write" }`, and `permissions: "write-all"` as write tokens.

GitHub expression bracket notation keeps the same trust boundary as dotted notation for selected event payload text. The scanner treats `github.event['issue']['body']`, `github['event']['pull_request']['body']`, `github.event.commits[0]['message']`, and `github.event['client_payload']['prompt']` as untrusted AI inputs.

Top-level workflow input bracket notation keeps the same trust boundary as dotted notation for prompt-like fields. The scanner treats `inputs['prompt']` and `inputs["instructions"]` as untrusted AI inputs when they are passed to an AI job. Separator-style prompt-like input names are also in scope: `inputs.issue_body`, `inputs['review_prompt']`, and `inputs['comment-body']` are untrusted AI inputs, while operational names such as `inputs.release_ref` stay out of scope by name alone.

## False Positive Discipline

The scanner prefers scoped findings:

- untrusted input findings point to the prompt or command line inside an AI job
- write-token findings prefer top-level write permissions only when an AI job exists
- shell findings are attached to shell steps inside AI jobs
- checkout credential findings only apply to checkout steps in AI jobs

If a finding appears on a workflow that only has an AI-related title, add a fixture or regression test before widening a rule.
