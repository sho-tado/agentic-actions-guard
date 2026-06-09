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

## False Positive Discipline

The scanner prefers scoped findings:

- untrusted input findings point to the prompt or command line inside an AI job
- write-token findings prefer top-level write permissions only when an AI job exists
- shell findings are attached to shell steps inside AI jobs
- checkout credential findings only apply to checkout steps in AI jobs

If a finding appears on a workflow that only has an AI-related title, add a fixture or regression test before widening a rule.
