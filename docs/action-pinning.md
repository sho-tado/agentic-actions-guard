# AI Action Pinning Guide

AI maintainer workflows should treat action references as part of the trust boundary. A mutable action ref can change behavior after review, which is more sensitive when the action reads issue or pull request text, calls model providers, runs tools, or uses repository tokens.

`agentic-actions-guard` emits `UNPINNED_AI_ACTION_REF` when an AI or curated maintainer action uses a tag, branch, or other ref that is not a full-length commit SHA.

## Recommended Shape

Prefer a reviewed full commit SHA:

```yaml
- uses: owner/ai-maintainer-action@1234567890abcdef1234567890abcdef12345678
```

Document the source release beside the pin:

```yaml
- uses: owner/ai-maintainer-action@1234567890abcdef1234567890abcdef12345678 # v1.2.3, reviewed 2026-06-07
```

Then update intentionally:

1. Review the upstream release notes and diff.
2. Run the workflow on a low-privilege event first.
3. Keep `permissions` read-only for the AI analysis job.
4. Move labels, comments, pushes, or release operations into a separate trusted job.
5. Re-run `agentic-actions-guard` and update the pin in the same pull request.

## When Tags May Be Acceptable

A mutable ref may be an accepted risk for a short period when:

- the workflow is private or internal-only
- the job has no secrets
- the job has read-only permissions
- the action does not execute tools or shell commands
- a dependency update process will replace the tag with a commit SHA

If you accept that risk, add a scoped allowlist entry with a reason and revisit date.

## Example Allowlist

```json
{
  "allowlist": [
    {
      "rule": "UNPINNED_AI_ACTION_REF",
      "path": ".github/workflows/ai-review.yml",
      "evidence": "owner/ai-maintainer-action@v1",
      "reason": "Temporary while the maintainer team reviews the upstream v1.2.3 commit SHA. Revisit by 2026-07-01."
    }
  ]
}
```

Use allowlists for reviewed exceptions, not as a default rollout strategy.
