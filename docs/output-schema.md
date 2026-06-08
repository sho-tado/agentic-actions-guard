# Output Schema Contract

This page documents the stable fields that downstream tooling can rely on when consuming `agentic-actions-guard` JSON and SARIF output.

The Markdown, review, summary, and annotation formats are maintainer-facing text surfaces. They may change wording to improve readability. JSON and SARIF are the machine-readable surfaces and should keep the fields below stable across patch releases.

For the broader report lifecycle and non-goals, see [Finding Lifecycle And Output Contract](finding-lifecycle.md).

## JSON Output

Generate JSON with:

```powershell
agentic-actions-guard scan . --format json
```

The top-level object contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `root` | string | Resolved scan root path. |
| `workflow_count` | number | Count of workflow YAML files scanned. |
| `findings` | array | Active findings that are not suppressed by allowlist policy. |
| `suppressed_findings` | array | Findings suppressed by accepted-risk allowlist policy. |
| `suppressions` | array | Audit rows that pair each suppressed finding with the matching allowlist entry. |
| `allowlist_entries` | array | Validated allowlist entries loaded for the scan. |
| `summary` | object | Active finding counts by severity. |
| `suppressed_summary` | object | Suppressed finding counts by severity. |

Severity summaries include these keys even when the count is zero:

```json
{
  "info": 0,
  "low": 0,
  "medium": 0,
  "high": 0,
  "critical": 0
}
```

## Finding Object

Each entry in `findings` and `suppressed_findings` contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `severity` | string | One of `info`, `low`, `medium`, `high`, or `critical`. |
| `rule` | string | Stable rule ID from [Rule Reference](rule-reference.md). |
| `path` | string | Workflow path, normalized with `/` separators. |
| `line` | number | 1-based line number when available. |
| `message` | string | Short finding message. |
| `evidence` | string | Public workflow evidence line or snippet. |
| `recommendation` | string | Practical maintainer remediation guidance. |

## Suppression Object

Each entry in `suppressions` contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `finding` | object | The suppressed finding object. |
| `allowlist_entry` | object | The allowlist entry that matched the finding. |

The `allowlist_entry` object includes the accepted-risk metadata provided by policy:

- `rule`
- `path`
- `evidence`
- `reason`
- `owner`
- `expires`
- `rationale`
- `removal_condition`

Fields omitted from the policy are omitted from `allowlist_entry`. Validation requires `reason`, `owner`, `expires`, `rationale`, and at least one matcher. `removal_condition` is required when `scan --allowlist-require-removal-condition` or `validate-allowlist --require-removal-condition` is used.

## SARIF Output

Generate SARIF with:

```powershell
agentic-actions-guard scan . --format sarif
```

The SARIF output uses version `2.1.0`.

Active findings are emitted as `runs[0].results`. Suppressed accepted risks are not emitted as active results, so GitHub code scanning does not open alerts for findings that maintainers have explicitly accepted.

The run properties contain scan metadata and accepted-risk audit data:

| Field | Meaning |
| --- | --- |
| `runs[0].properties.root` | Resolved scan root path. |
| `runs[0].properties.workflowCount` | Count of workflow YAML files scanned. |
| `runs[0].properties.summary` | Active finding counts by severity. |
| `runs[0].properties.suppressedSummary` | Suppressed finding counts by severity. |
| `runs[0].properties.suppressions` | Accepted-risk suppression audit rows. |

Each SARIF suppression row contains:

- `rule`
- `severity`
- `path`
- `line`
- `evidence`
- `reason`
- `owner`
- `expires`
- `rationale`
- `removalCondition`

`removalCondition` uses SARIF-friendly camelCase. JSON output keeps the policy field name `removal_condition`.

## Stability Notes

Patch releases should not remove documented JSON fields, rename documented SARIF properties, or change severity summary keys.

Minor releases may add fields. Downstream consumers should ignore unknown fields.

Human-readable Markdown wording can change more freely than JSON or SARIF fields.
