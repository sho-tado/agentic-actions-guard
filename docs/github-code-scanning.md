# GitHub Code Scanning Setup

Use this workflow to publish SARIF findings in GitHub code scanning.

```yaml
name: agentic-actions-guard

on:
  pull_request:
    paths:
      - ".github/workflows/**"
  push:
    branches: [main]
    paths:
      - ".github/workflows/**"

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sho-tado/agentic-actions-guard@v0.4.0
        with:
          path: .
          format: sarif
          fail-on: critical
          output: agentic-actions-guard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentic-actions-guard.sarif
```

## Rollout Advice

Start with `fail-on: critical` so teams see findings without blocking most existing workflow changes. Move to `fail-on: high` after expected findings are fixed or documented.

For public repositories, scan workflow changes on pull requests and scan the default branch on push. Do not give the scan job secrets.

## Local Reproduction

```powershell
python -m pip install git+https://github.com/sho-tado/agentic-actions-guard.git
agentic-actions-guard scan . --format sarif --fail-on critical > agentic-actions-guard.sarif
```
