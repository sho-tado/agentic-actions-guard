# Contributing

Thanks for helping make AI-assisted OSS maintenance safer.

## Good First Contributions

- Add public-safe risky or safer workflow fixtures under `examples/`.
- Add tests that pin expected scanner behavior for a fixture.
- Improve rule descriptions and recommendations.
- Improve maintainer-facing docs.
- Add curated action profiles when a public AI maintainer action has clear workflow examples and security guidance.

Do not include secrets, private workflow files, or private repository content in issues, fixtures, or tests.

## Public-Safe Fixtures

Fixtures should be synthetic and minimal. Use realistic workflow shapes, but avoid copying private prompts, real tokens, exploit payloads, or private repository data.

Good fixture contributions include:

- one risky workflow that should produce a high or critical finding
- one safer workflow that should not produce high or critical findings
- a test that captures the expected rule IDs
- a short docs update when the fixture introduces a new workflow family

## Development

```powershell
python -m pip install -e . pytest
python -m pytest
python -m agentic_actions_guard scan . --fail-on high
```

## Rule Design

Rules should be conservative and explainable:

- stable rule ID
- clear severity
- exact workflow file and line
- short evidence snippet
- practical recommendation
- test fixture that captures expected behavior

Prefer high-signal checks over broad matching that produces noisy reports.

## Security Reports

Follow [SECURITY.md](SECURITY.md) for vulnerability reports. Do not open public issues with exploit payloads or private repository data.
