# Security Policy

## Supported Versions

This project is in early alpha. Security fixes target the latest release.

## Reporting a Vulnerability

Please do not open a public issue for exploitable vulnerabilities in this project.

Send a private report to the maintainer through GitHub's private vulnerability reporting if enabled. If private reporting is not available yet, open a public issue with a high-level description only and ask for a private contact path. Do not include secrets, exploit payloads, or private repository data in public issues.

## Threat Model

The scanner treats workflow files as untrusted text. It does not execute workflows, evaluate model output, call external services, or require repository credentials.

Primary risks this project aims to detect:

- untrusted GitHub event text sent to an AI/agent workflow
- secrets or privileged tokens available to agent jobs
- broad write permissions in AI workflow jobs
- dangerous `pull_request_target` usage
- shell execution near AI/agent workflow steps
