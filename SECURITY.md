# Security policy

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Strataward/security-audit-skill/security/advisories/new) for a sensitive report. Do not disclose exploit details in a public issue.

Include the affected commit, helper or instruction, expected behavior, actual behavior, and a minimal reproduction with synthetic data. Do not send credentials, private repository contents, or customer data.

The maintainers review reports against the current main branch. This project does not promise a response time or a security certification.

## Execution model

The skill coordinates an audit. It does not enforce OS isolation. The agent must verify sandbox controls before running target code. The record helper is not a sandbox artifact exporter. The advisory helper sends reviewed public package metadata to fixed public services.

Treat source files, advisories, logs, and model output as untrusted data. A test pass, agent agreement, or package version match does not establish that an application is secure.
