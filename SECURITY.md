# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability, do **not** open a public GitHub issue.

Use one of these private channels:

1. GitHub Private Vulnerability Reporting for this repository (preferred).
2. If private reporting is unavailable, contact the repository maintainers directly and request an encrypted channel before sharing details.

## What to include in your report

- affected component(s) and version/commit
- vulnerability type and impact
- clear reproduction steps or proof-of-concept
- required privileges/assumptions
- suggested remediation (if available)

Please redact private keys, seed phrases, access tokens, and personal data.

## Response targets

- initial triage acknowledgment: within 3 business days
- status update after validation: within 7 business days
- target remediation timeline: based on severity and exploitability

## Disclosure policy

- We follow coordinated disclosure.
- Please do not disclose publicly until a fix is released and maintainers confirm disclosure timing.
- Once fixed, we may publish a security advisory and release notes.

## Telemetry

The CLI sends anonymous usage analytics and crash diagnostics by default. See
[Telemetry and privacy](README.md#telemetry-and-privacy) for exactly what is and is not collected,
and for the three supported ways to disable it.

Telemetry is keyed to a random install id, never to a wallet address. Crash reports never contain
output from the Rust signing binaries: it is replaced with the binary name and exit code before the
report is built, not scrubbed.

Reports that telemetry transmits a secret, a wallet address, a recipient address, a transaction
hash, an exact amount, an RPC URL path or key, or anything else that could link an analytics
identity to an on-chain identity are in scope and should be reported through the private channels
above.

## Scope notes

Security reports may include, but are not limited to:

- key management and secret handling
- signing, approval, and policy-bypass issues
- privilege escalation in daemon/CLI flows
- insecure defaults, auth bypass, replay, or injection paths
- supply-chain and dependency risks with practical impact

Out-of-scope examples (unless chained with exploitable impact):

- purely theoretical issues without practical exploit path
- missing best-practice headers in non-sensitive local interfaces
- vulnerabilities in third-party services not controlled by this project
