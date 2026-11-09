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

## Supported versions

Security fixes are made on the latest release line. AgentPay 1.0.0 replaced the TypeScript CLI,
the relay and web console, and the vault password; reports against 0.x releases are accepted when
the issue also affects 1.x or a supported migration path.

## Security model

The trust boundaries are described in [docs/architecture.md](docs/architecture.md) and the API's
[security notes](docs/daemon-api.md#security-notes-for-integrators). In short:

- only the signer daemon runs as root; it holds every key and enforces policy, spending limits, and
  manual approvals;
- the payments service runs as an unprivileged account, holds no keys, and is on the signer
  daemon's agent allowlist only;
- admin actions need a root peer (`sudo`) or a short-lived lease from a Secure Enclave key
  (Touch ID or the Mac password);
- secrets travel only on stdin, pipes, or the daemon sockets.

Bypasses of any of these boundaries are in scope, for example: signing outside an agent's policies
or limits, reaching admin methods without admin authority, impersonating a daemon socket, leaking
agent tokens, lease secrets, backup passphrases, or the machine secret, or the payments service
signing or sending something other than what the signer daemon approved.

## Telemetry

The payments service sends anonymous usage analytics and crash reports by default. See
[Telemetry and privacy](README.md#telemetry-and-privacy) for what is and is not collected and how
to turn it off.

Telemetry is keyed to a random install id, never to a wallet address. Reports that telemetry
transmits a secret, a wallet or recipient address, a transaction hash, an exact amount, an RPC or
merchant URL path or key, or anything else that could link an analytics identity to an on-chain
identity are in scope and should be reported through the private channels above.

## Scope notes

Security reports may include, but are not limited to:

- key management and secret handling
- signing, approval, and policy-bypass issues
- privilege escalation in the daemons, the installer (`agentpay-setup`), or the client
- insecure defaults, auth bypass, replay, or injection paths
- supply-chain and dependency risks with practical impact

Out-of-scope examples (unless chained with exploitable impact):

- purely theoretical issues without practical exploit path
- missing best-practice headers in non-sensitive local interfaces
- vulnerabilities in third-party services not controlled by this project
