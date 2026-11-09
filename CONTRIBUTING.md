# Contributing to AgentPay SDK

Thanks for contributing. Keep changes focused, tested, and documented.

## Scope

Contributions are welcome for:

- bug fixes
- tests and reliability improvements
- documentation
- developer experience and tooling
- security hardening (non-sensitive issues only; see [SECURITY.md](SECURITY.md) for vulnerabilities)

## Before you start

1. Check existing issues and pull requests to avoid duplicates.
2. Open an issue for non-trivial changes before implementation.
3. Keep pull requests focused: one logical change per PR.
4. Read [docs/architecture.md](docs/architecture.md). Changes to the daemon API also need
   [docs/daemon-api.md](docs/daemon-api.md).

## Toolchain

| Tool | Version |
|---|---|
| Rust | pinned in [`rust-toolchain.toml`](rust-toolchain.toml) (`rustup` installs it automatically) |
| Node.js (client only) | [`client/.nvmrc`](client/.nvmrc), npm with the committed `client/package-lock.json` |
| [`just`](https://github.com/casey/just) | any recent version |
| Xcode command line tools (macOS) | for `agentpay-auth` (Swift) |

## Development

```bash
just build                      # cargo build --workspace
just test                       # cargo test --workspace
just lint                       # fmt, clippy -D warnings, file length, no JavaScript,
                                # gen-api --check, API rustdoc
just dev                        # fmt, lint, test
just client-install             # npm ci in client/
just client-test                # tsc --noEmit, then Vitest
just client-lint                # Biome
cargo test -p agentpay-signerd  # one crate
cargo xtask build-macos-auth    # build agentpay-auth
cargo xtask test-macos-auth     # its end-to-end checks (AGENTPAY_SE_TESTS=1 adds Secure Enclave checks)
```

CI (`.github/workflows/ci.yml`) runs the lint, Rust test, MSRV, and client jobs on macOS and Linux.
Run `just lint`, `just test`, and the client recipes before opening a pull request.

## Rules

- **No JavaScript.** Only `.rs`, `.ts`, and `.tsx` (`cargo xtask check-no-js`). Repository tooling
  goes in `crates/xtask`.
- **Files stay at or under 1,000 lines** (`cargo xtask check-file-length`). Split into modules.
- **`clippy -D warnings`, rustfmt, Biome, and strict `tsc`** are enforced.
- **The daemon API is a public contract.** Every wire change goes through `crates/agentpay-api`
  (fully documented: `#![deny(missing_docs)]`), its fixtures, `docs/daemon-api.md`, and
  `cargo xtask gen-api`. Follow the versioning and deprecation policy in the spec.
- **Product logic lives in the daemons.** The client only parses arguments, calls the daemons
  through the generated types, and renders output. User-facing client text goes in
  `client/src/copy/`.
- **Secrets only travel on stdin or pipes**, never in arguments or environment variables. Use
  `zeroize` for secret memory. No `unwrap` in daemon code paths.
- **Tests with every change.** Each crate has unit tests; the payments service has end-to-end tests
  over real sockets (`crates/agentpay-paymentd/tests/e2e.rs`); the client uses Vitest with
  `ink-testing-library` and the API fixtures.

To add a payment feature, follow "Adding a paymentd method" in
[docs/daemon-api.md](docs/daemon-api.md) (the `skills/add-plugin` skill walks through it).

## What to submit

### Bug report

- clear title and expected vs actual behavior
- reproducible steps
- environment: OS and version, `agentpay --version`, `sudo ~/.agentpay/bin/agentpay-setup status`
- logs with secrets, addresses, and tokens redacted
- a minimal reproduction when possible

### Feature request

- the problem (what is hard today)
- the proposed solution and alternatives considered
- breaking-change risk, including API version impact
- security implications

### Pull request

- a short problem statement and a summary of the change
- tests for changed behavior (or a clear reason why not)
- updated docs, CLI help, and skills for user-facing changes
- migration notes for breaking changes, and a `CHANGELOG.md` entry

## Pull request quality bar

- no unrelated refactors
- no plaintext secrets or private keys in code, tests, fixtures, logs, or screenshots
- all checks above pass locally

## Commit guidance

- Use clear commit messages that describe intent (`fix(paymentd): …`, `docs: …`).
- Reference issue IDs when relevant.
- Squash noisy WIP commits before merge.

## Security issues

Do not file public issues for exploitable vulnerabilities. Use the private process in
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the repository
[MIT License](LICENSE).
