# AgentPay workspace tasks. Run `just --list` to see them.

default:
    @just --list

# Build every crate in the workspace.
build:
    cargo build --workspace

# Run every test in the workspace.
test:
    cargo test --workspace

# Everything CI lints: formatting, clippy, and repository checks.
lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo xtask check-file-length
    cargo xtask check-no-js
    cargo xtask gen-api --check
    RUSTDOCFLAGS="-D warnings" cargo doc -p agentpay-api --no-deps

# Regenerate the daemon API's JSON Schema (docs/api) and TypeScript types (client/src/generated).
gen-api:
    cargo xtask gen-api

# Format all Rust code.
fmt:
    cargo fmt --all

# Inner development loop: format, lint, then test.
dev: fmt lint test

# Build the macOS admin-auth helper (Swift) into target/release/agentpay-auth.
# Pass build options through, e.g. `just macos-auth --arch arm64 --arch x86_64`.
macos-auth *args:
    cargo xtask build-macos-auth {{args}}

# Build the macOS admin-auth helper and run its end-to-end checks without the Secure Enclave.
macos-auth-test:
    cargo xtask test-macos-auth

# Also run the Secure Enclave checks, including the user-presence enforcement regression test.
# Needs a Mac with a Secure Enclave and a login password; never prompts.
macos-auth-test-se:
    AGENTPAY_SE_TESTS=1 cargo xtask test-macos-auth

# Install the client's dependencies exactly as locked (client/package-lock.json).
client-install:
    cd client && npm ci

# Build the TypeScript + Ink client into client/dist.
client-build:
    cd client && npm run build

# Typecheck and test the client (tsc --noEmit, then Vitest).
client-test:
    cd client && npm run typecheck && npm test

# Lint and format-check the client (Biome).
client-lint:
    cd client && npm run lint

# Build the release tarball for this machine into dist/ and update dist/SHA256SUMS.
# Pass options through, e.g. `just dist --target x86_64-apple-darwin`. See docs/releasing.md.
dist *args:
    cargo xtask dist {{args}}

# Run scripts/install.sh end to end in throwaway homes against a synthetic release, or the
# real one with `just test-install --dist dist`. Never touches ~/.agentpay and never uses sudo.
test-install *args:
    cargo xtask test-install {{args}}

# Check the installer and the release launcher with shellcheck (POSIX sh).
lint-shell:
    shellcheck --shell=sh scripts/install.sh crates/xtask/src/dist/agentpay.sh
