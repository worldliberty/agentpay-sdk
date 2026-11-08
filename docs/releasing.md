# Releasing AgentPay

A release is one tarball per platform plus a `SHA256SUMS` file and the installer, attached to a GitHub release. Users install with:

```sh
curl -fsSL https://wlfi.sh | sh
agentpay setup
```

`https://wlfi.sh` must serve [`scripts/install.sh`](../scripts/install.sh), either the copy in the repository or the `install.sh` asset of the latest release (`https://github.com/worldliberty/agentpay-sdk/releases/latest/download/install.sh`). The installer is POSIX `sh` now, so pipe it into `sh`, not `bash`.

## What a release contains

| Platform | Asset | Built on |
|---|---|---|
| macOS, Apple silicon | `agentpay-<version>-macos-arm64.tar.gz` | `macos-15` |
| macOS, Intel | `agentpay-<version>-macos-x86_64.tar.gz` | `macos-15-intel` |
| Linux (glibc), x86_64 | `agentpay-<version>-linux-x86_64.tar.gz` | `ubuntu-24.04` |
| Linux (glibc), arm64 | `agentpay-<version>-linux-arm64.tar.gz` | `ubuntu-24.04-arm` |

Each tarball holds one directory, `agentpay-<version>-<os>-<arch>/`:

```text
bin/agentpay              launcher: runs client/dist/cli.js on node/bin/node
bin/agentpay-setup        symlink to ../libexec/agentpay-setup
libexec/                  agentpay-setup, agentpay-daemon, agentpay-paymentd
                          (+ agentpay-system-keychain and agentpay-auth on macOS)
client/                   the built Ink client and its production node_modules
node/                     bin/node and LICENSE of the pinned Node.js runtime
LICENSE
manifest.json             version, os, arch, target, commit, Node version, and the
                          path, mode, size and SHA-256 of every file
```

`agentpay setup` runs `sudo agentpay-setup install`, which copies the daemon binaries from its own directory (`libexec/`) into the root-owned prefix (`/Library/AgentPay/bin` or `/opt/agentpay/bin`). The launcher puts `libexec/` first on the client's `PATH`, so the client always finds the `agentpay-setup` and `agentpay-auth` that came with it.

### Why Node.js is bundled

The client is a Node program. Every release ships a pinned official Node.js build (`bin/node` and its license, about 40 MB of the download) instead of requiring Node on the machine:

- The old installer had to bootstrap Node through Homebrew when it was missing or too old. Bundling removes that step and the Homebrew dependency entirely.
- The client always runs on the Node version it was tested with, whatever `node` (if any) is on `PATH`. The launcher also clears `NODE_OPTIONS` and `NODE_PATH`.
- Supply chain: the Node archives are pinned by SHA-256 in [`crates/xtask/src/dist/node.rs`](../crates/xtask/src/dist/node.rs) and checked at build time. Nothing is resolved at install time.

To update Node, change `NODE_VERSION` and all four digests together, taking the digests from that release's `SHASUMS256.txt` (check its signature with the Node.js release keys first). Stay on an LTS line.

## Cutting a release

1. Bump the version in the root `Cargo.toml` (`[workspace.package] version`) and in `client/package.json`. They must match: `cargo xtask dist` and the release workflow check this.
2. Write `releases/v<version>.md` (used as the GitHub release notes) and update `CHANGELOG.md`.
3. Merge to `main`, then tag and push:

   ```sh
   git tag -s v1.2.3 -m "AgentPay 1.2.3"
   git push origin v1.2.3
   ```

4. [`.github/workflows/release.yml`](../.github/workflows/release.yml) then:
   - checks that the tag, `Cargo.toml` and `client/package.json` agree;
   - runs `cargo xtask dist --target <triple>` on each platform runner, with no caches;
   - installs each tarball with `scripts/install.sh` in a throwaway home (`cargo xtask test-install --dist dist`);
   - merges the per-platform `SHA256SUMS`, verifies every tarball against it, and creates the GitHub release with the four tarballs, `SHA256SUMS` and `install.sh`. Tags with a `-` (`v1.2.3-rc.1`) become pre-releases, which `latest` skips.

If a platform build fails, nothing is published. Fix it, delete the tag, and tag again.

## Building a release locally

```sh
cargo xtask dist                                # this machine's platform
cargo xtask dist --target x86_64-apple-darwin   # the other macOS architecture
just dist                                       # same as the first line
```

Requirements: the Rust toolchain from `rust-toolchain.toml` (plus `rustup target add <triple>` when building for the other macOS architecture), Node.js 20+ with npm to build the client, `curl`, and on macOS the Xcode command line tools (for `agentpay-auth`). Linux tarballs can only be built on Linux, and macOS tarballs on macOS.

`cargo xtask dist`:

1. builds `agentpay-daemon`, `agentpay-paymentd`, `agentpay-setup` (and `agentpay-system-keychain` on macOS) with `cargo build --release --locked --target <triple>`, remapping the repository and cargo home out of embedded paths, plus `agentpay-auth` on macOS;
2. copies `client/` (tracked and untracked-but-not-ignored files) to `target/dist/<triple>/client-src` and runs `npm ci` and `npm run build` there, so your working copy's `node_modules` and `dist` are never touched;
3. downloads the pinned Node.js archive into `target/dist/cache` (reused while its SHA-256 still matches) and extracts `bin/node` and `LICENSE`;
4. assembles the release, runs `npm ci --omit=dev --ignore-scripts` for the client's runtime dependencies (and fails on native addons), fails if any file other than the upstream Node binary contains your home directory or the repository path, and writes `manifest.json`;
5. writes `dist/agentpay-<version>-<os>-<arch>.tar.gz` and rewrites `dist/SHA256SUMS` for every tarball of this version in `dist/`.

Tarballs are reproducible: entries are sorted, owned by uid/gid 0, stamped with `SOURCE_DATE_EPOCH` (default: the commit time), and have normalized modes; the gzip header has no name or timestamp. Building the same commit with the same toolchain gives the same tarball as long as the compilers are deterministic. `manifest.json` records the commit and whether the tree was dirty. No environment variables, tokens or local paths are written into the release.

## Testing the installer

```sh
cargo xtask test-install              # synthetic release, seconds, no network
cargo xtask test-install --dist dist  # the real tarball from `cargo xtask dist`
just lint-shell                       # shellcheck --shell=sh
```

`test-install` serves the release from a temp directory over `file://` (`AGENTPAY_RELEASES_URL`) and runs `scripts/install.sh` under `/bin/sh` with no controlling terminal, a minimal environment and a throwaway `HOME` per scenario. It covers fresh installs, idempotent reruns, `curl | sh`, pinned versions, checksum mismatches and missing entries (nothing is extracted), `AGENTPAY_SHA256`, refusal of `$HOME`, `/`, `/usr*`, `/opt` and unknown non-empty directories, shell startup files (zsh, bash, fish, other shells, symlinked and half-edited files), moving an install from the previous TypeScript installer aside, downgrades, and the flags. With `--dist` it also runs the installed `agentpay --version`, `agentpay --help` and `agentpay-setup --version`. It never touches the real `~/.agentpay` and never uses sudo. CI runs the synthetic version on macOS and Ubuntu (where `/bin/sh` is dash) and shellcheck on Ubuntu.

## What the installer does

`scripts/install.sh` never uses sudo and refuses to run as root. In order, it:

1. detects the platform (an x86_64 shell under Rosetta gets the arm64 build; musl Linux is refused);
2. downloads `SHA256SUMS` of the requested release (`AGENTPAY_VERSION`, default latest) and picks the asset for this machine;
3. downloads the tarball and checks its SHA-256 before extracting anything (and against `AGENTPAY_SHA256` too, when set);
4. checks the install directory (`AGENTPAY_INSTALL_DIR`, default `~/.agentpay`): it refuses `$HOME`, `/`, `/usr*`, `/opt`, `/opt/agentpay`, `/Library/AgentPay` and other system directories, and non-empty directories that do not belong to AgentPay;
5. extracts into `versions/<version>/`, checks that `bin/agentpay --version` runs, then points `current` at it and links `bin/agentpay` and `bin/agentpay-setup`. Only the active version is kept;
6. adds `~/.agentpay/bin` to `PATH` in the login shell's startup file through one marked block (`# >>> agentpay >>>`), replacing the previous installer's block, which exported `AGENTPAY_HOME`. Running it again changes nothing. `--no-modify-path` skips this;
7. writes `installer.json` and prints a numbered summary ending in one next step, `agentpay setup`.

It is quiet unless something fails (`--verbose` prints every action). It only asks a question, on `/dev/tty`, before moving files from the previous TypeScript installer aside (default yes) or before a downgrade (default no). `--yes` answers yes to both. Without a terminal the default is taken, so a downgrade then needs `--yes`. There are no timed prompts.

Files from the previous installer (`app/`, `one-click-install-manifest.json`, the old `bin/` programs) are moved to `~/.agentpay/legacy/`. `config.json`, `client.json` and other state are left in place.

## Known limits

- The Linux binaries are built on Ubuntu 24.04, so they need a glibc at least as new as the one they link against there. Build on an older runner if older distributions must be supported.
- macOS binaries are not notarized. `curl` does not set the quarantine attribute, and the installer clears it anyway after the checksum matches.
