#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

WORK_DIR_DEFAULT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/agentpay-installer-smoke"
KEEP_WORK_DIR_DEFAULT="${AGENTPAY_INSTALLER_SMOKE_KEEP_WORK_DIR:-1}"
BUNDLE_ARCHIVE_DEFAULT="${AGENTPAY_INSTALLER_SMOKE_BUNDLE_ARCHIVE:-}"

WORK_DIR="$WORK_DIR_DEFAULT"
KEEP_WORK_DIR="$KEEP_WORK_DIR_DEFAULT"
BUNDLE_ARCHIVE="$BUNDLE_ARCHIVE_DEFAULT"

say() {
  printf '[agentpay-installer-smoke] %s\n' "$*"
}

die() {
  printf '[agentpay-installer-smoke] error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF_USAGE'
Run a GitHub-friendly smoke test for the AgentPay one-click installer.

Usage:
  scripts/run-installer-smoke.sh [options]

Options:
  --work-dir <dir>           Scratch directory for the bundle, install root, fake HOME, and logs
  --bundle-archive <path>    Prebuilt AgentPay installer bundle archive to install
  --keep-work-dir <0|1>      Keep the work directory after success/failure (default: 1)
  --help                     Show this message

Behavior:
  - runs scripts/installer.sh against a prebuilt bundle twice
  - uses a fake HOME so shell RC writes do not pollute the host runner
  - skips skills and admin setup
  - verifies agentpay and the required runtime binaries after install
EOF_USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --work-dir)
        WORK_DIR="$2"
        shift 2
        ;;
      --bundle-archive)
        BUNDLE_ARCHIVE="$2"
        shift 2
        ;;
      --keep-work-dir)
        KEEP_WORK_DIR="$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1"
        ;;
    esac
  done
}

normalize_keep_work_dir() {
  case "$KEEP_WORK_DIR" in
    0|1)
      ;;
    *)
      die "--keep-work-dir must be 0 or 1"
      ;;
  esac
}

require_host() {
  case "$(uname -s)" in
    Darwin|Linux)
      ;;
    *)
      die "This smoke runner currently supports only macOS or Linux hosts."
      ;;
  esac
  command -v tar >/dev/null 2>&1 || die "tar is required."
  command -v bash >/dev/null 2>&1 || die "bash is required."
  [[ -n "$BUNDLE_ARCHIVE" ]] || die "--bundle-archive is required."
  [[ -f "$BUNDLE_ARCHIVE" ]] || die "Bundle archive does not exist: $BUNDLE_ARCHIVE"
}

runtime_requires_macos_entries() {
  [[ "$(uname -s)" == "Darwin" ]]
}

runtime_requires_linux_entries() {
  [[ "$(uname -s)" == "Linux" ]]
}

prepare_dirs() {
  local abs=""
  mkdir -p "$(dirname "$WORK_DIR")"
  mkdir -p "$WORK_DIR"
  abs="$(cd "$WORK_DIR" && pwd)"
  WORK_DIR="$abs"
  LOG_DIR="$WORK_DIR/logs"
  HOME_DIR="$WORK_DIR/home"
  INSTALL_DIR="$WORK_DIR/install-root"
  ABS_BUNDLE_ARCHIVE="$(cd "$(dirname "$BUNDLE_ARCHIVE")" && pwd)/$(basename "$BUNDLE_ARCHIVE")"

  rm -rf "$LOG_DIR" "$HOME_DIR" "$INSTALL_DIR"
  mkdir -p "$LOG_DIR" "$HOME_DIR"
}

cleanup_on_success() {
  if [[ "$KEEP_WORK_DIR" == "1" ]]; then
    return
  fi
  rm -rf "$WORK_DIR"
}

write_outputs() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
      printf 'work_dir=%s\n' "$WORK_DIR"
      printf 'log_dir=%s\n' "$LOG_DIR"
      printf 'install_dir=%s\n' "$INSTALL_DIR"
    } >>"$GITHUB_OUTPUT"
  fi
}

run_and_capture() {
  local logfile="$1"
  shift
  (
    set -o pipefail
    "$@" 2>&1 | tee "$logfile"
  )
}

run_installer_pass() {
  local pass_name="$1"
  local logfile="$LOG_DIR/${pass_name}.log"

  say "Running installer pass: $pass_name"
  run_and_capture "$logfile" env \
    HOME="$HOME_DIR" \
    PATH="${PATH}" \
    SHELL="/bin/bash" \
    AGENTPAY_SDK_BUNDLE_URL="file://${ABS_BUNDLE_ARCHIVE}" \
    AGENTPAY_SETUP_DIR="$INSTALL_DIR" \
    AGENTPAY_SETUP_ASSUME_DEFAULTS="1" \
    AGENTPAY_SETUP_INSTALL_SKILLS="no" \
    AGENTPAY_SETUP_RUN_ADMIN_SETUP="no" \
    AGENTPAY_SETUP_USE_STDIN="1" \
    HOMEBREW_NO_AUTO_UPDATE="1" \
    bash "$REPO_ROOT/scripts/installer.sh"
}

verify_install() {
  local runtime_dir="$INSTALL_DIR"
  local verify_log="$LOG_DIR/verify.log"

  [[ -x "$runtime_dir/bin/agentpay" ]] || die "Missing agentpay runtime entry after install."
  [[ -x "$runtime_dir/bin/agentpay-admin" ]] || die "Missing agentpay-admin runtime entry after install."
  [[ -x "$runtime_dir/bin/agentpay-daemon" ]] || die "Missing agentpay-daemon runtime entry after install."
  [[ -x "$runtime_dir/bin/agentpay-agent" ]] || die "Missing agentpay-agent runtime entry after install."
  [[ -f "$runtime_dir/app/package.json" ]] || die "Missing packaged CLI metadata after install."
  [[ -f "$runtime_dir/app/dist/cli.cjs" ]] || die "Missing packaged CLI entrypoint after install."
  [[ -d "$runtime_dir/app/node_modules" ]] || die "Missing packaged CLI runtime dependencies after install."
  if runtime_requires_macos_entries; then
    [[ -x "$runtime_dir/bin/agentpay-system-keychain" ]] || die "Missing agentpay-system-keychain runtime entry after install."
  elif runtime_requires_linux_entries; then
    [[ -x "$runtime_dir/bin/agentpay-daemon-password-helper.sh" ]] || die "Missing Linux daemon password helper runtime entry after install."
  fi

  run_and_capture "$verify_log" env \
    HOME="$HOME_DIR" \
    PATH="$runtime_dir/bin:${PATH}" \
    AGENTPAY_HOME="$runtime_dir" \
    EXPECT_MACOS_RUNTIME="$(if runtime_requires_macos_entries; then printf '1'; else printf '0'; fi)" \
    EXPECT_LINUX_RUNTIME="$(if runtime_requires_linux_entries; then printf '1'; else printf '0'; fi)" \
    bash -c '
      set -euo pipefail
      command -v agentpay
      agentpay --help
      agentpay --version
      test -x "$AGENTPAY_HOME/bin/agentpay"
      test -x "$AGENTPAY_HOME/bin/agentpay-admin"
      test -x "$AGENTPAY_HOME/bin/agentpay-daemon"
      test -x "$AGENTPAY_HOME/bin/agentpay-agent"
      if [[ "${EXPECT_MACOS_RUNTIME:-0}" == "1" ]]; then
        test -x "$AGENTPAY_HOME/bin/agentpay-system-keychain"
      elif [[ "${EXPECT_LINUX_RUNTIME:-0}" == "1" ]]; then
        test -x "$AGENTPAY_HOME/bin/agentpay-daemon-password-helper.sh"
      fi
      test -f "$AGENTPAY_HOME/app/package.json"
      test -f "$AGENTPAY_HOME/app/dist/cli.cjs"
      test -d "$AGENTPAY_HOME/app/node_modules"
    '

  {
    printf 'WORK_DIR=%s\n' "$WORK_DIR"
    printf 'HOME_DIR=%s\n' "$HOME_DIR"
    printf 'INSTALL_DIR=%s\n' "$INSTALL_DIR"
    printf 'RUNTIME_DIR=%s\n' "$runtime_dir"
    printf 'BUNDLE_ARCHIVE=%s\n' "$ABS_BUNDLE_ARCHIVE"
  } >"$LOG_DIR/paths.env"

  find "$INSTALL_DIR" -maxdepth 4 -print | sort >"$LOG_DIR/install-tree.txt"
}

main() {
  parse_args "$@"
  normalize_keep_work_dir
  require_host
  prepare_dirs
  write_outputs

  run_installer_pass installer-pass-1
  run_installer_pass installer-pass-2
  verify_install

  say "Installer smoke succeeded. Logs: $LOG_DIR"
  cleanup_on_success
}

main "$@"
