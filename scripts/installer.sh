#!/usr/bin/env bash
set -eEuo pipefail

INSTALL_DIR_DEFAULT="${AGENTPAY_SETUP_DIR:-$HOME/.agentpay}"
ASSUME_DEFAULTS="${AGENTPAY_SETUP_ASSUME_DEFAULTS:-0}"
INSTALL_SKILLS_MODE="${AGENTPAY_SETUP_INSTALL_SKILLS:-auto}"
RUN_ADMIN_SETUP_DEFAULT="${AGENTPAY_SETUP_RUN_ADMIN_SETUP:-}"
CURSOR_WORKSPACE_DEFAULT="${AGENTPAY_SETUP_CURSOR_WORKSPACE:-}"
WORKSPACE_DEFAULT="${AGENTPAY_SETUP_WORKSPACE:-}"
BUNDLE_URL_OVERRIDE="${AGENTPAY_SDK_BUNDLE_URL:-${AGENTPAY_SDK_ARCHIVE_URL:-}}"
PUBLIC_RELEASE_REPO="${AGENTPAY_PUBLIC_RELEASE_REPO:-__AGENTPAY_PUBLIC_RELEASE_REPO__}"
PUBLIC_RELEASE_TAG="${AGENTPAY_PUBLIC_RELEASE_TAG:-__AGENTPAY_PUBLIC_RELEASE_TAG__}"
LEGACY_RELAY_MODE="${AGENTPAY_SETUP_RELAY_MODE:-}"
INSTALLER_MODE_DEFAULT="${AGENTPAY_SETUP_MODE:-full}"
AUTO_CONTINUE_SECONDS="${AGENTPAY_SETUP_AUTO_CONTINUE_SECONDS:-8}"
KEY_SEQUENCE_TIMEOUT_SECONDS="${AGENTPAY_SETUP_KEY_SEQUENCE_TIMEOUT_SECONDS:-0.05}"
NODE_MIN_MAJOR=20
RETRY_ATTEMPTS=3
RETRY_DELAY_SECONDS=2
CURRENT_STEP=""
CURRENT_STEP_HINT=""
PROMPT_IN="/dev/stdin"
PROMPT_OUT="/dev/stderr"
PROMPT_IN_FD=0
PROMPT_OUT_FD=2
HAS_LOCAL_TTY=0
INHERITED_PATH="${PATH:-}"
SHELL_RC_PATH=""
INSTALLED_SKILL_TARGETS=()
INSTALLED_CURSOR_ARTIFACTS=()
INSTALLED_PATH_SHIMS=()
SKILL_TARGET_IDS=()
SKILL_TARGET_LABELS=()
SKILL_TARGET_TYPES=()
SKILL_TARGET_DESTINATIONS=()
SKILL_TARGET_SOURCES=()
SKILL_TARGET_DETECTED=()
SKILL_TARGET_SELECTED=()
SKILL_TARGET_RECOMMENDED=()
SKILL_TARGET_NOTES=()
SKILL_TARGET_MENU_STATUS=""
CURRENT_SHELL_SHIM_PATH=""
CURRENT_SHELL_SHIM_WARNING=""
PATH_SHIM_MARKER="# agentpay-sdk one-click PATH shim"
INSTALLER_MODE=""

say() {
  printf '[agentpay-setup] %s\n' "$*"
}

warn() {
  printf '[agentpay-setup] warning: %s\n' "$*" >&2
}

die() {
  printf '[agentpay-setup] error: %s\n' "$*" >&2
  exit 1
}

step() {
  CURRENT_STEP="$1"
  CURRENT_STEP_HINT="${2:-}"
  say "$CURRENT_STEP"
}

on_error() {
  local status="$1"
  local line_no="$2"

  if [[ -n "$CURRENT_STEP" ]]; then
    warn "Setup failed during: $CURRENT_STEP"
  fi
  warn "The installer stopped at line $line_no with exit code $status."
  if [[ -n "$CURRENT_STEP_HINT" ]]; then
    warn "$CURRENT_STEP_HINT"
  fi
  warn "After fixing the issue, rerun this installer in the same directory. It is designed to be retry-safe."
}

trap 'on_error $? $LINENO' ERR

configure_bash_compatibility() {
  if (( BASH_VERSINFO[0] < 4 )); then
    KEY_SEQUENCE_TIMEOUT_SECONDS="${AGENTPAY_SETUP_KEY_SEQUENCE_TIMEOUT_SECONDS:-1}"
  fi
}

usage() {
  cat <<'EOF_USAGE'
AgentPay SDK one-click bootstrap

Usage:
  bash installer.sh
  bash installer.sh --skills-only
  curl -fsSL https://wlfi.sh | bash
  curl -fsSL https://wlfi.sh | bash -s -- --skills-only

What it does:
  - choose an install directory
  - download a prebuilt AgentPay SDK runtime bundle for this macOS or Linux architecture
  - install `agentpay` into a dedicated AGENTPAY_HOME without local Cargo or pnpm builds
  - auto-detect and preselect current AI agent skill targets
  - let the user toggle preset destinations and add custom skill/adaptor paths
  - install skills/adapters for Codex, Claude, Cline, Goose, Windsurf, OpenClaw, portable `.agents`, Cursor, and common workspace instruction files
  - optionally launch `agentpay admin setup`

What it does not do by default:
  - no local Rust build
  - no local npm / pnpm workspace install

What `--skills-only` does:
  - download the standard AgentPay SDK bundle and reuse its embedded skill files
  - auto-detect supported agent paths and present them as a toggleable install list
  - let the user add custom skill-pack or adapter destinations
  - skip Node, AgentPay SDK runtime, shell PATH, and wallet setup entirely

Optional environment overrides:
  AGENTPAY_SDK_BUNDLE_URL         reachable .tar/.tar.gz bundle to install
  AGENTPAY_SDK_ARCHIVE_URL        legacy alias for AGENTPAY_SDK_BUNDLE_URL
  AGENTPAY_PUBLIC_RELEASE_REPO    GitHub owner/repo that hosts AgentPay SDK bundles
  AGENTPAY_PUBLIC_RELEASE_TAG     GitHub release tag to download AgentPay SDK bundles from
  AGENTPAY_SETUP_DIR              install directory root
  AGENTPAY_SETUP_ASSUME_DEFAULTS  use defaults for all non-secret prompts
  AGENTPAY_SETUP_AUTO_CONTINUE_SECONDS seconds before default path/selection prompts auto-continue
  AGENTPAY_SETUP_MODE             full or skills-only
  AGENTPAY_SETUP_INSTALL_SKILLS   auto, yes, or no
  AGENTPAY_SETUP_WORKSPACE        explicit workspace path for AGENTS/CLAUDE/GEMINI/Copilot skill adapters
  AGENTPAY_SETUP_RUN_ADMIN_SETUP  yes or no; default is no
  AGENTPAY_SETUP_CURSOR_WORKSPACE explicit Cursor workspace path for adapter install
EOF_USAGE
}

parse_args() {
  INSTALLER_MODE="$INSTALLER_MODE_DEFAULT"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --skills-only)
        INSTALLER_MODE="skills-only"
        shift
        ;;
      --full)
        INSTALLER_MODE="full"
        shift
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

installer_mode_is_skills_only() {
  [[ "$INSTALLER_MODE" == "skills-only" ]]
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

clear_macos_quarantine() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    return
  fi

  if ! command_exists xattr; then
    return
  fi

  local target=""
  for target in "$@"; do
    [[ -e "$target" ]] || continue
    xattr -dr com.apple.quarantine "$target" >/dev/null 2>&1 || true
  done
}

host_kernel_name() {
  uname -s
}

host_bundle_platform_label() {
  local kernel_name
  kernel_name="$(host_kernel_name)"
  case "$kernel_name" in
    Darwin)
      printf 'macos\n'
      ;;
    Linux)
      printf 'linux\n'
      ;;
    *)
      die "Unsupported operating system for the one-click runtime bundle: $kernel_name"
      ;;
  esac
}

host_arch_label() {
  local machine
  machine="$(uname -m)"
  case "$machine" in
    arm64|aarch64)
      if [[ "$(host_kernel_name)" == "Linux" ]]; then
        die "Linux ARM64 is not currently supported. The AgentPay SDK installer supports macOS (ARM64/x64) and Linux x64."
      fi
      printf 'arm64\n'
      ;;
    x86_64)
      printf 'x64\n'
      ;;
    *)
      die "Unsupported architecture for the one-click bundle: $machine"
      ;;
  esac
}

runtime_bundle_requires_macos_helpers() {
  [[ "$(host_kernel_name)" == "Darwin" ]]
}

runtime_bundle_requires_linux_helpers() {
  [[ "$(host_kernel_name)" == "Linux" ]]
}

host_supports_packaged_admin_setup() {
  [[ "$(host_kernel_name)" == "Darwin" || "$(host_kernel_name)" == "Linux" ]]
}

init_prompt_io() {
  if [[ "${AGENTPAY_SETUP_USE_STDIN:-}" == "1" ]]; then
    PROMPT_IN="/dev/stdin"
    PROMPT_OUT="/dev/stderr"
    PROMPT_IN_FD=0
    PROMPT_OUT_FD=2
    HAS_LOCAL_TTY=0
    return
  fi

  if [[ -r /dev/tty ]] && [[ -w /dev/tty ]]; then
    if (( BASH_VERSINFO[0] >= 4 )); then
      exec {PROMPT_IN_FD}<>/dev/tty
    else
      PROMPT_IN_FD=3
      exec 3<>/dev/tty
    fi
    PROMPT_OUT_FD="$PROMPT_IN_FD"
    PROMPT_IN="/dev/tty"
    PROMPT_OUT="/dev/tty"
    HAS_LOCAL_TTY=1
    return
  fi

  PROMPT_IN="/dev/stdin"
  PROMPT_OUT="/dev/stderr"
  PROMPT_IN_FD=0
  PROMPT_OUT_FD=2
  HAS_LOCAL_TTY=0
}

read_prompt() {
  local prompt="$1"
  local reply=""

  printf '%s' "$prompt" >&$PROMPT_OUT_FD
  IFS= read -r -u "$PROMPT_IN_FD" reply || die "Installer input closed while waiting for: $prompt"
  printf '%s\n' "$reply"
}

can_auto_continue_prompt() {
  [[ "$ASSUME_DEFAULTS" != "1" ]] &&
    [[ "$PROMPT_IN" == "/dev/tty" ]] &&
    [[ "$PROMPT_OUT" == "/dev/tty" ]] &&
    [[ "$AUTO_CONTINUE_SECONDS" =~ ^[0-9]+$ ]] &&
    (( AUTO_CONTINUE_SECONDS > 0 ))
}

read_prompt_with_default_reply() {
  local prompt="$1"
  local default_reply="$2"
  local default_notice="${3:-Using default.}"
  local reply=""
  local remaining=0

  if ! can_auto_continue_prompt; then
    read_prompt "$prompt"
    return
  fi

  remaining="$AUTO_CONTINUE_SECONDS"
  while (( remaining > 0 )); do
    printf '\r\033[2K%s (auto in %ss) ' "$prompt" "$remaining" >&$PROMPT_OUT_FD
    if IFS= read -r -u "$PROMPT_IN_FD" -t 1 reply; then
      printf '\r\033[2K' >&$PROMPT_OUT_FD
      printf '%s\n' "$reply"
      return
    fi
    remaining=$((remaining - 1))
  done

  printf '\r\033[2K%s\n' "$default_notice" >&$PROMPT_OUT_FD
  printf '%s\n' "$default_reply"
}

confirm() {
  local prompt="$1"
  local default_answer="${2:-Y}"
  local reply=""
  local suffix="[Y/n]"

  if [[ "$default_answer" == "N" ]]; then
    suffix="[y/N]"
  fi

  if [[ "$ASSUME_DEFAULTS" == "1" ]]; then
    reply="$default_answer"
  else
    reply="$(read_prompt "$prompt $suffix ")"
  fi

  reply="${reply:-$default_answer}"
  case "$reply" in
    y|Y|yes|YES)
      return 0
      ;;
    n|N|no|NO)
      return 1
      ;;
    *)
      warn "Please answer yes or no."
      confirm "$prompt" "$default_answer"
      return $?
      ;;
  esac
}

prompt_with_default() {
  local prompt="$1"
  local default_value="$2"
  local reply=""

  if [[ "$ASSUME_DEFAULTS" == "1" ]]; then
    printf '%s\n' "$default_value"
    return
  fi

  reply="$(read_prompt_with_default_reply "$prompt [$default_value]" "$default_value" "Using default: $default_value")"
  if [[ -z "$reply" ]]; then
    printf 'Using default: %s\n' "$default_value" >&$PROMPT_OUT_FD
    printf '%s\n' "$default_value"
    return
  fi
  printf '%s\n' "$reply"
}

normalize_lowercase_env() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

trim_ascii_whitespace() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

compact_display_path() {
  local value="$1"
  if [[ -n "${HOME:-}" ]]; then
    value="${value//$HOME/\~}"
  fi
  printf '%s' "$value"
}

run_with_retry() {
  local attempts="$1"
  local delay_seconds="$2"
  shift 2

  local attempt=1
  local status=0
  while true; do
    if "$@"; then
      return 0
    else
      status=$?
    fi
    if (( attempt >= attempts )); then
      return "$status"
    fi
    warn "Attempt $attempt/${attempts} failed for: $*. Retrying in ${delay_seconds}s."
    sleep "$delay_seconds"
    attempt=$((attempt + 1))
  done
}

version_triplet_from_string() {
  local value="$1"
  local version
  version="$(printf '%s\n' "$value" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 | tr '.' ' ')"
  if [[ -z "$version" ]]; then
    printf '0 0 0\n'
    return
  fi
  printf '%s\n' "$version"
}

version_gte() {
  local left_major="$1"
  local left_minor="$2"
  local left_patch="$3"
  local right_major="$4"
  local right_minor="$5"
  local right_patch="$6"

  if (( left_major > right_major )); then
    return 0
  fi
  if (( left_major < right_major )); then
    return 1
  fi
  if (( left_minor > right_minor )); then
    return 0
  fi
  if (( left_minor < right_minor )); then
    return 1
  fi
  if (( left_patch >= right_patch )); then
    return 0
  fi
  return 1
}

load_brew_shellenv() {
  if command_exists brew; then
    eval "$(brew shellenv)"
    return
  fi

  if [[ "${AGENTPAY_SETUP_SKIP_SYSTEM_BREW_LOOKUP:-}" == "1" ]]; then
    return
  fi

  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
    return
  fi

  if [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
}

ensure_homebrew() {
  load_brew_shellenv
  if command_exists brew; then
    return
  fi

  if ! confirm "Homebrew is required to install the Node.js runtime. Install Homebrew now?" "Y"; then
    die "Homebrew is required to continue."
  fi

  if (( HAS_LOCAL_TTY == 0 )); then
    die "Homebrew bootstrap requires a local TTY. Install Homebrew manually first, then rerun this installer from a local terminal."
  fi

  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" </dev/tty >/dev/tty 2>/dev/tty
  load_brew_shellenv
  command_exists brew || die "Homebrew install finished, but brew is still unavailable on PATH."
}

ensure_node() {
  local node_version node_major node_minor node_patch

  if command_exists node; then
    node_version="$(node --version 2>/dev/null || true)"
    read -r node_major node_minor node_patch <<<"$(version_triplet_from_string "$node_version")"
    if version_gte "$node_major" "$node_minor" "$node_patch" "$NODE_MIN_MAJOR" 0 0; then
      NODE_PATH="$(command -v node)"
      return
    fi
  fi

  ensure_homebrew
  if ! confirm "Node ${NODE_MIN_MAJOR}+ is required to run agentpay. Install or update it with Homebrew now?" "Y"; then
    die "Node ${NODE_MIN_MAJOR}+ is required."
  fi

  if (( HAS_LOCAL_TTY == 1 )); then
    brew install node@20 </dev/tty >/dev/tty 2>/dev/tty
  else
    brew install node@20
  fi
  export PATH="$(brew --prefix node@20)/bin:$PATH"
  command_exists node || die "Node install finished, but node is still unavailable on PATH."

  node_version="$(node --version 2>/dev/null || true)"
  read -r node_major node_minor node_patch <<<"$(version_triplet_from_string "$node_version")"
  version_gte "$node_major" "$node_minor" "$node_patch" "$NODE_MIN_MAJOR" 0 0 || die "Node install finished, but the detected version is still too old: ${node_version:-unknown}"
  NODE_PATH="$(command -v node)"
}

validate_installer_modes() {
  ASSUME_DEFAULTS="$(normalize_lowercase_env "$ASSUME_DEFAULTS")"
  INSTALLER_MODE="$(normalize_lowercase_env "$INSTALLER_MODE")"
  INSTALL_SKILLS_MODE="$(normalize_lowercase_env "$INSTALL_SKILLS_MODE")"
  LEGACY_RELAY_MODE="$(normalize_lowercase_env "$LEGACY_RELAY_MODE")"

  case "$ASSUME_DEFAULTS" in
    0|1|yes|no|true|false)
      ;;
    *)
      die "AGENTPAY_SETUP_ASSUME_DEFAULTS must be one of: 0, 1, yes, no, true, false."
      ;;
  esac

  case "$ASSUME_DEFAULTS" in
    1|yes|true)
      ASSUME_DEFAULTS="1"
      ;;
    *)
      ASSUME_DEFAULTS="0"
      ;;
  esac

  case "$INSTALLER_MODE" in
    full|skills-only)
      ;;
    *)
      die "AGENTPAY_SETUP_MODE must be full or skills-only."
      ;;
  esac

  [[ "$AUTO_CONTINUE_SECONDS" =~ ^[0-9]+$ ]] ||
    die "AGENTPAY_SETUP_AUTO_CONTINUE_SECONDS must be a non-negative integer."

  case "$INSTALL_SKILLS_MODE" in
    auto|yes|no)
      ;;
    *)
      die "AGENTPAY_SETUP_INSTALL_SKILLS must be auto, yes, or no."
      ;;
  esac

  if [[ -n "$LEGACY_RELAY_MODE" ]] && [[ "$LEGACY_RELAY_MODE" != "skip" ]]; then
    die "Relay setup is not part of the one-click installer. Leave AGENTPAY_SETUP_RELAY_MODE unset or set it to skip."
  fi

  if installer_mode_is_skills_only; then
    if [[ "$INSTALL_SKILLS_MODE" == "no" ]]; then
      die "AGENTPAY_SETUP_INSTALL_SKILLS=no cannot be used with --skills-only."
    fi

    if [[ "${AGENTPAY_SETUP_SKIP_SKILLS:-}" == "1" ]]; then
      die "AGENTPAY_SETUP_SKIP_SKILLS=1 cannot be used with --skills-only."
    fi

    case "$(normalize_lowercase_env "${RUN_ADMIN_SETUP_DEFAULT:-}")" in
      ""|no)
        ;;
      yes)
        die "AGENTPAY_SETUP_RUN_ADMIN_SETUP=yes cannot be used with --skills-only."
        ;;
      *)
        die "AGENTPAY_SETUP_RUN_ADMIN_SETUP must be yes or no."
        ;;
    esac
  fi
}

resolve_run_admin_setup_default() {
  local requested="${RUN_ADMIN_SETUP_DEFAULT:-}"
  if [[ -n "$requested" ]]; then
    requested="$(normalize_lowercase_env "$requested")"
    case "$requested" in
      yes|no)
        printf '%s\n' "$requested"
        return
        ;;
      *)
        die "AGENTPAY_SETUP_RUN_ADMIN_SETUP must be yes or no."
        ;;
    esac
  fi

  printf 'no\n'
}

resolve_runtime_bundle_asset_name() {
  printf 'agentpay-sdk-%s-%s.tar.gz\n' "$(host_bundle_platform_label)" "$(host_arch_label)"
}

resolve_skill_bundle_platform_label() {
  case "$(host_kernel_name)" in
    Darwin|Linux)
      host_bundle_platform_label
      ;;
    *)
      printf 'linux\n'
      ;;
  esac
}

resolve_default_bundle_url() {
  local release_repo
  local release_tag
  local asset_name
  release_repo="$PUBLIC_RELEASE_REPO"
  release_tag="$PUBLIC_RELEASE_TAG"
  if installer_mode_is_skills_only; then
    asset_name="agentpay-sdk-$(resolve_skill_bundle_platform_label)-$(host_arch_label).tar.gz"
  else
    asset_name="$(resolve_runtime_bundle_asset_name)"
  fi
  printf 'https://github.com/%s/releases/download/%s/%s\n' "$release_repo" "$release_tag" "$asset_name"
}

bundle_has_skill_pack() {
  local bundle_dir="$1"
  [[ -f "$bundle_dir/skills/agentpay-sdk/SKILL.md" ]]
}

bundle_has_agent_template() {
  local bundle_dir="$1"
  local source_name="$2"
  [[ -f "$bundle_dir/skills/agentpay-sdk/agents/$source_name" ]]
}

bundle_manifest_string_field() {
  local bundle_dir="$1"
  local field_name="$2"
  local manifest_path="$bundle_dir/bundle-manifest.json"

  [[ -f "$manifest_path" ]] || return 1

  sed -n "s/.*\"$field_name\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$manifest_path" | head -n 1
}

runtime_bundle_manifest_matches_host() {
  local bundle_dir="$1"
  local manifest_platform=""
  local manifest_arch=""
  local expected_platform=""
  local expected_arch=""

  manifest_platform="$(bundle_manifest_string_field "$bundle_dir" "platform")"
  manifest_arch="$(bundle_manifest_string_field "$bundle_dir" "arch")"
  expected_platform="$(host_bundle_platform_label)"
  expected_arch="$(host_arch_label)"

  [[ "$manifest_platform" == "$expected_platform" ]] &&
    [[ "$manifest_arch" == "$expected_arch" ]]
}

runtime_bundle_looks_usable() {
  local bundle_dir="$1"

  [[ -f "$bundle_dir/bundle-manifest.json" ]] &&
    runtime_bundle_manifest_matches_host "$bundle_dir" &&
    [[ -f "$bundle_dir/app/package.json" ]] &&
    [[ -f "$bundle_dir/app/dist/cli.cjs" ]] &&
    [[ -d "$bundle_dir/app/node_modules" ]] &&
    [[ -x "$bundle_dir/runtime/bin/agentpay-daemon" ]] &&
    [[ -x "$bundle_dir/runtime/bin/agentpay-admin" ]] &&
    [[ -x "$bundle_dir/runtime/bin/agentpay-agent" ]] &&
    {
      ! runtime_bundle_requires_macos_helpers ||
        {
          [[ -x "$bundle_dir/runtime/bin/agentpay-system-keychain" ]] &&
            [[ -x "$bundle_dir/runtime/bin/run-agentpay-daemon.sh" ]] &&
            [[ -x "$bundle_dir/runtime/bin/install-user-daemon.sh" ]] &&
            [[ -x "$bundle_dir/runtime/bin/uninstall-user-daemon.sh" ]]
        }
    } &&
    {
      ! runtime_bundle_requires_linux_helpers ||
        {
          [[ -x "$bundle_dir/runtime/bin/run-agentpay-daemon.sh" ]] &&
            [[ -x "$bundle_dir/runtime/bin/agentpay-daemon-password-helper.sh" ]] &&
            [[ -x "$bundle_dir/runtime/bin/install-system-daemon.sh" ]] &&
            [[ -x "$bundle_dir/runtime/bin/uninstall-system-daemon.sh" ]]
        }
    } &&
    bundle_has_skill_pack "$bundle_dir"
}

skills_bundle_looks_usable() {
  local bundle_dir="$1"

  [[ -f "$bundle_dir/bundle-manifest.json" ]] &&
    bundle_has_skill_pack "$bundle_dir"
}

bundle_looks_usable() {
  local bundle_dir="$1"

  if installer_mode_is_skills_only; then
    skills_bundle_looks_usable "$bundle_dir"
    return $?
  fi

  runtime_bundle_looks_usable "$bundle_dir"
}

resolve_archive_root() {
  local extracted_dir="$1"
  local entry=""

  if bundle_looks_usable "$extracted_dir"; then
    printf '%s\n' "$extracted_dir"
    return 0
  fi

  for entry in "$extracted_dir"/*; do
    [[ -e "$entry" ]] || continue
    if bundle_looks_usable "$entry"; then
      printf '%s\n' "$entry"
      return 0
    fi
  done

  return 1
}

install_bundle_archive() {
  local bundle_url="$1"
  local temp_dir archive_path bundle_root
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agentpay-sdk-bundle.XXXXXX")"
  archive_path="$temp_dir/bundle.tar.gz"

  if ! run_with_retry "$RETRY_ATTEMPTS" "$RETRY_DELAY_SECONDS" curl -fsSL "$bundle_url" -o "$archive_path"; then
    rm -rf "$temp_dir"
    die "Could not download the AgentPay SDK bundle from $bundle_url. Check the URL or publish a reachable release artifact."
  fi

  tar -xf "$archive_path" -C "$temp_dir"
  bundle_root="$(resolve_archive_root "$temp_dir")" || {
    rm -rf "$temp_dir"
    if installer_mode_is_skills_only; then
      die "The archive at $bundle_url did not contain the AgentPay skill files required for --skills-only."
    fi
    die "The archive at $bundle_url did not contain a usable AgentPay SDK runtime bundle."
  }

  BUNDLE_TEMP_DIR="$temp_dir"
  BUNDLE_ROOT="$bundle_root"
}

choose_install_dir() {
  if [[ "$ASSUME_DEFAULTS" != "1" ]]; then
    say "Choose the local AgentPay install directory. Press Enter to keep the default."
  fi
  INSTALL_DIR="$(prompt_with_default "Install directory for AgentPay local files" "$INSTALL_DIR_DEFAULT")"
  INSTALL_DIR="${INSTALL_DIR/#\~/$HOME}"
  mkdir -p "$(dirname "$INSTALL_DIR")"
  INSTALL_DIR="$(cd "$(dirname "$INSTALL_DIR")" && pwd)/$(basename "$INSTALL_DIR")"
  mkdir -p "$INSTALL_DIR"
  RUNTIME_DIR="$INSTALL_DIR"
  say "Using install directory: $INSTALL_DIR"
}

escape_posix_shell_argument() {
  printf "'%s'" "${1//\'/\'\\\'\'}"
}

write_shell_exports() {
  local rc_file tmp_file
  rc_file="$(shell_rc_file)"
  SHELL_RC_PATH="$rc_file"
  tmp_file="$(mktemp)"
  mkdir -p "$(dirname "$rc_file")"
  touch "$rc_file"

  awk '
    BEGIN { skip = 0 }
    /^# >>> agentpay-sdk >>>$/ { skip = 1; next }
    /^# <<< agentpay-sdk <<<$/ { skip = 0; next }
    skip == 0 { print }
  ' "$rc_file" >"$tmp_file"

  cat >>"$tmp_file" <<EOF_EXPORTS
# >>> agentpay-sdk >>>
export AGENTPAY_HOME="$RUNTIME_DIR"
export PATH="\$AGENTPAY_HOME/bin:\$PATH"
# <<< agentpay-sdk <<<
EOF_EXPORTS

  mv "$tmp_file" "$rc_file"
  export AGENTPAY_HOME="$RUNTIME_DIR"
  export PATH="$RUNTIME_DIR/bin:$PATH"
}

shell_rc_file() {
  local shell_name
  shell_name="$(basename "${SHELL:-zsh}")"
  case "$shell_name" in
    bash)
      printf '%s\n' "$HOME/.bashrc"
      ;;
    zsh)
      printf '%s\n' "$HOME/.zshrc"
      ;;
    *)
      printf '%s\n' "$HOME/.zshrc"
      ;;
  esac
}

install_cli_launcher() {
  local node_path="$1"
  local launcher_path="$RUNTIME_DIR/bin/agentpay"
  local quoted_node_path
  quoted_node_path="$(escape_posix_shell_argument "$node_path")"

  cat >"$launcher_path" <<EOF_LAUNCHER
#!/bin/sh
set -eu

SCRIPT_DIR="\$(CDPATH= cd -- "\$(dirname "\$0")" && pwd)"
AGENTPAY_HOME_DEFAULT="\$(CDPATH= cd -- "\$SCRIPT_DIR/.." && pwd)"
CLI_ENTRYPOINT="\$SCRIPT_DIR/../app/dist/cli.cjs"

if [ ! -f "\$CLI_ENTRYPOINT" ]; then
  echo "agentpay runtime is incomplete: missing \$CLI_ENTRYPOINT" >&2
  exit 1
fi

export AGENTPAY_HOME="\$AGENTPAY_HOME_DEFAULT"

exec $quoted_node_path "\$CLI_ENTRYPOINT" "\$@"
EOF_LAUNCHER
  chmod 755 "$launcher_path"
}

path_shim_is_managed() {
  local shim_path="$1"

  [[ -f "$shim_path" ]] || return 1
  grep -Fq "$PATH_SHIM_MARKER" "$shim_path"
}

install_current_shell_path_shim() {
  local shim_path="$1"
  local quoted_runtime_launcher
  quoted_runtime_launcher="$(escape_posix_shell_argument "$RUNTIME_DIR/bin/agentpay")"

  cat >"$shim_path" <<EOF_PATH_SHIM
#!/bin/sh
$PATH_SHIM_MARKER
set -eu

exec $quoted_runtime_launcher "\$@"
EOF_PATH_SHIM
  chmod 755 "$shim_path"
  CURRENT_SHELL_SHIM_PATH="$shim_path"
  INSTALLED_PATH_SHIMS=("$shim_path")
  CURRENT_SHELL_SHIM_WARNING=""
}

maybe_install_current_shell_path_shim() {
  local path_entries=()
  local entry candidate_path

  CURRENT_SHELL_SHIM_PATH=""
  CURRENT_SHELL_SHIM_WARNING=""
  INSTALLED_PATH_SHIMS=()

  if [[ -z "$INHERITED_PATH" ]]; then
    CURRENT_SHELL_SHIM_WARNING="the inherited PATH was empty"
    return
  fi

  IFS=':' read -r -a path_entries <<<"$INHERITED_PATH"
  for entry in "${path_entries[@]}"; do
    [[ -n "$entry" ]] || continue
    entry="${entry/#\~/$HOME}"
    [[ "$entry" == "$RUNTIME_DIR/bin" ]] && continue
    candidate_path="$entry/agentpay"

    if [[ -e "$candidate_path" ]] || [[ -L "$candidate_path" ]]; then
      if path_shim_is_managed "$candidate_path"; then
        install_current_shell_path_shim "$candidate_path"
        return
      fi
      CURRENT_SHELL_SHIM_WARNING="the earlier PATH entry $candidate_path already exists and is not managed by this installer"
      return
    fi

    if [[ -d "$entry" ]] && [[ -w "$entry" ]]; then
      install_current_shell_path_shim "$candidate_path"
      return
    fi
  done

  CURRENT_SHELL_SHIM_WARNING="no writable existing directory in the inherited PATH could host a agentpay shim"
}

install_runtime_from_bundle() {
  local managed_entries=(
    "agentpay-daemon"
    "agentpay-admin"
    "agentpay-agent"
  )
  local macos_only_entries=(
    "agentpay-system-keychain"
    "run-agentpay-daemon.sh"
    "install-user-daemon.sh"
    "uninstall-user-daemon.sh"
  )
  local linux_only_entries=(
    "run-agentpay-daemon.sh"
    "agentpay-daemon-password-helper.sh"
    "install-system-daemon.sh"
    "uninstall-system-daemon.sh"
  )
  local entry=""

  if runtime_bundle_requires_macos_helpers; then
    managed_entries+=("${macos_only_entries[@]}")
  elif runtime_bundle_requires_linux_helpers; then
    managed_entries+=("${linux_only_entries[@]}")
  fi

  mkdir -p "$RUNTIME_DIR/bin"
  chmod 700 "$RUNTIME_DIR/bin"
  rm -rf "$RUNTIME_DIR/app"
  mkdir -p "$RUNTIME_DIR/app"
  cp -R "$BUNDLE_ROOT/app"/. "$RUNTIME_DIR/app"/

  for entry in "${macos_only_entries[@]}"; do
    rm -f "$RUNTIME_DIR/bin/$entry"
  done
  for entry in "${linux_only_entries[@]}"; do
    rm -f "$RUNTIME_DIR/bin/$entry"
  done
  for entry in "${managed_entries[@]}"; do
    rm -f "$RUNTIME_DIR/bin/$entry"
    cp "$BUNDLE_ROOT/runtime/bin/$entry" "$RUNTIME_DIR/bin/$entry"
    chmod 755 "$RUNTIME_DIR/bin/$entry"
  done

  install_cli_launcher "$NODE_PATH"
  maybe_install_current_shell_path_shim
  clear_macos_quarantine "$RUNTIME_DIR"

  [[ -x "$RUNTIME_DIR/bin/agentpay" ]] || die "Required AgentPay SDK runtime entry is missing after install: $RUNTIME_DIR/bin/agentpay"
  [[ -x "$RUNTIME_DIR/bin/agentpay-daemon" ]] || die "Required AgentPay SDK runtime entry is missing after install: $RUNTIME_DIR/bin/agentpay-daemon"
  [[ -x "$RUNTIME_DIR/bin/agentpay-admin" ]] || die "Required AgentPay SDK runtime entry is missing after install: $RUNTIME_DIR/bin/agentpay-admin"
  [[ -x "$RUNTIME_DIR/bin/agentpay-agent" ]] || die "Required AgentPay SDK runtime entry is missing after install: $RUNTIME_DIR/bin/agentpay-agent"
  if runtime_bundle_requires_macos_helpers; then
    [[ -x "$RUNTIME_DIR/bin/agentpay-system-keychain" ]] || die "Required AgentPay SDK runtime entry is missing after install: $RUNTIME_DIR/bin/agentpay-system-keychain"
  elif runtime_bundle_requires_linux_helpers; then
    [[ -x "$RUNTIME_DIR/bin/agentpay-daemon-password-helper.sh" ]] || die "Required AgentPay SDK runtime entry is missing after install: $RUNTIME_DIR/bin/agentpay-daemon-password-helper.sh"
  fi
}

install_skill_pack() {
  local destination="$1"
  mkdir -p "$(dirname "$destination")"
  rm -rf "$destination"
  cp -R "$BUNDLE_ROOT/skills/agentpay-sdk" "$destination"
  clear_macos_quarantine "$destination"
  INSTALLED_SKILL_TARGETS+=("$destination")
}

install_adapter_file() {
  local source_name="$1"
  local destination="$2"

  if ! bundle_has_agent_template "$BUNDLE_ROOT" "$source_name"; then
    warn "Skipping $destination because this bundle does not include the $source_name template."
    return 1
  fi

  mkdir -p "$(dirname "$destination")"
  cp "$BUNDLE_ROOT/skills/agentpay-sdk/agents/$source_name" "$destination"
  clear_macos_quarantine "$destination"
  INSTALLED_CURSOR_ARTIFACTS+=("$destination")
}

install_cursor_adapter() {
  local workspace="$1"
  local cursor_rule_path="$workspace/.cursor/rules/agentpay-sdk.mdc"
  local agents_path="$workspace/AGENTS.md"
  local installed_any=0
  if install_adapter_file "cursor-agentpay-sdk.mdc" "$cursor_rule_path"; then
    installed_any=1
  fi

  if [[ ! -e "$agents_path" ]] && install_adapter_file "AGENTS.md" "$agents_path"; then
    installed_any=1
  fi

  (( installed_any == 1 ))
}

write_install_manifest() {
  local manifest_path="$RUNTIME_DIR/one-click-install-manifest.json"
  local skill_targets cursor_artifacts path_shims

  skill_targets="$(printf '%s\n' "${INSTALLED_SKILL_TARGETS[@]-}")"
  cursor_artifacts="$(printf '%s\n' "${INSTALLED_CURSOR_ARTIFACTS[@]-}")"
  path_shims="$(printf '%s\n' "${INSTALLED_PATH_SHIMS[@]-}")"

  AGENTPAY_INSTALLER_MANIFEST_PATH="$manifest_path" \
  AGENTPAY_INSTALLER_INSTALL_ROOT="$INSTALL_DIR" \
  AGENTPAY_INSTALLER_RUNTIME_DIR="$RUNTIME_DIR" \
  AGENTPAY_INSTALLER_SHELL_RC_PATH="$SHELL_RC_PATH" \
  AGENTPAY_INSTALLER_SKILL_TARGETS="$skill_targets" \
  AGENTPAY_INSTALLER_CURSOR_ARTIFACTS="$cursor_artifacts" \
  AGENTPAY_INSTALLER_PATH_SHIMS="$path_shims" \
  node <<'EOF_MANIFEST'
const fs = require('fs');

function splitEnvList(value) {
  return value
    .split('\n')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

const manifest = {
  version: 1,
  installRoot: process.env.AGENTPAY_INSTALLER_INSTALL_ROOT || null,
  agentpayHome: process.env.AGENTPAY_INSTALLER_RUNTIME_DIR || null,
  shellRcPath: process.env.AGENTPAY_INSTALLER_SHELL_RC_PATH || null,
  skillTargets: splitEnvList(process.env.AGENTPAY_INSTALLER_SKILL_TARGETS || ''),
  cursorArtifactPaths: splitEnvList(process.env.AGENTPAY_INSTALLER_CURSOR_ARTIFACTS || ''),
  pathShimPaths: splitEnvList(process.env.AGENTPAY_INSTALLER_PATH_SHIMS || ''),
};

fs.writeFileSync(
  process.env.AGENTPAY_INSTALLER_MANIFEST_PATH,
  `${JSON.stringify(manifest, null, 2)}\n`,
  { mode: 0o600 },
);
EOF_MANIFEST
}

resolve_input_path() {
  local value="$1"
  value="${value/#\~/$HOME}"
  if [[ "$value" != /* ]]; then
    value="$PWD/$value"
  fi
  printf '%s\n' "$value"
}

workspace_looks_relevant() {
  local workspace="$1"

  [[ -d "$workspace/.git" ]] ||
    [[ -d "$workspace/.cursor" ]] ||
    [[ -d "$workspace/.claude" ]] ||
    [[ -d "$workspace/.agents" ]] ||
    [[ -d "$workspace/.cline" ]] ||
    [[ -d "$workspace/.goose" ]] ||
    [[ -d "$workspace/.windsurf" ]] ||
    [[ -d "$workspace/.github" ]] ||
    [[ -f "$workspace/AGENTS.md" ]] ||
    [[ -f "$workspace/CLAUDE.md" ]] ||
    [[ -f "$workspace/GEMINI.md" ]]
}

resolve_general_workspace() {
  local workspace="${WORKSPACE_DEFAULT:-}"

  if [[ -n "$workspace" ]]; then
    printf '%s\n' "$(resolve_input_path "$workspace")"
    return
  fi

  if workspace_looks_relevant "$PWD"; then
    printf '%s\n' "$PWD"
    return
  fi

  printf '\n'
}

resolve_cursor_workspace() {
  local default_workspace="${CURSOR_WORKSPACE_DEFAULT:-}"
  local general_workspace=""

  if [[ -n "$default_workspace" ]]; then
    printf '%s\n' "$(resolve_input_path "$default_workspace")"
    return
  fi

  general_workspace="$(resolve_general_workspace)"
  if [[ -n "$general_workspace" ]] && [[ -d "$general_workspace/.cursor" ]]; then
    printf '%s\n' "$general_workspace"
    return
  fi

  printf '\n'
}

reset_skill_target_catalog() {
  SKILL_TARGET_IDS=()
  SKILL_TARGET_LABELS=()
  SKILL_TARGET_TYPES=()
  SKILL_TARGET_DESTINATIONS=()
  SKILL_TARGET_SOURCES=()
  SKILL_TARGET_DETECTED=()
  SKILL_TARGET_SELECTED=()
  SKILL_TARGET_RECOMMENDED=()
  SKILL_TARGET_NOTES=()
  SKILL_TARGET_MENU_STATUS=""
}

register_skill_target() {
  local id="$1"
  local label="$2"
  local type="$3"
  local destination="$4"
  local source="$5"
  local detected="$6"
  local recommended="$7"
  local note="${8:-$destination}"

  SKILL_TARGET_IDS+=("$id")
  SKILL_TARGET_LABELS+=("$label")
  SKILL_TARGET_TYPES+=("$type")
  SKILL_TARGET_DESTINATIONS+=("$destination")
  SKILL_TARGET_SOURCES+=("$source")
  SKILL_TARGET_DETECTED+=("$detected")
  SKILL_TARGET_SELECTED+=("0")
  SKILL_TARGET_RECOMMENDED+=("$recommended")
  SKILL_TARGET_NOTES+=("$note")
}

count_skill_targets_with_flag() {
  local flag_name="$1"
  local count=0
  local index=0
  local value=""

  case "$flag_name" in
    detected)
      for ((index = 0; index < ${#SKILL_TARGET_DETECTED[@]}; index += 1)); do
        value="${SKILL_TARGET_DETECTED[$index]}"
        if [[ "$value" == "1" ]]; then
          count=$((count + 1))
        fi
      done
      ;;
    selected)
      for ((index = 0; index < ${#SKILL_TARGET_SELECTED[@]}; index += 1)); do
        value="${SKILL_TARGET_SELECTED[$index]}"
        if [[ "$value" == "1" ]]; then
          count=$((count + 1))
        fi
      done
      ;;
    recommended)
      for ((index = 0; index < ${#SKILL_TARGET_RECOMMENDED[@]}; index += 1)); do
        value="${SKILL_TARGET_RECOMMENDED[$index]}"
        if [[ "$value" == "1" ]]; then
          count=$((count + 1))
        fi
      done
      ;;
    *)
      die "Unknown skill target flag: $flag_name"
      ;;
  esac

  printf '%s\n' "$count"
}

set_skill_target_selection() {
  local index="$1"
  local selected="$2"
  SKILL_TARGET_SELECTED[$index]="$selected"
}

select_all_skill_targets() {
  local index=0
  for ((index = 0; index < ${#SKILL_TARGET_SELECTED[@]}; index += 1)); do
    set_skill_target_selection "$index" "1"
  done
}

apply_default_skill_target_selection() {
  local detected_count=0
  local index=0

  if [[ "$INSTALL_SKILLS_MODE" == "yes" ]]; then
    select_all_skill_targets
    return
  fi

  detected_count="$(count_skill_targets_with_flag detected)"
  if (( detected_count > 0 )); then
    for ((index = 0; index < ${#SKILL_TARGET_SELECTED[@]}; index += 1)); do
      set_skill_target_selection "$index" "${SKILL_TARGET_DETECTED[$index]}"
    done
    return
  fi

  for ((index = 0; index < ${#SKILL_TARGET_SELECTED[@]}; index += 1)); do
    set_skill_target_selection "$index" "${SKILL_TARGET_RECOMMENDED[$index]}"
  done
}

find_skill_target_index() {
  local type="$1"
  local destination="$2"
  local index=0

  for ((index = 0; index < ${#SKILL_TARGET_IDS[@]}; index += 1)); do
    if [[ "${SKILL_TARGET_TYPES[$index]}" == "$type" ]] && [[ "${SKILL_TARGET_DESTINATIONS[$index]}" == "$destination" ]]; then
      printf '%s\n' "$index"
      return 0
    fi
  done

  return 1
}

register_custom_skill_target() {
  local label="$1"
  local type="$2"
  local destination="$3"
  local source="$4"
  local note="${5:-$destination}"
  local existing_index=""
  local custom_index=$(( ${#SKILL_TARGET_IDS[@]} + 1 ))

  if existing_index="$(find_skill_target_index "$type" "$destination")"; then
    set_skill_target_selection "$existing_index" "1"
    say "Custom target already exists in the selection list: ${SKILL_TARGET_LABELS[$existing_index]}"
    return
  fi

  register_skill_target "custom-$custom_index" "$label" "$type" "$destination" "$source" "0" "0" "$note"
  set_skill_target_selection "$((${#SKILL_TARGET_IDS[@]} - 1))" "1"
}

build_skill_target_catalog() {
  local workspace=""
  local cursor_workspace=""

  reset_skill_target_catalog
  workspace="$(resolve_general_workspace)"
  cursor_workspace="$(resolve_cursor_workspace)"

  register_skill_target \
    "codex-global" \
    "Codex global skill pack" \
    "skill_pack" \
    "$HOME/.codex/skills/agentpay-sdk" \
    "" \
    "$(if [[ -d "$HOME/.codex" ]] || [[ -d "$HOME/.codex/skills" ]] || [[ -d "$HOME/.codex/skills/agentpay-sdk" ]] || command_exists codex; then printf '1'; else printf '0'; fi)" \
    "1"

  register_skill_target \
    "agents-portable-global" \
    "Portable global agents skill pack" \
    "skill_pack" \
    "$HOME/.config/agents/skills/agentpay-sdk" \
    "" \
    "$(if [[ -d "$HOME/.config/agents" ]] || [[ -d "$HOME/.config/agents/skills" ]] || [[ -d "$HOME/.config/agents/skills/agentpay-sdk" ]]; then printf '1'; else printf '0'; fi)" \
    "1"

  register_skill_target \
    "agents-legacy-global" \
    "Legacy ~/.agents skill pack" \
    "skill_pack" \
    "$HOME/.agents/skills/agentpay-sdk" \
    "" \
    "$(if [[ -d "$HOME/.agents" ]] || [[ -d "$HOME/.agents/skills" ]] || [[ -d "$HOME/.agents/skills/agentpay-sdk" ]]; then printf '1'; else printf '0'; fi)" \
    "1"

  register_skill_target \
    "claude-global" \
    "Claude global skill pack" \
    "skill_pack" \
    "$HOME/.claude/skills/agentpay-sdk" \
    "" \
    "$(if [[ -d "$HOME/.claude" ]] || [[ -d "$HOME/.claude/skills" ]] || [[ -d "$HOME/.claude/skills/agentpay-sdk" ]] || command_exists claude; then printf '1'; else printf '0'; fi)" \
    "1"

  register_skill_target \
    "cline-global" \
    "Cline global skill pack" \
    "skill_pack" \
    "$HOME/.cline/skills/agentpay-sdk" \
    "" \
    "$(if [[ -d "$HOME/.cline" ]] || [[ -d "$HOME/.cline/skills" ]] || [[ -d "$HOME/.cline/skills/agentpay-sdk" ]] || [[ -d "$HOME/Documents/Cline" ]]; then printf '1'; else printf '0'; fi)" \
    "1"

  register_skill_target \
    "goose-global" \
    "Goose global skill pack" \
    "skill_pack" \
    "$HOME/.config/goose/skills/agentpay-sdk" \
    "" \
    "$(if [[ -d "$HOME/.config/goose" ]] || [[ -d "$HOME/.config/goose/skills" ]] || [[ -d "$HOME/.config/goose/skills/agentpay-sdk" ]] || command_exists goose; then printf '1'; else printf '0'; fi)" \
    "1"

  register_skill_target \
    "windsurf-global" \
    "Windsurf global skill pack" \
    "skill_pack" \
    "$HOME/.codeium/windsurf/skills/agentpay-sdk" \
    "" \
    "$(if [[ -d "$HOME/.codeium/windsurf" ]] || [[ -d "$HOME/.codeium/windsurf/skills" ]] || [[ -d "$HOME/.codeium/windsurf/skills/agentpay-sdk" ]]; then printf '1'; else printf '0'; fi)" \
    "1"

  register_skill_target \
    "openclaw-global" \
    "OpenClaw global skill pack" \
    "skill_pack" \
    "$HOME/.openclaw/skills/agentpay-sdk" \
    "" \
    "$(if [[ -d "$HOME/.openclaw" ]] || [[ -d "$HOME/.openclaw/skills" ]] || [[ -d "$HOME/.openclaw/skills/agentpay-sdk" ]]; then printf '1'; else printf '0'; fi)" \
    "1"

  if [[ -n "$workspace" ]]; then
    register_skill_target \
      "agents-project" \
      "Workspace .agents skill pack" \
      "skill_pack" \
      "$workspace/.agents/skills/agentpay-sdk" \
      "" \
      "$(if [[ -d "$workspace/.agents" ]] || [[ -d "$workspace/.agents/skills" ]] || [[ -d "$workspace/.agents/skills/agentpay-sdk" ]]; then printf '1'; else printf '0'; fi)" \
      "0"

    register_skill_target \
      "claude-project" \
      "Workspace .claude skill pack" \
      "skill_pack" \
      "$workspace/.claude/skills/agentpay-sdk" \
      "" \
      "$(if [[ -d "$workspace/.claude" ]] || [[ -d "$workspace/.claude/skills" ]] || [[ -d "$workspace/.claude/skills/agentpay-sdk" ]]; then printf '1'; else printf '0'; fi)" \
      "0"

    register_skill_target \
      "cline-project" \
      "Workspace .cline skill pack" \
      "skill_pack" \
      "$workspace/.cline/skills/agentpay-sdk" \
      "" \
      "$(if [[ -d "$workspace/.cline" ]] || [[ -d "$workspace/.cline/skills" ]] || [[ -d "$workspace/.cline/skills/agentpay-sdk" ]]; then printf '1'; else printf '0'; fi)" \
      "0"

    register_skill_target \
      "goose-project" \
      "Workspace .goose skill pack" \
      "skill_pack" \
      "$workspace/.goose/skills/agentpay-sdk" \
      "" \
      "$(if [[ -d "$workspace/.goose" ]] || [[ -d "$workspace/.goose/skills" ]] || [[ -d "$workspace/.goose/skills/agentpay-sdk" ]]; then printf '1'; else printf '0'; fi)" \
      "0"

    register_skill_target \
      "windsurf-project" \
      "Workspace .windsurf skill pack" \
      "skill_pack" \
      "$workspace/.windsurf/skills/agentpay-sdk" \
      "" \
      "$(if [[ -d "$workspace/.windsurf" ]] || [[ -d "$workspace/.windsurf/skills" ]] || [[ -d "$workspace/.windsurf/skills/agentpay-sdk" ]]; then printf '1'; else printf '0'; fi)" \
      "0"

    if bundle_has_agent_template "$BUNDLE_ROOT" "AGENTS.md"; then
      register_skill_target \
        "agents-root" \
        "Workspace AGENTS.md adapter" \
        "file" \
        "$workspace/AGENTS.md" \
        "AGENTS.md" \
        "$(if [[ -f "$workspace/AGENTS.md" ]]; then printf '1'; else printf '0'; fi)" \
        "0"
    fi

    if bundle_has_agent_template "$BUNDLE_ROOT" "CLAUDE.md"; then
      register_skill_target \
        "claude-root" \
        "Workspace CLAUDE.md adapter" \
        "file" \
        "$workspace/CLAUDE.md" \
        "CLAUDE.md" \
        "$(if [[ -f "$workspace/CLAUDE.md" ]] || [[ -d "$workspace/.claude" ]]; then printf '1'; else printf '0'; fi)" \
        "0"
    fi

    if bundle_has_agent_template "$BUNDLE_ROOT" "GEMINI.md"; then
      register_skill_target \
        "gemini-root" \
        "Workspace GEMINI.md adapter" \
        "file" \
        "$workspace/GEMINI.md" \
        "GEMINI.md" \
        "$(if [[ -f "$workspace/GEMINI.md" ]]; then printf '1'; else printf '0'; fi)" \
        "0"
    fi

    if bundle_has_agent_template "$BUNDLE_ROOT" "copilot-instructions.md"; then
      register_skill_target \
        "copilot-root" \
        "Workspace Copilot instructions" \
        "file" \
        "$workspace/.github/copilot-instructions.md" \
        "copilot-instructions.md" \
        "$(if [[ -f "$workspace/.github/copilot-instructions.md" ]] || [[ -d "$workspace/.github" ]]; then printf '1'; else printf '0'; fi)" \
        "0"
    fi

    if bundle_has_agent_template "$BUNDLE_ROOT" "cline-agentpay-sdk.md"; then
      register_skill_target \
        "cline-rule" \
        "Workspace Cline rules file" \
        "file" \
        "$workspace/.clinerules/agentpay-sdk.md" \
        "cline-agentpay-sdk.md" \
        "$(if [[ -f "$workspace/.clinerules/agentpay-sdk.md" ]] || [[ -d "$workspace/.clinerules" ]]; then printf '1'; else printf '0'; fi)" \
        "0"
    fi
  fi

  if [[ -n "$cursor_workspace" ]] && bundle_has_agent_template "$BUNDLE_ROOT" "cursor-agentpay-sdk.mdc"; then
    register_skill_target \
      "cursor-workspace" \
      "Cursor workspace adapter" \
      "cursor_workspace" \
      "$cursor_workspace" \
      "" \
      "$(if [[ -d "$cursor_workspace/.cursor" ]] || [[ -f "$cursor_workspace/.cursor/rules/agentpay-sdk.mdc" ]] || [[ -n "${CURSOR_WORKSPACE_DEFAULT:-}" ]]; then printf '1'; else printf '0'; fi)" \
      "0" \
      "$cursor_workspace/.cursor/rules/agentpay-sdk.mdc + AGENTS.md"
  fi
}

print_skill_target_menu() {
  local index=0
  local selected_marker=""
  local line=""

  {
    printf '\nAgentPay skill targets\n\n'
    for ((index = 0; index < ${#SKILL_TARGET_IDS[@]}; index += 1)); do
      if [[ "${SKILL_TARGET_SELECTED[$index]}" == "1" ]]; then
        selected_marker="x"
      else
        selected_marker=" "
      fi

      line="${SKILL_TARGET_LABELS[$index]} - $(compact_display_path "${SKILL_TARGET_NOTES[$index]}")"
      printf '  %2d. [%s] %s\n' "$((index + 1))" "$selected_marker" "$line"
    done
    printf '\nEnter numbers to toggle, `c` to add custom, Enter to install, or `s` to skip.\n'
  } >&$PROMPT_OUT_FD
}

first_selected_skill_target_index() {
  local index=0

  for ((index = 0; index < ${#SKILL_TARGET_SELECTED[@]}; index += 1)); do
    if [[ "${SKILL_TARGET_SELECTED[$index]}" == "1" ]]; then
      printf '%s\n' "$index"
      return 0
    fi
  done

  printf '0\n'
}

render_skill_target_picker() {
  local current_index="$1"
  local remaining="$2"
  local index=0
  local selected_marker=""
  local pointer=" "
  local line=""
  local selected_count=0
  local printed_selected=0

  selected_count="$(count_skill_targets_with_flag selected)"

  {
    printf '\033[H\033[2J'
    printf 'Choose skill targets\n'
    printf 'Up/Down move  Space select  c custom  Enter install'
    if (( remaining > 0 )); then
      printf '  auto in %ss' "$remaining"
    fi
    printf '\n\n'

    for ((index = 0; index < ${#SKILL_TARGET_IDS[@]}; index += 1)); do
      if [[ "${SKILL_TARGET_SELECTED[$index]}" == "1" ]]; then
        selected_marker="x"
      else
        selected_marker=" "
      fi

      if (( index == current_index )); then
        pointer=">"
      else
        pointer=" "
      fi

      line="$pointer [$selected_marker] ${SKILL_TARGET_LABELS[$index]} - $(compact_display_path "${SKILL_TARGET_NOTES[$index]}")"
      if (( index == current_index )); then
        printf '\033[7m%s\033[0m\n' "$line"
      else
        printf '%s\n' "$line"
      fi
    done

    printf '\nSelected (%s)\n' "$selected_count"
    if (( selected_count == 0 )); then
      printf '  none\n'
    else
      for ((index = 0; index < ${#SKILL_TARGET_IDS[@]}; index += 1)); do
        if [[ "${SKILL_TARGET_SELECTED[$index]}" != "1" ]]; then
          continue
        fi
        printf '  %s\n' "${SKILL_TARGET_LABELS[$index]}"
        printed_selected=$((printed_selected + 1))
        if (( printed_selected >= 6 && selected_count > printed_selected )); then
          printf '  + %s more\n' "$((selected_count - printed_selected))"
          break
        fi
      done
    fi

    if [[ -n "$SKILL_TARGET_MENU_STATUS" ]]; then
      printf '\n%s\n' "$SKILL_TARGET_MENU_STATUS"
    fi
  } >&$PROMPT_OUT_FD
}

read_skill_target_picker_key() {
  local key=""
  local next=""

  if ! IFS= read -r -u "$PROMPT_IN_FD" -s -n 1 -t 1 key; then
    return 1
  fi

  if [[ "$key" == $'\033' ]]; then
    if IFS= read -r -u "$PROMPT_IN_FD" -s -n 1 -t "$KEY_SEQUENCE_TIMEOUT_SECONDS" next; then
      key+="$next"
      if [[ "$next" == "[" ]] && IFS= read -r -u "$PROMPT_IN_FD" -s -n 1 -t "$KEY_SEQUENCE_TIMEOUT_SECONDS" next; then
        key+="$next"
      fi
    fi
  fi

  printf '%s' "$key"
}

prompt_skill_target_selection_picker() {
  local current_index=0
  local key=""
  local deadline=0
  local now=0
  local remaining=0

  if (( ${#SKILL_TARGET_IDS[@]} == 0 )); then
    return 0
  fi

  current_index="$(first_selected_skill_target_index)"
  if can_auto_continue_prompt; then
    deadline=$(( $(date +%s) + AUTO_CONTINUE_SECONDS ))
  fi

  while true; do
    remaining=0
    if (( deadline > 0 )); then
      now="$(date +%s)"
      remaining=$((deadline - now))
      if (( remaining <= 0 )); then
        SKILL_TARGET_MENU_STATUS="Installing the current selection."
        render_skill_target_picker "$current_index" 0
        printf '\n' >&$PROMPT_OUT_FD
        return 0
      fi
    fi

    render_skill_target_picker "$current_index" "$remaining"
    if ! key="$(read_skill_target_picker_key)"; then
      continue
    fi

    if (( deadline > 0 )); then
      deadline=$(( $(date +%s) + AUTO_CONTINUE_SECONDS ))
    fi

    case "$key" in
      $'\033[A')
        if (( current_index > 0 )); then
          current_index=$((current_index - 1))
        else
          current_index=$((${#SKILL_TARGET_IDS[@]} - 1))
        fi
        SKILL_TARGET_MENU_STATUS=""
        ;;
      $'\033[B')
        if (( current_index + 1 < ${#SKILL_TARGET_IDS[@]} )); then
          current_index=$((current_index + 1))
        else
          current_index=0
        fi
        SKILL_TARGET_MENU_STATUS=""
        ;;
      " ")
        if [[ "${SKILL_TARGET_SELECTED[$current_index]}" == "1" ]]; then
          set_skill_target_selection "$current_index" "0"
          SKILL_TARGET_MENU_STATUS="Removed ${SKILL_TARGET_LABELS[$current_index]}"
        else
          set_skill_target_selection "$current_index" "1"
          SKILL_TARGET_MENU_STATUS="Selected ${SKILL_TARGET_LABELS[$current_index]}"
        fi
        ;;
      ""|$'\n'|$'\r')
        printf '\n' >&$PROMPT_OUT_FD
        return 0
        ;;
      c|C|a|A)
        printf '\n' >&$PROMPT_OUT_FD
        prompt_custom_skill_target
        current_index=$((${#SKILL_TARGET_IDS[@]} - 1))
        SKILL_TARGET_MENU_STATUS="Custom destination added."
        ;;
      s|S)
        for ((current_index = 0; current_index < ${#SKILL_TARGET_SELECTED[@]}; current_index += 1)); do
          set_skill_target_selection "$current_index" "0"
        done
        printf '\n' >&$PROMPT_OUT_FD
        return 0
        ;;
      *)
        SKILL_TARGET_MENU_STATUS="Use Up/Down, Space, c, Enter, or s."
        ;;
    esac
  done
}

prompt_custom_skill_target() {
  local workspace=""
  local reply=""
  local destination=""
  local label=""
  local type=""
  local source=""
  local default_destination=""

  workspace="$(resolve_general_workspace)"

  {
    printf '\nCustom destination types\n'
    printf '  1. Skill pack directory\n'
    printf '  2. AGENTS.md adapter file\n'
    printf '  3. CLAUDE.md adapter file\n'
    printf '  4. GEMINI.md adapter file\n'
    printf '  5. Copilot instructions file\n'
    printf '  6. Cursor workspace adapter\n'
    printf '  7. Cline rules file\n\n'
  } >&$PROMPT_OUT_FD

  reply="$(trim_ascii_whitespace "$(read_prompt "Choose a custom target type ")")"
  case "$reply" in
    1)
      label="Custom skill pack"
      type="skill_pack"
      default_destination="$HOME/.local/share/agentpay-sdk/skills/agentpay-sdk"
      ;;
    2)
      label="Custom AGENTS.md adapter"
      type="file"
      source="AGENTS.md"
      default_destination="${workspace:-$PWD}/AGENTS.md"
      ;;
    3)
      label="Custom CLAUDE.md adapter"
      type="file"
      source="CLAUDE.md"
      default_destination="${workspace:-$PWD}/CLAUDE.md"
      ;;
    4)
      label="Custom GEMINI.md adapter"
      type="file"
      source="GEMINI.md"
      default_destination="${workspace:-$PWD}/GEMINI.md"
      ;;
    5)
      label="Custom Copilot instructions"
      type="file"
      source="copilot-instructions.md"
      default_destination="${workspace:-$PWD}/.github/copilot-instructions.md"
      ;;
    6)
      label="Custom Cursor workspace adapter"
      type="cursor_workspace"
      default_destination="${CURSOR_WORKSPACE_DEFAULT:-${workspace:-$PWD}}"
      ;;
    7)
      label="Custom Cline rules file"
      type="file"
      source="cline-agentpay-sdk.md"
      default_destination="${workspace:-$PWD}/.clinerules/agentpay-sdk.md"
      ;;
    *)
      warn "Unknown custom target type: ${reply:-empty}"
      return
      ;;
  esac

  destination="$(prompt_with_default "Destination path" "$default_destination")"
  destination="$(resolve_input_path "$destination")"

  if [[ "$type" == "cursor_workspace" ]]; then
    if ! bundle_has_agent_template "$BUNDLE_ROOT" "cursor-agentpay-sdk.mdc"; then
      warn "This bundle does not include the Cursor workspace adapter template."
      return
    fi
    register_custom_skill_target "$label" "$type" "$destination" "" "$destination/.cursor/rules/agentpay-sdk.mdc + AGENTS.md"
    return
  fi

  if ! bundle_has_agent_template "$BUNDLE_ROOT" "$source"; then
    warn "This bundle does not include the $source template."
    return
  fi

  register_custom_skill_target "$label" "$type" "$destination" "$source" "$destination"
}

prompt_skill_target_selection() {
  local reply=""
  local tokens=()
  local token=""
  local index=0

  if [[ "$ASSUME_DEFAULTS" == "1" ]] || [[ "$INSTALL_SKILLS_MODE" != "auto" ]]; then
    return 0
  fi

  if (( HAS_LOCAL_TTY == 1 )) && [[ "$PROMPT_IN" == "/dev/tty" ]] && [[ "$PROMPT_OUT" == "/dev/tty" ]]; then
    prompt_skill_target_selection_picker
    return 0
  fi

  if (( HAS_LOCAL_TTY == 0 )) && [[ "${AGENTPAY_SETUP_USE_STDIN:-}" != "1" ]]; then
    return 0
  fi

  while true; do
    print_skill_target_menu
    reply="$(trim_ascii_whitespace "$(read_prompt_with_default_reply "Selection" "__install__" "Installing the preselected targets.")")"

    case "${reply:-i}" in
      __install__|i|I|install|INSTALL)
        return 0
        ;;
      "")
        printf 'Installing the preselected targets.\n' >&$PROMPT_OUT_FD
        return 0
        ;;
      s|S|skip|SKIP)
        for ((index = 0; index < ${#SKILL_TARGET_SELECTED[@]}; index += 1)); do
          set_skill_target_selection "$index" "0"
        done
        return 0
        ;;
      a|A|add|ADD)
        prompt_custom_skill_target
        ;;
      *)
        reply="${reply//,/ }"
        IFS=' ' read -r -a tokens <<<"$reply"
        for token in "${tokens[@]}"; do
          [[ -n "$token" ]] || continue
          if [[ ! "$token" =~ ^[0-9]+$ ]]; then
            warn "Unknown selection token: $token"
            continue
          fi

          index=$((token - 1))
          if (( index < 0 || index >= ${#SKILL_TARGET_IDS[@]} )); then
            warn "Selection out of range: $token"
            continue
          fi

          if [[ "${SKILL_TARGET_SELECTED[$index]}" == "1" ]]; then
            set_skill_target_selection "$index" "0"
          else
            set_skill_target_selection "$index" "1"
          fi
        done
        ;;
    esac
  done
}

install_selected_skill_targets() {
  local index=0
  local label=""
  local type=""
  local destination=""
  local source=""

  for ((index = 0; index < ${#SKILL_TARGET_IDS[@]}; index += 1)); do
    if [[ "${SKILL_TARGET_SELECTED[$index]}" != "1" ]]; then
      continue
    fi

    label="${SKILL_TARGET_LABELS[$index]}"
    type="${SKILL_TARGET_TYPES[$index]}"
    destination="${SKILL_TARGET_DESTINATIONS[$index]}"
    source="${SKILL_TARGET_SOURCES[$index]}"

    case "$type" in
      skill_pack)
        say "Installing $label"
        install_skill_pack "$destination"
        ;;
      file)
        say "Installing $label"
        install_adapter_file "$source" "$destination"
        ;;
      cursor_workspace)
        say "Installing $label"
        mkdir -p "$destination"
        install_cursor_adapter "$destination"
        ;;
      *)
        die "Unknown skill target type: $type"
        ;;
    esac
  done
}

maybe_install_skill_targets() {
  local selected_count=0

  if [[ "${AGENTPAY_SETUP_SKIP_SKILLS:-}" == "1" ]]; then
    say "Skipping optional skill installation because AGENTPAY_SETUP_SKIP_SKILLS=1."
    return
  fi

  if [[ "$INSTALL_SKILLS_MODE" == "no" ]]; then
    say "Skipping optional skill installation because AGENTPAY_SETUP_INSTALL_SKILLS=no."
    return
  fi

  maybe_warn_about_missing_adapter_templates
  build_skill_target_catalog
  apply_default_skill_target_selection
  prompt_skill_target_selection

  selected_count="$(count_skill_targets_with_flag selected)"
  if (( selected_count == 0 )); then
    say "Skipping AI integration install because no targets are selected."
    return
  fi

  install_selected_skill_targets
}

maybe_warn_about_missing_adapter_templates() {
  local missing=()
  local missing_text=""

  bundle_has_agent_template "$BUNDLE_ROOT" "AGENTS.md" || missing+=("AGENTS.md")
  bundle_has_agent_template "$BUNDLE_ROOT" "CLAUDE.md" || missing+=("CLAUDE.md")
  bundle_has_agent_template "$BUNDLE_ROOT" "GEMINI.md" || missing+=("GEMINI.md")
  bundle_has_agent_template "$BUNDLE_ROOT" "copilot-instructions.md" || missing+=("copilot-instructions.md")
  bundle_has_agent_template "$BUNDLE_ROOT" "cline-agentpay-sdk.md" || missing+=("cline-agentpay-sdk.md")
  bundle_has_agent_template "$BUNDLE_ROOT" "cursor-agentpay-sdk.mdc" || missing+=("cursor-agentpay-sdk.mdc")

  if (( ${#missing[@]} == 0 )); then
    return
  fi

  missing_text="$(printf '%s, ' "${missing[@]}")"
  missing_text="${missing_text%, }"
  warn "This bundle is missing some optional adapters. Skipping: $missing_text"
}

maybe_run_admin_setup() {
  local run_setup
  run_setup="$(resolve_run_admin_setup_default)"

  if [[ "$run_setup" == "no" ]]; then
    say "Skipping wallet setup during one-click install. Run agentpay admin setup when you are ready to create or attach a wallet."
    return
  fi

  if ! host_supports_packaged_admin_setup; then
    die "AGENTPAY_SETUP_RUN_ADMIN_SETUP=yes is not supported on this platform yet. Managed daemon setup currently supports macOS and Linux only."
  fi

  if (( HAS_LOCAL_TTY == 0 )); then
    die "agentpay admin setup requires a local TTY for secure password prompts. Rerun this installer from a local terminal, or set AGENTPAY_SETUP_RUN_ADMIN_SETUP=no and run agentpay admin setup later."
  fi

  say "Starting agentpay admin setup now."
  agentpay admin setup </dev/tty >/dev/tty 2>/dev/tty
}

print_summary() {
  if ! host_supports_packaged_admin_setup; then
    if [[ -n "$CURRENT_SHELL_SHIM_PATH" ]]; then
      cat <<EOF_SUMMARY

AgentPay SDK install complete.

Install root:
  $INSTALL_DIR

AgentPay SDK runtime:
  $RUNTIME_DIR

Run now in this shell:
  agentpay --help

Current-shell shim:
  $CURRENT_SHELL_SHIM_PATH

Managed wallet setup is supported on macOS and Linux.
Run agentpay admin setup when you are ready to create or attach a wallet.
EOF_SUMMARY
      return
    fi

    cat <<EOF_SUMMARY

AgentPay SDK install complete.

Install root:
  $INSTALL_DIR

AgentPay SDK runtime:
  $RUNTIME_DIR

Your current shell still needs the updated PATH:
  source "$SHELL_RC_PATH"

Current-shell shim was skipped:
  ${CURRENT_SHELL_SHIM_WARNING:-unable to place agentpay into an existing PATH entry}

Or run AgentPay directly right now without reloading the shell:
  "$RUNTIME_DIR/bin/agentpay" --help

Managed wallet setup is supported on macOS and Linux.
Run agentpay admin setup when you are ready to create or attach a wallet.
EOF_SUMMARY
    return
  fi

  if [[ -n "$CURRENT_SHELL_SHIM_PATH" ]]; then
    cat <<EOF_SUMMARY

AgentPay SDK install complete.

Install root:
  $INSTALL_DIR

AgentPay SDK runtime:
  $RUNTIME_DIR

Run now in this shell:
  agentpay --help

Current-shell shim:
  $CURRENT_SHELL_SHIM_PATH

Future shells are configured via:
  source "$SHELL_RC_PATH"

Managed wallet setup is supported on macOS and Linux.

When you are ready to create or attach a wallet:
  1. Run agentpay admin setup
  2. Complete the secure local password prompts there
EOF_SUMMARY
    return
  fi

  cat <<EOF_SUMMARY

AgentPay SDK install complete.

Install root:
  $INSTALL_DIR

AgentPay SDK runtime:
  $RUNTIME_DIR

Your current shell still needs the updated PATH:
  source "$SHELL_RC_PATH"

Current-shell shim was skipped:
  ${CURRENT_SHELL_SHIM_WARNING:-unable to place agentpay into an existing PATH entry}

Or run AgentPay directly right now without reloading the shell:
  "$RUNTIME_DIR/bin/agentpay" --help

Managed wallet setup is supported on macOS and Linux.

When you are ready to create or attach a wallet:
  1. Reload your shell with: source "$SHELL_RC_PATH"
  2. Run agentpay admin setup
  3. Complete the secure local password prompts there
EOF_SUMMARY
}

print_skills_only_summary() {
  local target=""
  local installed_any=0

  cat <<'EOF_SUMMARY'

AgentPay SDK skills install finished.
EOF_SUMMARY

  if (( ${#INSTALLED_SKILL_TARGETS[@]} > 0 )); then
    installed_any=1
    printf '\nSkill targets:\n'
    for target in "${INSTALLED_SKILL_TARGETS[@]}"; do
      printf '  %s\n' "$target"
    done
  fi

  if (( ${#INSTALLED_CURSOR_ARTIFACTS[@]} > 0 )); then
    installed_any=1
    printf '\nAdapter artifacts:\n'
    for target in "${INSTALLED_CURSOR_ARTIFACTS[@]}"; do
      printf '  %s\n' "$target"
    done
  fi

  if (( installed_any == 0 )); then
    cat <<'EOF_SUMMARY'

No local AI targets were installed.
Rerun with AGENTPAY_SETUP_INSTALL_SKILLS=yes and optionally AGENTPAY_SETUP_CURSOR_WORKSPACE=<path>.
EOF_SUMMARY
    return
  fi

  cat <<'EOF_SUMMARY'

Rerun the same installer command any time to refresh the skill pack.
EOF_SUMMARY
}

cleanup_temp_bundle() {
  if [[ -n "${BUNDLE_TEMP_DIR:-}" ]]; then
    rm -rf "$BUNDLE_TEMP_DIR"
  fi
}

main() {
  parse_args "$@"

  configure_bash_compatibility
  init_prompt_io
  validate_installer_modes

  if ! installer_mode_is_skills_only; then
    choose_install_dir
  fi

  BUNDLE_URL="${BUNDLE_URL_OVERRIDE:-$(resolve_default_bundle_url)}"
  trap cleanup_temp_bundle EXIT

  if installer_mode_is_skills_only; then
    step "Downloading the shared AgentPay SDK bundle" "If this download failed, publish or pass a reachable AgentPay SDK bundle via AGENTPAY_SDK_BUNDLE_URL."
  else
    step "Downloading the prebuilt AgentPay SDK runtime bundle" "If this download failed, publish or pass a reachable AgentPay SDK bundle via AGENTPAY_SDK_BUNDLE_URL."
  fi
  install_bundle_archive "$BUNDLE_URL"

  if installer_mode_is_skills_only; then
    step "Installing AgentPay skill targets" "If a skill install failed, rerun after fixing the destination path or set AGENTPAY_SETUP_CURSOR_WORKSPACE explicitly."
    maybe_install_skill_targets
    print_skills_only_summary
    return
  fi

  step "Checking the Node.js runtime" "Install Node 20+ and rerun the installer."
  ensure_node

  step "Updating shell environment" "Open a new shell after install if agentpay is not immediately available."
  write_shell_exports

  step "Installing agentpay from the prebuilt runtime bundle" "If installation failed, check filesystem permissions under the install directory and rerun."
  install_runtime_from_bundle

  step "Installing optional skill targets" "If a skill install failed, rerun with AGENTPAY_SETUP_SKIP_SKILLS=1 and install that target later."
  maybe_install_skill_targets

  step "Recording one-click install metadata" "If manifest writing failed, check filesystem permissions under the install directory and rerun."
  write_install_manifest

  if [[ "$(resolve_run_admin_setup_default)" == "yes" ]]; then
    step "Wallet setup" "If admin setup fails, rerun agentpay admin setup after fixing the reported issue."
    maybe_run_admin_setup
  fi

  print_summary
}

main "$@"
