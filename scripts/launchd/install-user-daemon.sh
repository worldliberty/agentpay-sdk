#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF2'
Install or replace the AgentPay SDK root LaunchDaemon.

Usage:
  install-user-daemon.sh [options]

Options:
  --label <label>                LaunchDaemon label (default: com.agentpay.daemon)
  --runner <path>                LaunchDaemon runner script path (required)
  --daemon-bin <path>            Rust daemon binary path (required)
  --keychain-helper <path>       Rust helper path for daemon System.keychain access (required)
  --state-file <path>            Encrypted daemon state path (required)
  --daemon-socket <path>         Daemon unix socket path (required)
  --keychain-service <name>      Keychain service (default: agentpay-daemon-password)
  --keychain-account <name>      Keychain account (required)
  --signer-backend <kind>        Signer backend for daemon (default: software)
  --allow-admin-euid <uid>       Allowed admin client uid (required)
  --allow-agent-euid <uid>       Allowed agent client uid (required)
  --vault-password-stdin         Read vault password from stdin and store it in System.keychain
  --help                         Show this help
EOF2
}

require_non_empty_value() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" ]]; then
    echo "missing value for $flag" >&2
    exit 1
  fi
}

validate_label() {
  local value="$1"
  if [[ ! "$value" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "invalid --label '$value': allowed characters are [A-Za-z0-9._-]" >&2
    exit 1
  fi
}

read_secret_from_stdin() {
  local label="$1"
  local raw
  raw="$(cat)"
  raw="${raw%$'\n'}"
  raw="${raw%$'\r'}"
  if [[ -z "${raw//[[:space:]]/}" ]]; then
    echo "$label must not be empty or whitespace" >&2
    exit 1
  fi
  printf '%s' "$raw"
}

require_regular_executable() {
  local label="$1"
  local target="$2"

  if [[ -L "$target" ]]; then
    echo "$label must not be a symlink: $target" >&2
    exit 1
  fi
  if [[ ! -f "$target" ]]; then
    echo "$label must be a regular file: $target" >&2
    exit 1
  fi
  if [[ ! -x "$target" ]]; then
    echo "$label is not executable: $target" >&2
    exit 1
  fi
}

install_private_file() {
  local label="$1"
  local target="$2"
  local value="$3"
  local temp_target="${target}.tmp.$$"

  if [[ -L "$target" ]]; then
    echo "$label must not be a symlink: $target" >&2
    exit 1
  fi
  if [[ -e "$target" && ! -f "$target" ]]; then
    echo "$label must be a regular file: $target" >&2
    exit 1
  fi

  printf '%s' "$value" > "$temp_target"
  chmod 600 "$temp_target"
  chown root:wheel "$temp_target"
  mv -f "$temp_target" "$target"
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "install-user-daemon.sh supports macOS launchd only" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "install-user-daemon.sh must be run as root" >&2
  exit 1
fi

label="com.agentpay.daemon"
runner=""
daemon_bin=""
keychain_helper=""
state_file=""
daemon_socket=""
keychain_service="agentpay-daemon-password"
keychain_account=""
signer_backend="software"
allow_admin_euid=""
allow_agent_euid=""
vault_password_stdin=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      require_non_empty_value "$1" "${2:-}"
      label="$2"
      shift 2
      ;;
    --runner)
      require_non_empty_value "$1" "${2:-}"
      runner="$2"
      shift 2
      ;;
    --daemon-bin)
      require_non_empty_value "$1" "${2:-}"
      daemon_bin="$2"
      shift 2
      ;;
    --keychain-helper)
      require_non_empty_value "$1" "${2:-}"
      keychain_helper="$2"
      shift 2
      ;;
    --state-file)
      require_non_empty_value "$1" "${2:-}"
      state_file="$2"
      shift 2
      ;;
    --daemon-socket)
      require_non_empty_value "$1" "${2:-}"
      daemon_socket="$2"
      shift 2
      ;;
    --keychain-service)
      require_non_empty_value "$1" "${2:-}"
      keychain_service="$2"
      shift 2
      ;;
    --keychain-account)
      require_non_empty_value "$1" "${2:-}"
      keychain_account="$2"
      shift 2
      ;;
    --signer-backend)
      require_non_empty_value "$1" "${2:-}"
      signer_backend="$2"
      shift 2
      ;;
    --allow-admin-euid)
      require_non_empty_value "$1" "${2:-}"
      allow_admin_euid="$2"
      shift 2
      ;;
    --allow-agent-euid)
      require_non_empty_value "$1" "${2:-}"
      allow_agent_euid="$2"
      shift 2
      ;;
    --vault-password-stdin)
      vault_password_stdin=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

validate_label "$label"
require_non_empty_value "--runner" "$runner"
require_non_empty_value "--daemon-bin" "$daemon_bin"
require_non_empty_value "--keychain-helper" "$keychain_helper"
require_non_empty_value "--state-file" "$state_file"
require_non_empty_value "--daemon-socket" "$daemon_socket"
require_non_empty_value "--keychain-account" "$keychain_account"
require_non_empty_value "--allow-admin-euid" "$allow_admin_euid"
require_non_empty_value "--allow-agent-euid" "$allow_agent_euid"

if [[ ! -x "$runner" ]]; then
  echo "runner is not executable: $runner" >&2
  exit 1
fi
if [[ ! -x "$daemon_bin" ]]; then
  echo "daemon binary is not executable: $daemon_bin" >&2
  exit 1
fi
if [[ ! -x "$keychain_helper" ]]; then
  echo "keychain helper is not executable: $keychain_helper" >&2
  exit 1
fi

if [[ "$vault_password_stdin" != true ]]; then
  echo "install-user-daemon.sh requires --vault-password-stdin" >&2
  exit 1
fi

vault_password="$(read_secret_from_stdin 'vault password')"
trap 'unset vault_password' EXIT
relay_daemon_token="${AGENTPAY_RELAY_DAEMON_TOKEN:-}"

launch_daemons_dir="/Library/LaunchDaemons"
plist_path="${launch_daemons_dir}/${label}.plist"
log_dir="/var/log/agentpay"
stdout_log="${log_dir}/${label}.out.log"
stderr_log="${log_dir}/${label}.err.log"
managed_bin_dir="/Library/AgentPay/bin"
managed_runner="${managed_bin_dir}/run-agentpay-daemon.sh"
managed_daemon_bin="${managed_bin_dir}/$(basename "$daemon_bin")"
managed_keychain_helper="${managed_bin_dir}/$(basename "$keychain_helper")"
state_dir="$(dirname "$state_file")"
socket_dir="$(dirname "$daemon_socket")"
relay_token_file="${state_dir}/relay-daemon-token"

require_regular_executable "runner" "$runner"
require_regular_executable "daemon binary" "$daemon_bin"
require_regular_executable "keychain helper" "$keychain_helper"

mkdir -p "$launch_daemons_dir" "$log_dir" "$managed_bin_dir" "$state_dir" "$socket_dir"
chmod 755 "$launch_daemons_dir"
chmod 755 "$managed_bin_dir"
chmod 700 "$log_dir" "$state_dir"
chmod 755 "$socket_dir"
chown root:wheel "$log_dir" "$managed_bin_dir" "$state_dir" "$socket_dir"

temp_runner="${managed_runner}.tmp.$$"
temp_daemon_bin="${managed_daemon_bin}.tmp.$$"
temp_keychain_helper="${managed_keychain_helper}.tmp.$$"
temp_relay_token_file="${relay_token_file}.tmp.$$"
temp_keychain_replace_stderr="${managed_keychain_helper}.replace-stderr.$$"
trap 'rm -f "$temp_runner" "$temp_daemon_bin" "$temp_keychain_helper" "$temp_relay_token_file" "$temp_keychain_replace_stderr"; unset vault_password relay_daemon_token' EXIT

install -o root -g wheel -m 755 "$runner" "$temp_runner"
install -o root -g wheel -m 755 "$daemon_bin" "$temp_daemon_bin"
install -o root -g wheel -m 700 "$keychain_helper" "$temp_keychain_helper"
mv -f "$temp_runner" "$managed_runner"
mv -f "$temp_daemon_bin" "$managed_daemon_bin"
mv -f "$temp_keychain_helper" "$managed_keychain_helper"

if [[ -n "$relay_daemon_token" ]]; then
  install_private_file "relay daemon token file" "$relay_token_file" "$relay_daemon_token"
else
  rm -f "$relay_token_file"
fi

replace_keychain_password() {
  "$managed_keychain_helper" replace-generic-password \
    --keychain /Library/Keychains/System.keychain \
    --service "$keychain_service" \
    --account "$keychain_account" \
    --password-stdin <<<"$vault_password"
}

replace_status=0
replace_keychain_password 2>"$temp_keychain_replace_stderr" || replace_status=$?
if [[ "$replace_status" -ne 0 ]]; then
  if grep -Eiq 'specified item already exists|already exists in the keychain|errSecDuplicateItem' "$temp_keychain_replace_stderr"; then
    /usr/bin/security delete-generic-password \
      -s "$keychain_service" \
      -a "$keychain_account" \
      /Library/Keychains/System.keychain >/dev/null 2>&1 || true
    replace_keychain_password
  else
    cat "$temp_keychain_replace_stderr" >&2
    exit "$replace_status"
  fi
fi

cat > "$plist_path" <<EOF2
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
      <string>${managed_runner}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
      <key>AGENTPAY_DAEMON_BIN</key>
      <string>${managed_daemon_bin}</string>
      <key>AGENTPAY_STATE_FILE</key>
      <string>${state_file}</string>
      <key>AGENTPAY_DAEMON_SOCKET</key>
      <string>${daemon_socket}</string>
      <key>AGENTPAY_KEYCHAIN_SERVICE</key>
      <string>${keychain_service}</string>
      <key>AGENTPAY_KEYCHAIN_ACCOUNT</key>
      <string>${keychain_account}</string>
      <key>AGENTPAY_KEYCHAIN_HELPER</key>
      <string>${managed_keychain_helper}</string>
      <key>AGENTPAY_SIGNER_BACKEND</key>
      <string>${signer_backend}</string>
      <key>AGENTPAY_ALLOW_ADMIN_EUID</key>
      <string>${allow_admin_euid}</string>
      <key>AGENTPAY_ALLOW_AGENT_EUID</key>
      <string>${allow_agent_euid}</string>
EOF2

if [[ -n "$relay_daemon_token" ]]; then
cat >> "$plist_path" <<EOF2
      <key>AGENTPAY_RELAY_DAEMON_TOKEN_FILE</key>
      <string>${relay_token_file}</string>
EOF2
fi

cat >> "$plist_path" <<EOF2
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>${state_dir}</string>
    <key>StandardOutPath</key>
    <string>${stdout_log}</string>
    <key>StandardErrorPath</key>
    <string>${stderr_log}</string>
  </dict>
</plist>
EOF2
chmod 644 "$plist_path"
chown root:wheel "$plist_path"

launchctl bootout system/${label} >/dev/null 2>&1 || true
launchctl enable system/${label} >/dev/null 2>&1 || true
launchctl bootstrap system "$plist_path"
launchctl enable system/${label} >/dev/null 2>&1 || true
launchctl kickstart -k system/${label} >/dev/null 2>&1 || true

cat <<EOF2
installed launch daemon:
  label: ${label}
  plist: ${plist_path}
  runner: ${managed_runner}
  daemon bin: ${managed_daemon_bin}
  keychain helper: ${managed_keychain_helper}
  daemon socket: ${daemon_socket}
  state file: ${state_file}
  signer backend: ${signer_backend}
  keychain service: ${keychain_service}
  keychain account: ${keychain_account}
EOF2

if [[ -n "$relay_daemon_token" ]]; then
  cat <<EOF2
  relay daemon token file: ${relay_token_file}
EOF2
fi
