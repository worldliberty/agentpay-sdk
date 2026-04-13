#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Install or replace the AgentPay SDK root systemd daemon.

Usage:
  install-system-daemon.sh [options]

Options:
  --label <label>                systemd unit label without .service (default: agentpay-daemon)
  --runner <path>                Runner script path (required)
  --daemon-bin <path>            Rust daemon binary path (required)
  --password-helper <path>       Root password helper path (required)
  --state-file <path>            Encrypted daemon state path (required)
  --daemon-socket <path>         Daemon unix socket path (required)
  --password-file <path>         Root-only daemon password file path (required)
  --signer-backend <kind>        Signer backend for daemon (default: software)
  --allow-admin-euid <uid>       Allowed admin client uid (required)
  --allow-agent-euid <uid>       Allowed agent client uid (required)
  --vault-password-stdin         Read vault password from stdin and store it in the managed password file
  --help                         Show this help
EOF
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

quote_systemd_env_assignment() {
  local name="$1"
  local value="$2"

  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "systemd environment value for $name must not contain newlines" >&2
    exit 1
  fi

  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//%/%%}"
  printf '"%s=%s"' "$name" "$value"
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
  chown root:root "$temp_target"
  mv -f "$temp_target" "$target"
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "install-system-daemon.sh supports Linux systemd only" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "install-system-daemon.sh must be run as root" >&2
  exit 1
fi

command -v systemctl >/dev/null 2>&1 || {
  echo "systemctl is required to install the managed AgentPay daemon on Linux" >&2
  exit 1
}

label="agentpay-daemon"
runner=""
daemon_bin=""
password_helper=""
state_file=""
daemon_socket=""
password_file=""
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
    --password-helper)
      require_non_empty_value "$1" "${2:-}"
      password_helper="$2"
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
    --password-file)
      require_non_empty_value "$1" "${2:-}"
      password_file="$2"
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
require_non_empty_value "--password-helper" "$password_helper"
require_non_empty_value "--state-file" "$state_file"
require_non_empty_value "--daemon-socket" "$daemon_socket"
require_non_empty_value "--password-file" "$password_file"
require_non_empty_value "--allow-admin-euid" "$allow_admin_euid"
require_non_empty_value "--allow-agent-euid" "$allow_agent_euid"

if [[ "$vault_password_stdin" != true ]]; then
  echo "install-system-daemon.sh requires --vault-password-stdin" >&2
  exit 1
fi

require_regular_executable "runner" "$runner"
require_regular_executable "daemon binary" "$daemon_bin"
require_regular_executable "password helper" "$password_helper"

vault_password="$(read_secret_from_stdin 'vault password')"
trap 'unset vault_password' EXIT
relay_daemon_token="${AGENTPAY_RELAY_DAEMON_TOKEN:-}"

managed_bin_dir="/opt/agentpay/bin"
managed_runner="${managed_bin_dir}/run-agentpay-daemon.sh"
managed_daemon_bin="${managed_bin_dir}/$(basename "$daemon_bin")"
managed_password_helper="${managed_bin_dir}/$(basename "$password_helper")"
state_dir="$(dirname "$state_file")"
socket_dir="$(dirname "$daemon_socket")"
unit_path="/etc/systemd/system/${label}.service"
relay_token_file="${state_dir}/relay-daemon-token"

mkdir -p "$managed_bin_dir" "$state_dir" "$socket_dir"
chmod 755 "$managed_bin_dir"
chmod 700 "$state_dir"
chmod 755 "$socket_dir"
chown root:root "$managed_bin_dir" "$state_dir" "$socket_dir"

install -o root -g root -m 700 "$runner" "$managed_runner"
install -o root -g root -m 700 "$daemon_bin" "$managed_daemon_bin"
install -o root -g root -m 700 "$password_helper" "$managed_password_helper"
install_private_file "managed daemon password file" "$password_file" "$vault_password"

if [[ -n "$relay_daemon_token" ]]; then
  install_private_file "managed relay daemon token file" "$relay_token_file" "$relay_daemon_token"
else
  rm -f "$relay_token_file"
fi

env_daemon_bin="$(quote_systemd_env_assignment AGENTPAY_DAEMON_BIN "$managed_daemon_bin")"
env_state_file="$(quote_systemd_env_assignment AGENTPAY_STATE_FILE "$state_file")"
env_daemon_socket="$(quote_systemd_env_assignment AGENTPAY_DAEMON_SOCKET "$daemon_socket")"
env_password_file="$(quote_systemd_env_assignment AGENTPAY_PASSWORD_FILE "$password_file")"
env_password_helper="$(quote_systemd_env_assignment AGENTPAY_PASSWORD_HELPER "$managed_password_helper")"
env_signer_backend="$(quote_systemd_env_assignment AGENTPAY_SIGNER_BACKEND "$signer_backend")"
env_allow_admin_euid="$(quote_systemd_env_assignment AGENTPAY_ALLOW_ADMIN_EUID "$allow_admin_euid")"
env_allow_agent_euid="$(quote_systemd_env_assignment AGENTPAY_ALLOW_AGENT_EUID "$allow_agent_euid")"
env_relay_token_file="$(quote_systemd_env_assignment AGENTPAY_RELAY_DAEMON_TOKEN_FILE "$relay_token_file")"

cat >"$unit_path" <<EOF_UNIT
[Unit]
Description=AgentPay managed daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
Environment=$env_daemon_bin
Environment=$env_state_file
Environment=$env_daemon_socket
Environment=$env_password_file
Environment=$env_password_helper
Environment=$env_signer_backend
Environment=$env_allow_admin_euid
Environment=$env_allow_agent_euid
Environment=$env_relay_token_file
ExecStart=$managed_runner
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF_UNIT
chmod 644 "$unit_path"

systemctl daemon-reload
systemctl enable --now "${label}.service"

cat <<EOF
installed systemd daemon:
  unit: ${label}.service
  runner: ${managed_runner}
  daemon bin: ${managed_daemon_bin}
  password helper: ${managed_password_helper}
  daemon socket: ${daemon_socket}
  state file: ${state_file}
  password file: ${password_file}
EOF
