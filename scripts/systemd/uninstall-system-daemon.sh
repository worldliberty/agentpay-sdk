#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Uninstall AgentPay SDK root systemd daemon.

Usage:
  uninstall-system-daemon.sh [options]

Options:
  --label <label>                systemd unit label without .service (default: agentpay-daemon)
  --delete-password-file <path>  Remove the managed daemon password file
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

if [[ "$(id -u)" -ne 0 ]]; then
  echo "uninstall-system-daemon.sh must be run as root" >&2
  exit 1
fi

label="agentpay-daemon"
delete_password_file=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      require_non_empty_value "$1" "${2:-}"
      label="$2"
      shift 2
      ;;
    --delete-password-file)
      require_non_empty_value "$1" "${2:-}"
      delete_password_file="$2"
      shift 2
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
unit_path="/etc/systemd/system/${label}.service"

systemctl disable --now "${label}.service" >/dev/null 2>&1 || true

if [[ -f "$unit_path" ]]; then
  rm -f "$unit_path"
fi

systemctl daemon-reload >/dev/null 2>&1 || true

if [[ -n "$delete_password_file" && -f "$delete_password_file" ]]; then
  rm -f "$delete_password_file"
fi

cat <<EOF
uninstalled systemd daemon:
  unit removed: ${unit_path}
  password file removed: ${delete_password_file:-false}
EOF
