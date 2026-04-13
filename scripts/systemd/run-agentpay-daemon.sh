#!/usr/bin/env bash
set -euo pipefail

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing required environment variable: $name" >&2
    exit 1
  fi
}

require_var "AGENTPAY_DAEMON_BIN"
require_var "AGENTPAY_STATE_FILE"
require_var "AGENTPAY_DAEMON_SOCKET"
require_var "AGENTPAY_PASSWORD_FILE"
require_var "AGENTPAY_PASSWORD_HELPER"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run-agentpay-daemon.sh must run as root" >&2
  exit 1
fi

if [[ ! -x "$AGENTPAY_DAEMON_BIN" ]]; then
  echo "daemon binary is not executable: $AGENTPAY_DAEMON_BIN" >&2
  exit 1
fi
if [[ ! -x "$AGENTPAY_PASSWORD_HELPER" ]]; then
  echo "password helper is not executable: $AGENTPAY_PASSWORD_HELPER" >&2
  exit 1
fi

umask 077
mkdir -p "$(dirname "$AGENTPAY_STATE_FILE")"
mkdir -p "$(dirname "$AGENTPAY_DAEMON_SOCKET")"
chmod 700 "$(dirname "$AGENTPAY_STATE_FILE")"
chmod 755 "$(dirname "$AGENTPAY_DAEMON_SOCKET")"
chown root:root "$(dirname "$AGENTPAY_STATE_FILE")" "$(dirname "$AGENTPAY_DAEMON_SOCKET")"

if ! vault_password="$("$AGENTPAY_PASSWORD_HELPER" "$AGENTPAY_PASSWORD_FILE" 2>/dev/null)"; then
  cat >&2 <<EOF2
failed to read daemon password from the managed password file.
expected password file:
  path: $AGENTPAY_PASSWORD_FILE
  helper: $AGENTPAY_PASSWORD_HELPER
EOF2
  exit 1
fi

trap 'unset vault_password' EXIT

admin_uid="${AGENTPAY_ALLOW_ADMIN_EUID:?missing AGENTPAY_ALLOW_ADMIN_EUID}"
agent_uid="${AGENTPAY_ALLOW_AGENT_EUID:?missing AGENTPAY_ALLOW_AGENT_EUID}"
signer_backend="${AGENTPAY_SIGNER_BACKEND:-software}"

args=(
  --non-interactive
  --vault-password-stdin
  --state-file "$AGENTPAY_STATE_FILE"
  --daemon-socket "$AGENTPAY_DAEMON_SOCKET"
  --signer-backend "$signer_backend"
  --allow-admin-euid "$admin_uid"
  --allow-agent-euid "$agent_uid"
)
if [[ -n "${AGENTPAY_ALLOW_CLIENT_EUID:-}" ]]; then
  args+=(--allow-client-euid "$AGENTPAY_ALLOW_CLIENT_EUID")
fi
if [[ -n "${AGENTPAY_TPM_DEVICE:-}" ]]; then
  args+=(--tpm-device "$AGENTPAY_TPM_DEVICE")
fi

exec "$AGENTPAY_DAEMON_BIN" "${args[@]}" <<<"$vault_password"
