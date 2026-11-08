#!/usr/bin/env bash
# launchd runner for the AgentPay daemon, installed by `agentpay-setup` (which embeds this file).
#
# Reads the machine secret from the System Keychain through the root-only helper and hands it to
# the daemon on stdin. The secret never appears in argv or the environment.
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
require_var "AGENTPAY_KEYCHAIN_HELPER"
require_var "AGENTPAY_KEYCHAIN_SERVICE"
require_var "AGENTPAY_KEYCHAIN_ACCOUNT"
require_var "AGENTPAY_ALLOW_ADMIN_EUID"
require_var "AGENTPAY_ALLOW_AGENT_EUID"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run-agentpay-daemon.sh must run as root" >&2
  exit 1
fi

for executable in "$AGENTPAY_DAEMON_BIN" "$AGENTPAY_KEYCHAIN_HELPER"; do
  if [[ -L "$executable" || ! -f "$executable" || ! -x "$executable" ]]; then
    echo "not a regular executable file: $executable" >&2
    exit 1
  fi
done

umask 077
keychain="${AGENTPAY_KEYCHAIN:-/Library/Keychains/System.keychain}"

if ! machine_secret="$("$AGENTPAY_KEYCHAIN_HELPER" read-generic-password \
  --keychain "$keychain" \
  --service "$AGENTPAY_KEYCHAIN_SERVICE" \
  --account "$AGENTPAY_KEYCHAIN_ACCOUNT" 2>/dev/null)"; then
  cat >&2 <<EOF
failed to read the AgentPay machine secret from the System Keychain
  service: $AGENTPAY_KEYCHAIN_SERVICE
  account: $AGENTPAY_KEYCHAIN_ACCOUNT
rerun: sudo agentpay-setup install --user <your-login>
EOF
  exit 1
fi
trap 'unset machine_secret' EXIT

args=(
  --state-secret-stdin
  --state-file "$AGENTPAY_STATE_FILE"
  --daemon-socket "$AGENTPAY_DAEMON_SOCKET"
  --signer-backend "${AGENTPAY_SIGNER_BACKEND:-software}"
  --allow-admin-euid "$AGENTPAY_ALLOW_ADMIN_EUID"
  --allow-agent-euid "$AGENTPAY_ALLOW_AGENT_EUID"
)

# A pipe (process substitution) rather than a here-string, which bash may spill to a temp file;
# `exec` keeps the daemon as launchd's direct child.
exec "$AGENTPAY_DAEMON_BIN" "${args[@]}" < <(printf '%s\n' "$machine_secret")
