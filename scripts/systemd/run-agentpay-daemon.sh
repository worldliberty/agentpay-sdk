#!/usr/bin/env bash
# systemd runner for the AgentPay daemon, installed by `agentpay-setup` (which embeds this file).
#
# Reads the machine secret from the root-only secret file and hands it to the daemon on stdin.
# The secret never appears in argv or the environment.
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
require_var "AGENTPAY_SECRET_FILE"
require_var "AGENTPAY_ALLOW_ADMIN_EUID"
require_var "AGENTPAY_ALLOW_AGENT_EUID"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run-agentpay-daemon.sh must run as root" >&2
  exit 1
fi

if [[ -L "$AGENTPAY_DAEMON_BIN" || ! -f "$AGENTPAY_DAEMON_BIN" || ! -x "$AGENTPAY_DAEMON_BIN" ]]; then
  echo "not a regular executable file: $AGENTPAY_DAEMON_BIN" >&2
  exit 1
fi

secret_file="$AGENTPAY_SECRET_FILE"
if [[ -L "$secret_file" || ! -f "$secret_file" ]]; then
  cat >&2 <<EOF
the AgentPay machine secret is missing or not a regular file: $secret_file
rerun: sudo agentpay-setup install --user <your-login>
EOF
  exit 1
fi
# GNU stat; the file must stay root-owned and private.
if [[ "$(stat -c '%u %a' "$secret_file")" != "0 600" ]]; then
  echo "the AgentPay machine secret must be owned by root with mode 0600: $secret_file" >&2
  exit 1
fi

umask 077
machine_secret="$(<"$secret_file")"
trap 'unset machine_secret' EXIT

args=(
  --state-secret-stdin
  --state-file "$AGENTPAY_STATE_FILE"
  --daemon-socket "$AGENTPAY_DAEMON_SOCKET"
  --signer-backend "${AGENTPAY_SIGNER_BACKEND:-software}"
  --allow-admin-euid "$AGENTPAY_ALLOW_ADMIN_EUID"
  --allow-agent-euid "$AGENTPAY_ALLOW_AGENT_EUID"
)
if [[ -n "${AGENTPAY_TPM_DEVICE:-}" ]]; then
  args+=(--tpm-device "$AGENTPAY_TPM_DEVICE")
fi

# A pipe (process substitution) rather than a here-string, which bash may spill to a temp file;
# `exec` keeps the daemon as systemd's direct child.
exec "$AGENTPAY_DAEMON_BIN" "${args[@]}" < <(printf '%s\n' "$machine_secret")
