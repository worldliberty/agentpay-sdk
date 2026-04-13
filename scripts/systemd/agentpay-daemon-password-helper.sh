#!/usr/bin/env bash
set -euo pipefail

password_file="${1:-}"
if [[ -z "$password_file" ]]; then
  echo "usage: agentpay-daemon-password-helper.sh <password-file>" >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "agentpay-daemon-password-helper.sh must run as root" >&2
  exit 1
fi
if [[ -L "$password_file" ]]; then
  echo "password file must not be a symlink: $password_file" >&2
  exit 1
fi
if [[ ! -f "$password_file" ]]; then
  echo "password file is missing: $password_file" >&2
  exit 1
fi
if [[ ! -r "$password_file" ]]; then
  echo "password file is not readable: $password_file" >&2
  exit 1
fi

cat "$password_file"
