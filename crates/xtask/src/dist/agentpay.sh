#!/bin/sh
# `agentpay`: runs the bundled client (client/dist/cli.js) on the bundled Node.js runtime.
#
# Installed as <release>/bin/agentpay and usually reached through the symlinks
# ~/.agentpay/bin/agentpay -> ../current/bin/agentpay, so the release directory is found by
# resolving symlinks from this script's own path. Written by `cargo xtask dist`.
set -eu

self=$0
while [ -L "$self" ]; do
  link=$(readlink "$self")
  case $link in
    /*) self=$link ;;
    *) self="$(dirname "$self")/$link" ;;
  esac
done
root=$(CDPATH='' cd -P -- "$(dirname -- "$self")/.." && pwd -P)

node="$root/node/bin/node"
entry="$root/client/dist/cli.js"
if [ ! -x "$node" ] || [ ! -f "$entry" ]; then
  printf 'agentpay: the installation in %s is incomplete.\n' "$root" >&2
  printf 'Next: reinstall AgentPay: curl -fsSL https://wlfi.sh | sh\n' >&2
  exit 1
fi

# The client finds agentpay-setup and agentpay-auth on PATH; prefer the ones from this release.
PATH="$root/libexec:$PATH"
export PATH
# Options meant for other Node.js programs must not change how the client runs.
unset NODE_OPTIONS NODE_PATH
exec "$node" "$entry" "$@"
