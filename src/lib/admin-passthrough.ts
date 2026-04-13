export function rewriteAdminHelpText(value: string): string {
  return value
    .replaceAll('agentpay-admin', 'agentpay admin')
    .replace(/^\s*bootstrap\s+.*\n/gmu, '')
    .replace(/^\s*rotate-agent-auth-token\s+.*\n/gmu, '')
    .replace(/^\s*revoke-agent-key\s+.*\n/gmu, '')
    .replace(
      'Admin CLI for configuring vault policies and agent keys',
      'Admin CLI for configuring daemon setup, policies, chains, tokens, and agent keys',
    )
    .replace(
      'Launch interactive terminal UI for bootstrap configuration',
      'Launch interactive terminal UI for wallet setup and policy configuration',
    )
    .replace(
      '  reset                            Remove the managed daemon state and local wallet credentials\n  help                             Print this message or the help of the given subcommand(s)',
      '  chain                            Manage active chain selection and chain profiles\n  token                            Manage shared token definitions and default policies\n  daemon                           Daemon launch is managed by admin setup\n  reset                            Remove the managed daemon state and local wallet credentials\n  uninstall                        Fully remove the managed daemon, local files, and logs\n  help                             Print this message or the help of the given subcommand(s)',
    )
    .replace(
      '  help                             Print this message or the help of the given subcommand(s)',
      '  chain                            Manage active chain selection and chain profiles\n  token                            Manage shared token definitions and default policies\n  daemon                           Daemon launch is managed by admin setup\n  uninstall                        Fully remove the managed daemon, local files, and logs\n  help                             Print this message or the help of the given subcommand(s)',
    );
}

export function blockedRawAdminPassthroughMessage(command: string | undefined): string | null {
  if (command === 'rotate-agent-auth-token') {
    return '`agentpay admin rotate-agent-auth-token` is disabled; use `agentpay config agent-auth rotate` so the rotated token is stored in the local credential store.';
  }
  if (command === 'revoke-agent-key') {
    return '`agentpay admin revoke-agent-key` is disabled; use `agentpay config agent-auth revoke` so local credentials are removed safely.';
  }
  return null;
}
