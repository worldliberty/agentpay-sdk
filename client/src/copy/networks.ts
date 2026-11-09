/** Wording for networks: why one cannot be read, and grouping headings. */
export const networks = {
  rateLimited: 'The public RPC is limiting requests',
  timedOut: 'The RPC did not answer in time',
  wrongChain: 'The RPC serves a different network',
  unreachable: 'The RPC cannot be reached',
  noRpc: 'No RPC URL is set',
  setRpc: (network: string) =>
    `Use your own RPC: \`agentpay config set chains.${network}.rpc_url <URL>\` (backups: \`chains.${network}.fallback_rpc_urls\`).`,
  testnets: 'Test networks',
  noFundsYet: 'no funds yet',
  unreadable: (count: number) =>
    count === 1 ? '1 network cannot be read' : `${count} networks cannot be read`,
};
