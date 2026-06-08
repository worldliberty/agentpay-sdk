export function assertRpcChainIdMatches(expectedChainId: number, actualChainId: number): void {
  if (actualChainId !== expectedChainId) {
    throw new Error(
      `RPC endpoint chainId ${actualChainId} does not match expected chainId ${expectedChainId}`,
    );
  }
}
