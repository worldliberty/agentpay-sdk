import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/network-selection.ts', import.meta.url);

test('resolveCliNetworkProfile rejects numeric user input', async () => {
  const networkSelection = await import(`${modulePath.href}?case=${Date.now()}-numeric`);

  assert.throws(
    () =>
      networkSelection.resolveCliNetworkProfile('1', {
        chainId: 1,
        chainName: 'eth',
        rpcUrl: 'https://rpc.ethereum.example',
        chains: {
          eth: {
            chainId: 1,
            name: 'ETH',
            rpcUrl: 'https://eth.llamarpc.com',
          },
        },
      }),
    /network must be a chain name, not a chain id/,
  );
});

test('resolveCliRpcUrl prefers the selected network rpc over the active global rpc', async () => {
  const networkSelection = await import(`${modulePath.href}?case=${Date.now()}-rpc`);

  const rpcUrl = networkSelection.resolveCliRpcUrl(undefined, 'eth', {
    chainId: 1,
    chainName: 'eth',
    rpcUrl: 'https://rpc.ethereum.example',
    chains: {
      eth: {
        chainId: 1,
        name: 'ETH',
        rpcUrl: 'https://eth.llamarpc.com',
      },
      sepolia: {
        chainId: 1,
        name: 'Ethereum',
        rpcUrl: 'https://rpc.ethereum.example',
      },
    },
  });

  assert.equal(rpcUrl, 'https://eth.llamarpc.com');
});

test('resolveCliRpcUrl accepts an explicit rpcUrl override first', async () => {
  const networkSelection = await import(`${modulePath.href}?case=${Date.now()}-rpc-explicit`);

  const rpcUrl = networkSelection.resolveCliRpcUrl(' https://rpc.override.example ', 'eth', {
    rpcUrl: 'https://rpc.global.example',
    chains: {
      eth: {
        chainId: 1,
        name: 'ETH',
        rpcUrl: 'https://eth.llamarpc.com',
      },
    },
  });

  assert.equal(rpcUrl, 'https://rpc.override.example');
});

test('resolveCliNetworkProfile falls back to the active configured chain when omitted', async () => {
  const networkSelection = await import(`${modulePath.href}?case=${Date.now()}-active`);

  const profile = networkSelection.resolveCliNetworkProfile(undefined, {
    chainId: 1,
    chainName: 'eth',
    rpcUrl: 'https://rpc.ethereum.example',
    chains: {
      eth: {
        chainId: 1,
        name: 'ETH',
        rpcUrl: 'https://eth.llamarpc.com',
      },
    },
  });

  assert.equal(profile.chainId, 1);
  assert.equal(profile.rpcUrl, 'https://eth.llamarpc.com');
});

test('resolveCliNetworkProfile falls back to active chainId when chainName is unset', async () => {
  const networkSelection = await import(`${modulePath.href}?case=${Date.now()}-active-chain-id`);

  const profile = networkSelection.resolveCliNetworkProfile(undefined, {
    chainId: 1,
    chains: {
      eth: {
        chainId: 1,
        name: 'ETH',
        rpcUrl: 'https://eth.llamarpc.com',
      },
    },
  });

  assert.equal(profile.chainId, 1);
  assert.equal(profile.name, 'ETH');
});

test('resolveCliNetworkProfile rejects missing and unknown selectors', async () => {
  const networkSelection = await import(
    `${modulePath.href}?case=${Date.now()}-missing-and-unknown`
  );

  assert.throws(
    () =>
      networkSelection.resolveCliNetworkProfile(undefined, {
        chains: {},
      }),
    /network is required/,
  );

  assert.throws(
    () =>
      networkSelection.resolveCliNetworkProfile('unknown', {
        chains: {
          eth: {
            chainId: 1,
            name: 'ETH',
            rpcUrl: 'https://eth.llamarpc.com',
          },
        },
      }),
    /network 'unknown' is not a configured or builtin chain name/,
  );
});

test('resolveCliRpcUrl rejects missing rpcUrl when explicit, network, and config values are absent', async () => {
  const networkSelection = await import(`${modulePath.href}?case=${Date.now()}-rpc-required`);

  assert.throws(
    () =>
      networkSelection.resolveCliRpcUrl(undefined, 'eth', {
        chains: {
          eth: {
            chainId: 1,
            name: 'ETH',
          },
        },
      }),
    /rpcUrl is required/,
  );
});

test('resolveCliRpcUrl falls back to the configured global rpcUrl when the selected network has none', async () => {
  const networkSelection = await import(
    `${modulePath.href}?case=${Date.now()}-rpc-global-fallback`
  );

  const rpcUrl = networkSelection.resolveCliRpcUrl(undefined, 'eth', {
    rpcUrl: 'https://rpc.global.example',
    chains: {
      eth: {
        chainId: 1,
        name: 'ETH',
      },
    },
  });

  assert.equal(rpcUrl, 'https://rpc.global.example');
});
