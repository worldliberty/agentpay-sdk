import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

import { createPublicClient, http as httpTransport, isAddressEqual } from 'viem';
import { tempoModerato } from 'viem/chains';
import { Abis, Actions, Addresses } from 'viem/tempo';

const repoRoot = path.resolve(new URL('../../..', import.meta.url).pathname);
const SERVER_PORT = 4020;
const DEFAULT_RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const PRICE_UNITS = '0.01';
const WLFI_AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE = 'wlfi-agent-agent-auth-token';

function log(message) {
  process.stderr.write(`[demo] ${message}\n`);
}

async function waitFor(condition, label, timeoutMs = 60_000, intervalMs = 500) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const value = await condition();
      if (value) {
        return value;
      }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`timed out waiting for ${label}`);
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      stdio: ['ignore', 'pipe', 'pipe'],
      ...options,
    });

    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      reject(
        new Error(
          `${command} ${args.join(' ')} failed with exit ${code}\n${stderr || stdout || ''}`.trim(),
        ),
      );
    });
  });
}

function writeExecutable(filePath, body) {
  fs.writeFileSync(filePath, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
}

async function loadWlfiWalletContext() {
  const [{ stdout: configRaw }, { stdout: walletRaw }] = await Promise.all([
    runCommand('wlfi-agent', ['config', 'show', '--json']),
    runCommand('wlfi-agent', ['wallet', '--json']),
  ]);
  const config = JSON.parse(configRaw);
  const wallet = JSON.parse(walletRaw);

  const { stdout: keychainToken } = await runCommand('security', [
    'find-generic-password',
    '-s',
    WLFI_AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
    '-a',
    wallet.agentKeyId,
    '-w',
  ]);

  const wlfiBinDir = String(config.paths?.wlfiHome || '').trim()
    ? path.join(config.paths.wlfiHome, 'bin')
    : String(config.rustBinDir ?? '').trim();
  if (!wlfiBinDir) {
    throw new Error('wlfi-agent config is missing rustBinDir');
  }

  return {
    agentAuthToken: keychainToken.trim(),
    agentKeyId: String(wallet.agentKeyId),
    daemonSocket: String(config.daemonSocket),
    wallet,
    wlfiBinDir,
  };
}

function writeAgentpayConfig({ agentpayHome, rustBinDir, daemonSocket, wallet }) {
  fs.writeFileSync(
    path.join(agentpayHome, 'config.json'),
    `${JSON.stringify(
      {
        rustBinDir,
        daemonSocket,
        agentKeyId: wallet.agentKeyId,
        wallet,
      },
      null,
      2,
    )}\n`,
  );
}

function streamWithPrefix(stream, prefix) {
  stream?.on('data', (chunk) => {
    const text = chunk.toString();
    for (const line of text.split(/\r?\n/u)) {
      if (!line) {
        continue;
      }
      process.stderr.write(`${prefix}${line}\n`);
    }
  });
}

function createAgentpayWrappers({ rustBinDir, wlfiBinDir }) {
  writeExecutable(
    path.join(rustBinDir, 'agentpay-agent'),
    `exec "${path.join(wlfiBinDir, 'wlfi-agent-agent')}" "$@"`,
  );
  writeExecutable(
    path.join(rustBinDir, 'agentpay-admin'),
    `exec "${path.join(wlfiBinDir, 'wlfi-agent-admin')}" "$@"`,
  );
}

async function ensureTempoFunding(address) {
  const client = createPublicClient({
    chain: tempoModerato,
    transport: httpTransport(tempoModerato.rpcUrls.default.http[0]),
  });
  const [tokenBalance, gasBalance] = await Promise.all([
    client.readContract({
      address: Addresses.pathUsd,
      abi: Abis.tip20,
      functionName: 'balanceOf',
      args: [address],
    }),
    client.getBalance({ address }),
  ]);

  if (tokenBalance > 0n && gasBalance > 0n) {
    log(
      `Tempo Moderato wallet is funded: ${tokenBalance.toString()} PATH/USD and ${gasBalance.toString()} wei gas`,
    );
    return;
  }

  log(`funding ${address} on Tempo Moderato via faucet`);
  await Actions.faucet.fundSync(client, {
    account: address,
    timeout: 30_000,
  });

  await waitFor(async () => {
    const [fundedTokenBalance, fundedGasBalance] = await Promise.all([
      client.readContract({
        address: Addresses.pathUsd,
        abi: Abis.tip20,
        functionName: 'balanceOf',
        args: [address],
      }),
      client.getBalance({ address }),
    ]);
    return fundedTokenBalance > 0n && fundedGasBalance > 0n
      ? { fundedTokenBalance, fundedGasBalance }
      : null;
  }, 'Tempo Moderato faucet funding');
}

async function startExampleServer({ recipient }) {
  let terminated = false;
  const child = spawn(process.execPath, ['example/mpp/server/server.mjs'], {
    cwd: repoRoot,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(SERVER_PORT),
      MPP_REALM: `127.0.0.1:${SERVER_PORT}`,
      MPP_SECRET_KEY: process.env.MPP_SECRET_KEY || 'agentpay-mpp-demo-tempo-testnet-secret',
      RECIPIENT_ADDRESS: recipient,
      TOKEN_ADDRESS: Addresses.pathUsd,
      PRICE_UNITS,
      PRODUCT_NAME: 'Tempo Testnet Photo',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  streamWithPrefix(child.stdout, '[server] ');
  streamWithPrefix(child.stderr, '[server] ');
  child.on('exit', (code, signal) => {
    if (!terminated && code !== 0 && signal !== 'SIGTERM') {
      process.stderr.write(`[server] exited unexpectedly (code=${code} signal=${signal})\n`);
    }
  });

  await waitFor(async () => {
    const response = await fetch(`http://127.0.0.1:${SERVER_PORT}/health`);
    return response.ok ? response : null;
  }, 'example server readiness');

  return {
    stop() {
      terminated = true;
      child.kill('SIGTERM');
    },
  };
}

async function runAgentpayMpp({ homeDir, daemonSocket, agentKeyId, agentAuthToken }) {
  return await new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        '--import',
        'tsx',
        'src/cli.ts',
        'mpp',
        `http://127.0.0.1:${SERVER_PORT}/api/photo`,
        '--amount',
        PRICE_UNITS,
        '--rpc-url',
        tempoModerato.rpcUrls.default.http[0],
        '--agent-key-id',
        agentKeyId,
        '--agent-auth-token-stdin',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        daemonSocket,
        '--json',
      ],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          HOME: homeDir,
          AGENTPAY_HOME: path.join(homeDir, '.agentpay'),
        },
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );

    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.stdin?.end(`${agentAuthToken}\n`);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

async function main() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-mpp-tempo-testnet-'));
  const agentpayHome = path.join(tempDir, '.agentpay');
  const rustBinDir = path.join(agentpayHome, 'bin');
  const recipient = process.env.RECIPIENT_ADDRESS || DEFAULT_RECIPIENT;
  let serverHandle = null;

  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  try {
    const wlfi = await loadWlfiWalletContext();
    const walletAddress = String(wlfi.wallet.address);
    if (isAddressEqual(walletAddress, recipient)) {
      throw new Error('payer and recipient must be different addresses');
    }

    log(`payer: ${walletAddress}`);
    log(`recipient: ${recipient}`);
    await ensureTempoFunding(walletAddress);

    createAgentpayWrappers({
      rustBinDir,
      wlfiBinDir: wlfi.wlfiBinDir,
    });
    writeAgentpayConfig({
      agentpayHome,
      rustBinDir,
      daemonSocket: wlfi.daemonSocket,
      wallet: wlfi.wallet,
    });

    serverHandle = await startExampleServer({ recipient });
    log(`example server ready at http://127.0.0.1:${SERVER_PORT}/api/photo`);

    const result = await runAgentpayMpp({
      homeDir: tempDir,
      daemonSocket: wlfi.daemonSocket,
      agentKeyId: wlfi.agentKeyId,
      agentAuthToken: wlfi.agentAuthToken,
    });
    if (result.stderr.trim()) {
      process.stderr.write(result.stderr);
      if (!result.stderr.endsWith('\n')) {
        process.stderr.write('\n');
      }
    }
    if (result.code !== 0) {
      throw new Error(`agentpay mpp failed with exit ${result.code}\n${result.stdout}`);
    }

    const parsed = JSON.parse(result.stdout);
    const txHash = [
      parsed.payment?.txHash,
      parsed.payment?.receipt?.txHash,
      parsed.payment?.receipt?.reference,
    ].find((value) => typeof value === 'string' && value.length > 0);
    process.stdout.write(`${JSON.stringify(parsed, null, 2)}\n`);
    log(`purchased photo via tx ${txHash ?? 'unknown'}`);
    log(`temporary AGENTPAY_HOME: ${agentpayHome}`);
  } finally {
    serverHandle?.stop?.();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

await main();
