import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

import { createPublicClient, http as httpTransport, isAddressEqual } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { tempoModerato } from 'viem/chains';
import { Abis, Actions, Addresses } from 'viem/tempo';

const repoRoot = path.resolve(new URL('../../..', import.meta.url).pathname);
const SERVER_PORT = 4021;
const DEFAULT_RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const PRICE_UNITS = '0.01';
const DEPOSIT_UNITS = '0.02';
const WLFI_AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE = 'wlfi-agent-agent-auth-token';
const AGENTPAY_AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE = 'agentpay-agent-auth-token';

function log(message) {
  process.stderr.write(`[session-demo] ${message}\n`);
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
  const status = await runCommand('wlfi-agent', ['config', 'agent-auth', 'status', '--json']);
  const agentAuthStatus = JSON.parse(status.stdout);

  let agentAuthToken = '';
  let agentAuthTokenSource = '';
  if (agentAuthStatus?.keychain?.stored === true) {
    const { stdout: keychainToken } = await runCommand('security', [
      'find-generic-password',
      '-s',
      WLFI_AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
      '-a',
      wallet.agentKeyId,
      '-w',
    ]);
    agentAuthToken = keychainToken.trim();
    agentAuthTokenSource = 'macOS Keychain';
  } else {
    agentAuthToken = (
      process.env.AGENTPAY_MPP_DEMO_AGENT_AUTH_TOKEN ||
      process.env.WLFI_AGENT_AUTH_TOKEN ||
      process.env.AGENTPAY_AGENT_AUTH_TOKEN ||
      ''
    ).trim();
    agentAuthTokenSource = 'environment';
  }
  if (!agentAuthToken) {
    throw new Error(
      [
        `no wlfi-agent auth token is available for agentKeyId ${wallet.agentKeyId}`,
        'The session demo can use one of these sources:',
        `1. Store the token in macOS Keychain via \`wlfi-agent config agent-auth rotate\` or another local import flow`,
        '2. Export a token into this process only:',
        '   `AGENTPAY_MPP_DEMO_AGENT_AUTH_TOKEN=<token> pnpm example:mpp:session-demo`',
      ].join('\n'),
    );
  }

  const wlfiBinDir = String(config.paths?.wlfiHome || '').trim()
    ? path.join(config.paths.wlfiHome, 'bin')
    : String(config.rustBinDir ?? '').trim();
  if (!wlfiBinDir) {
    throw new Error('wlfi-agent config is missing rustBinDir');
  }

  return {
    kind: 'wlfi-agent',
    agentAuthToken,
    agentAuthTokenSource,
    agentKeyId: String(wallet.agentKeyId),
    daemonSocket: String(config.daemonSocket),
    homeDir: path.dirname(
      String(config.paths?.wlfiHome || '').trim() || path.join(os.homedir(), '.wlfi_agent'),
    ),
    wallet,
    wlfiBinDir,
  };
}

async function loadAgentpayWalletContext() {
  const [{ stdout: configRaw }, { stdout: walletRaw }] = await Promise.all([
    runCommand(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'config', 'show', '--json']),
    runCommand(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'wallet', '--json']),
  ]);
  const config = JSON.parse(configRaw);
  const wallet = JSON.parse(walletRaw);
  const agentKeyId = String(wallet.agentKeyId ?? config.agentKeyId ?? '').trim();
  if (!agentKeyId) {
    throw new Error('agentpay wallet is missing agentKeyId');
  }

  const { stdout: keychainToken } = await runCommand('security', [
    'find-generic-password',
    '-s',
    AGENTPAY_AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
    '-a',
    agentKeyId,
    '-w',
  ]);

  return {
    kind: 'agentpay',
    agentAuthToken: keychainToken.trim(),
    agentAuthTokenSource: 'macOS Keychain',
    agentKeyId,
    daemonSocket: String(config.daemonSocket ?? '/Library/AgentPay/run/daemon.sock'),
    homeDir: os.homedir(),
    wallet,
    rustBinDir: String(config.paths?.rustBinDir ?? path.join(os.homedir(), '.agentpay', 'bin')),
  };
}

async function loadDemoWalletContext() {
  try {
    return await loadAgentpayWalletContext();
  } catch (agentpayError) {
    log(
      `local agentpay context unavailable, falling back to wlfi-agent compatibility: ${
        agentpayError instanceof Error ? agentpayError.message : String(agentpayError)
      }`,
    );
    return await loadWlfiWalletContext();
  }
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

async function startExampleServer({ recipient, recipientPrivateKey }) {
  let terminated = false;
  const child = spawn(process.execPath, ['example/mpp/server/session-server.mjs'], {
    cwd: repoRoot,
    env: {
      ...process.env,
      HOST: '127.0.0.1',
      PORT: String(SERVER_PORT),
      MPP_REALM: `127.0.0.1:${SERVER_PORT}`,
      MPP_SECRET_KEY:
        process.env.MPP_SECRET_KEY || 'agentpay-mpp-demo-tempo-testnet-session-secret',
      RECIPIENT_ADDRESS: recipient,
      ...(recipientPrivateKey ? { RECIPIENT_PRIVATE_KEY: recipientPrivateKey } : {}),
      TOKEN_ADDRESS: Addresses.pathUsd,
      PRICE_UNITS,
      PRODUCT_NAME: 'Tempo Testnet Session Photo',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  streamWithPrefix(child.stdout, '[session-server] ');
  streamWithPrefix(child.stderr, '[session-server] ');
  child.on('exit', (code, signal) => {
    if (!terminated && code !== 0 && signal !== 'SIGTERM') {
      process.stderr.write(
        `[session-server] exited unexpectedly (code=${code} signal=${signal})\n`,
      );
    }
  });

  await waitFor(async () => {
    const response = await fetch(`http://127.0.0.1:${SERVER_PORT}/health`);
    return response.ok ? response : null;
  }, 'session server readiness');

  return {
    stop() {
      terminated = true;
      child.kill('SIGTERM');
    },
  };
}

async function runAgentpayMpp({
  homeDir,
  daemonSocket,
  agentKeyId,
  agentAuthToken,
  sessionStatePath,
  closeSession,
  useKeychainBackedAgentpay,
}) {
  return await new Promise((resolve, reject) => {
    const args = [
      '--import',
      'tsx',
      'src/cli.ts',
      'mpp',
      `http://127.0.0.1:${SERVER_PORT}/api/photo`,
      '--amount',
      PRICE_UNITS,
      '--deposit',
      DEPOSIT_UNITS,
      '--rpc-url',
      tempoModerato.rpcUrls.default.http[0],
      '--session-state-file',
      sessionStatePath,
      '--json',
    ];
    if (useKeychainBackedAgentpay) {
      args.push('--daemon-socket', daemonSocket);
    } else {
      args.push(
        '--agent-key-id',
        agentKeyId,
        '--agent-auth-token-stdin',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        daemonSocket,
      );
    }
    if (closeSession) {
      args.push('--close-session');
    }

    const child = spawn(process.execPath, args, {
      cwd: repoRoot,
      env: {
        ...process.env,
        HOME: homeDir,
        AGENTPAY_HOME: path.join(homeDir, '.agentpay'),
      },
      stdio: ['pipe', 'pipe', 'pipe'],
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
    if (useKeychainBackedAgentpay) {
      child.stdin?.end();
    } else {
      child.stdin?.end(`${agentAuthToken}\n`);
    }
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

function printResult(label, result) {
  process.stdout.write(`${JSON.stringify({ step: label, ...result }, null, 2)}\n`);
}

async function main() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-mpp-tempo-session-'));
  const agentpayHome = path.join(tempDir, '.agentpay');
  const rustBinDir = path.join(agentpayHome, 'bin');
  const recipient = process.env.RECIPIENT_ADDRESS || DEFAULT_RECIPIENT;
  let serverHandle = null;

  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  try {
    const context = await loadDemoWalletContext();
    const walletAddress = String(context.wallet.address);
    const recipientPrivateKey =
      process.env.RECIPIENT_PRIVATE_KEY || `0x${crypto.randomBytes(32).toString('hex')}`;
    const recipientAccount = privateKeyToAccount(recipientPrivateKey);
    const effectiveRecipient = recipientAccount.address;
    if (isAddressEqual(walletAddress, effectiveRecipient)) {
      throw new Error('payer and recipient must be different addresses');
    }

    log(`payer: ${walletAddress}`);
    log(`recipient: ${effectiveRecipient}`);
    log(`wallet source: ${context.kind}`);
    log(`agent auth token source: ${context.agentAuthTokenSource}`);
    await ensureTempoFunding(walletAddress);
    await ensureTempoFunding(effectiveRecipient);
    const effectiveSessionStatePath =
      context.kind === 'agentpay'
        ? path.join(context.homeDir, '.agentpay', 'tempo-session-demo.json')
        : path.join(agentpayHome, 'tempo-session.json');
    fs.rmSync(effectiveSessionStatePath, { force: true });

    if (context.kind === 'wlfi-agent') {
      createAgentpayWrappers({
        rustBinDir,
        wlfiBinDir: context.wlfiBinDir,
      });
      writeAgentpayConfig({
        agentpayHome,
        rustBinDir,
        daemonSocket: context.daemonSocket,
        wallet: context.wallet,
      });
    }

    serverHandle = await startExampleServer({
      recipient: effectiveRecipient,
      recipientPrivateKey,
    });
    log(`session server ready at http://127.0.0.1:${SERVER_PORT}/api/photo`);

    const first = await runAgentpayMpp({
      homeDir: context.kind === 'agentpay' ? context.homeDir : tempDir,
      daemonSocket: context.daemonSocket,
      agentKeyId: context.agentKeyId,
      agentAuthToken: context.agentAuthToken,
      sessionStatePath: effectiveSessionStatePath,
      closeSession: false,
      useKeychainBackedAgentpay: context.kind === 'agentpay',
    });
    if (first.stderr.trim()) {
      process.stderr.write(first.stderr);
      if (!first.stderr.endsWith('\n')) {
        process.stderr.write('\n');
      }
    }
    if (first.code !== 0) {
      throw new Error(`first agentpay mpp call failed with exit ${first.code}\n${first.stdout}`);
    }
    const firstParsed = JSON.parse(first.stdout);
    if (!fs.existsSync(effectiveSessionStatePath)) {
      throw new Error('expected session state file after first session request');
    }
    printResult('open', firstParsed);
    log(`opened session ${firstParsed.payment?.channelId ?? 'unknown'}`);

    const second = await runAgentpayMpp({
      homeDir: context.kind === 'agentpay' ? context.homeDir : tempDir,
      daemonSocket: context.daemonSocket,
      agentKeyId: context.agentKeyId,
      agentAuthToken: context.agentAuthToken,
      sessionStatePath: effectiveSessionStatePath,
      closeSession: true,
      useKeychainBackedAgentpay: context.kind === 'agentpay',
    });
    if (second.stderr.trim()) {
      process.stderr.write(second.stderr);
      if (!second.stderr.endsWith('\n')) {
        process.stderr.write('\n');
      }
    }
    if (second.code !== 0) {
      throw new Error(`second agentpay mpp call failed with exit ${second.code}\n${second.stdout}`);
    }
    const secondParsed = JSON.parse(second.stdout);
    if (fs.existsSync(effectiveSessionStatePath)) {
      throw new Error('expected session state file to be deleted after close-session request');
    }
    printResult('reuse-close', secondParsed);
    log(`closed session ${secondParsed.payment?.channelId ?? 'unknown'}`);
    if (context.kind !== 'agentpay') {
      log(`temporary AGENTPAY_HOME: ${agentpayHome}`);
    }
  } finally {
    serverHandle?.stop?.();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

await main();
