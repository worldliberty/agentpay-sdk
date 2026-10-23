#!/usr/bin/env node

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import {
  getAssociatedTokenAddressSync,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
} from '@solana/spl-token';
import { ComputeBudgetProgram, Connection, PublicKey } from '@solana/web3.js';
import { publicKeyToAddress } from 'viem/accounts';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const solanaBinDir = path.join(os.homedir(), '.local/share/solana/install/active_release/bin');
const foundryBinDir = path.join(os.homedir(), '.foundry/bin');
const solana = path.join(solanaBinDir, 'solana');
const solanaKeygen = path.join(solanaBinDir, 'solana-keygen');
const solanaTestValidator = path.join(solanaBinDir, 'solana-test-validator');
const splToken = path.join(solanaBinDir, 'spl-token');
const anvil = path.join(foundryBinDir, 'anvil');
const forge = path.join(foundryBinDir, 'forge');
const cast = path.join(foundryBinDir, 'cast');
const pnpm = 'pnpm';
const anvilPrivateKey = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-live-e2e-'));
fs.chmodSync(tempRoot, 0o700);
const agentpayHome = path.join(tempRoot, 'home');
const binDir = path.join(agentpayHome, 'bin');
const logsDir = path.join(tempRoot, 'logs');
const ledgerDir = path.join(tempRoot, 'solana-ledger');
const rootDirTag = `agentpay-live-e2e-${process.pid}`;
const rootStateDir = path.join('/private/var/db', rootDirTag);
const rootRunDir = path.join('/Library/AgentPay/run', rootDirTag);
const daemonSocket = path.join(rootRunDir, 'daemon.sock');
const stateFile = path.join(rootStateDir, 'daemon-state.enc');
const configPath = path.join(agentpayHome, 'config.json');
const rootPasswordPath = path.join(os.homedir(), '.rpw');
const vaultPassword = 'agentpay-live-e2e-vault-password';
const envBase = {
  ...process.env,
  AGENTPAY_HOME: agentpayHome,
  AGENTPAY_DAEMON_SOCKET: daemonSocket,
  PATH: `${solanaBinDir}:${foundryBinDir}:${process.env.PATH ?? ''}`,
};

const children = [];
let tmuxSession;
let rootPassword;

function log(message) {
  process.stderr.write(`[live-e2e] ${message}\n`);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

function ensureExecutable(filePath) {
  assert(fs.existsSync(filePath), `missing required executable: ${filePath}`);
}

function copyDebugBinary(name) {
  const source = path.join(repoRoot, 'target/debug', name);
  const target = path.join(binDir, name);
  assert(fs.existsSync(source), `missing built debug binary: ${source}`);
  fs.copyFileSync(source, target);
  fs.chmodSync(target, 0o755);
  return target;
}

function parseJson(stdout, label) {
  const trimmed = stdout.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    throw new Error(`${label} did not produce JSON: ${trimmed.slice(0, 1000)}`);
  }
}

function extractAddress(payload, label) {
  const candidates = [
    payload?.address,
    payload?.mint,
    payload?.account,
    payload?.associatedTokenAddress,
    payload?.associated_token_address,
    payload?.commandOutput?.address,
    payload?.commandOutput?.mint,
    payload?.commandOutput?.account,
    payload?.commandOutput?.associatedTokenAddress,
    payload?.commandOutput?.associated_token_address,
  ];
  const match = candidates.find((value) => typeof value === 'string' && value.trim());
  assert(match, `${label} did not include an address field: ${JSON.stringify(payload)}`);
  return match;
}

function redactCommand(cmd, args) {
  return [cmd, ...args].join(' ');
}

async function run(cmd, args = [], options = {}) {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const env = options.env ?? envBase;
  const cwd = options.cwd ?? repoRoot;
  const label = options.label ?? redactCommand(cmd, args);
  log(label);
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd,
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      child.kill('SIGTERM');
      reject(
        new Error(
          `${label} timed out after ${timeoutMs}ms\nstdout:\n${stdout}\nstderr:\n${stderr}`,
        ),
      );
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', (error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      const result = { code, stdout, stderr };
      if (code === 0 || options.allowFailure) {
        resolve(result);
        return;
      }
      reject(
        new Error(`${label} failed with exit code ${code}\nstdout:\n${stdout}\nstderr:\n${stderr}`),
      );
    });
    if (options.stdin != null) {
      child.stdin.end(options.stdin);
    } else {
      child.stdin.end();
    }
  });
}

function readRootPassword() {
  if (rootPassword !== undefined) {
    return rootPassword;
  }
  assert(
    fs.existsSync(rootPasswordPath),
    `root password file is required for isolated daemon state setup: ${rootPasswordPath}`,
  );
  rootPassword = fs.readFileSync(rootPasswordPath, 'utf8').replace(/[\r\n]+$/u, '');
  assert(rootPassword, `root password file is empty: ${rootPasswordPath}`);
  return rootPassword;
}

async function runSudo(args, options = {}) {
  return run('sudo', ['-S', '-p', '', ...args], {
    ...options,
    stdin: `${readRootPassword()}\n${options.stdinSuffix ?? ''}`,
    timeoutMs: options.timeoutMs ?? 30_000,
  });
}

function startProcess(name, cmd, args, options = {}) {
  log(`starting ${name}`);
  const stdoutPath = path.join(logsDir, `${name}.stdout.log`);
  const stderrPath = path.join(logsDir, `${name}.stderr.log`);
  const stdout = fs.openSync(stdoutPath, 'a');
  const stderr = fs.openSync(stderrPath, 'a');
  const child = spawn(cmd, args, {
    cwd: options.cwd ?? repoRoot,
    env: options.env ?? envBase,
    stdio: ['pipe', stdout, stderr],
  });
  children.push({ name, child });
  if (options.stdin != null) {
    child.stdin.end(options.stdin);
  } else if (options.closeStdin) {
    child.stdin.end();
  }
  child.once('exit', (code, signal) => {
    fs.closeSync(stdout);
    fs.closeSync(stderr);
    if (!options.allowExit) {
      log(
        `${name} exited early: code=${code} signal=${signal}; logs: ${stdoutPath}, ${stderrPath}`,
      );
    }
  });
  return child;
}

async function waitUntil(label, fn, timeoutMs = 60_000, intervalMs = 500) {
  const started = Date.now();
  let lastError;
  while (Date.now() - started < timeoutMs) {
    try {
      const value = await fn();
      if (value) {
        return value;
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`${label} did not become ready${lastError ? `: ${lastError.message}` : ''}`);
}

async function runJson(cmd, args, options = {}) {
  const result = await run(cmd, args, options);
  return parseJson(result.stdout, options.label ?? cmd);
}

function adminArgs(args) {
  return [
    '--json',
    '--quiet',
    '--vault-password-stdin',
    '--non-interactive',
    '--daemon-socket',
    daemonSocket,
    ...args,
  ];
}

async function runAdminJson(adminBin, args, options = {}) {
  return runJson(adminBin, adminArgs(args), {
    ...options,
    stdin: `${vaultPassword}\n`,
    env: envBase,
  });
}

async function runAgentpayJson(args, agentAuthToken, options = {}) {
  return runJson(
    pnpm,
    [
      'exec',
      'tsx',
      'src/cli.ts',
      ...args,
      '--agent-key-id',
      options.agentKeyId,
      '--agent-auth-token-stdin',
      '--daemon-socket',
      daemonSocket,
      '--json',
    ],
    {
      ...options,
      stdin: `${agentAuthToken}\n`,
      env: envBase,
      timeoutMs: options.timeoutMs ?? 120_000,
    },
  );
}

async function runAgentpay(args, agentAuthToken, options = {}) {
  return run(
    pnpm,
    [
      'exec',
      'tsx',
      'src/cli.ts',
      ...args,
      '--agent-key-id',
      options.agentKeyId,
      '--agent-auth-token-stdin',
      '--daemon-socket',
      daemonSocket,
      '--json',
    ],
    {
      ...options,
      stdin: `${agentAuthToken}\n`,
      env: envBase,
      timeoutMs: options.timeoutMs ?? 120_000,
    },
  );
}

async function splJson(args, label) {
  return runJson(splToken, args, { label, timeoutMs: 120_000 });
}

async function splAddress(args, label) {
  return extractAddress(await splJson(args, label), label);
}

function bootstrapField(payload, snake, camel = snake) {
  return payload[snake] ?? payload[camel];
}

function solanaAddressFromHex(publicKeyHex) {
  return new PublicKey(Buffer.from(publicKeyHex.replace(/^0x/u, ''), 'hex')).toBase58();
}

function associatedTokenAddress(mint, owner, programId) {
  return getAssociatedTokenAddressSync(
    new PublicKey(mint),
    new PublicKey(owner),
    false,
    programId,
  ).toBase58();
}

function evmAddressFromPublicKey(publicKeyHex) {
  const normalized = publicKeyHex.startsWith('0x') ? publicKeyHex : `0x${publicKeyHex}`;
  return publicKeyToAddress(normalized);
}

function parseCastUint(stdout, label) {
  const value = stdout.trim();
  const firstToken = value.split(/\s+/u)[0] ?? '';
  if (/^0x[0-9a-f]+$/iu.test(firstToken) || /^(0|[1-9][0-9]*)$/u.test(firstToken)) {
    return BigInt(firstToken);
  }
  throw new Error(`${label} was not a uint value: ${value}`);
}

async function waitForSolanaTransaction(rpcUrl, signature) {
  const connection = new Connection(rpcUrl, 'confirmed');
  return waitUntil(
    `Solana transaction ${signature}`,
    async () =>
      connection.getTransaction(signature, {
        commitment: 'confirmed',
        maxSupportedTransactionVersion: 0,
      }),
    30_000,
    1_000,
  );
}

function solanaTxIncludesProgram(tx, programId) {
  const message = tx.transaction.message;
  const accountKeys = message.staticAccountKeys ?? message.accountKeys ?? [];
  const keys = accountKeys.map((key) => {
    if (typeof key === 'string') {
      return key;
    }
    if (key.pubkey) {
      return key.pubkey.toBase58();
    }
    return key.toBase58();
  });
  return keys.includes(programId);
}

async function startManualSolanaTransfer({ agentAuthToken, agentKeyId, rpcUrl, mint, recipient }) {
  const args = [
    'exec',
    'tsx',
    'src/cli.ts',
    'transfer-spl',
    '--network',
    'solana-devnet',
    '--mint',
    mint,
    '--to',
    recipient,
    '--amount',
    '1',
    '--broadcast',
    '--rpc-url',
    rpcUrl,
    '--compute-unit-limit',
    '60000',
    '--compute-unit-price-micro-lamports',
    '5',
    '--agent-key-id',
    agentKeyId,
    '--agent-auth-token-stdin',
    '--daemon-socket',
    daemonSocket,
    '--json',
  ];
  const child = spawn(pnpm, args, {
    cwd: repoRoot,
    env: envBase,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });
  child.stdin.end(`${agentAuthToken}\n`);
  return {
    child,
    get stderr() {
      return stderr;
    },
    done: new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error(`manual transfer timed out\nstdout:\n${stdout}\nstderr:\n${stderr}`));
      }, 120_000);
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code === 0) {
          resolve(parseJson(stdout, 'manual transfer'));
        } else {
          reject(
            new Error(
              `manual transfer failed with exit code ${code}\nstdout:\n${stdout}\nstderr:\n${stderr}`,
            ),
          );
        }
      });
      child.on('error', reject);
    }),
  };
}

function findPendingManualApproval(requests) {
  assert(
    Array.isArray(requests),
    `manual approval list was not an array: ${JSON.stringify(requests)}`,
  );
  return requests.find((request) => request?.status === 'pending');
}

async function verifyTuiInTmux(adminBin) {
  tmuxSession = `agentpay-live-e2e-${process.pid}`;
  await run('tmux', [
    'new-session',
    '-d',
    '-s',
    tmuxSession,
    '-x',
    '120',
    '-y',
    '40',
    'env',
    `AGENTPAY_HOME=${agentpayHome}`,
    adminBin,
    '--daemon-socket',
    daemonSocket,
    'tui',
  ]);
  await new Promise((resolve) => setTimeout(resolve, 500));
  await run('tmux', ['send-keys', '-t', tmuxSession, vaultPassword, 'Enter']);
  await new Promise((resolve) => setTimeout(resolve, 2_500));
  const capture = await run('tmux', ['capture-pane', '-p', '-t', tmuxSession], {
    timeoutMs: 10_000,
  });
  await run('tmux', ['send-keys', '-t', tmuxSession, 'q'], { timeoutMs: 10_000 });
  await run('tmux', ['kill-session', '-t', tmuxSession], {
    allowFailure: true,
    timeoutMs: 10_000,
  });
  tmuxSession = undefined;
  const pane = capture.stdout;
  assert(
    /AgentPay|Manual Approval|Token|Policy|Bootstrap/iu.test(pane),
    `TUI pane did not render expected content:\n${pane}`,
  );
  return pane.split('\n').slice(0, 8).join('\n');
}

function writeSolidityFixture(filePath) {
  fs.writeFileSync(
    filePath,
    `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockERC20 {
    string public name = "Live AgentPay Token";
    string public symbol = "LAPT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint256 supply) {
        totalSupply = supply;
        balanceOf[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
`,
    { mode: 0o600 },
  );
}

async function main() {
  [solana, solanaKeygen, solanaTestValidator, splToken, anvil, forge, cast].forEach(
    ensureExecutable,
  );
  fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
  fs.mkdirSync(binDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(logsDir, { recursive: true, mode: 0o700 });
  await runSudo(['mkdir', '-p', rootStateDir, rootRunDir], {
    label: 'sudo mkdir isolated daemon directories',
  });
  await runSudo(['chown', 'root:wheel', rootStateDir, rootRunDir], {
    label: 'sudo chown isolated daemon directories',
  });
  await runSudo(['chmod', '700', rootStateDir], {
    label: 'sudo chmod isolated daemon state directory',
  });
  await runSudo(['chmod', '755', rootRunDir], {
    label: 'sudo chmod isolated daemon run directory',
  });

  const daemonBin = copyDebugBinary('agentpay-daemon');
  const adminBin = copyDebugBinary('agentpay-admin');
  copyDebugBinary('agentpay-agent');

  const solanaRpcPort = await freePort();
  const solanaFaucetPort = await freePort();
  const anvilPort = await freePort();
  const solanaRpcUrl = `http://127.0.0.1:${solanaRpcPort}`;
  const anvilRpcUrl = `http://127.0.0.1:${anvilPort}`;

  startProcess('solana-test-validator', solanaTestValidator, [
    '--ledger',
    ledgerDir,
    '--reset',
    '--quiet',
    '--bind-address',
    '127.0.0.1',
    '--rpc-port',
    String(solanaRpcPort),
    '--faucet-port',
    String(solanaFaucetPort),
  ]);
  await waitUntil('Solana test validator', async () => {
    const result = await run(solana, ['--url', solanaRpcUrl, 'cluster-version'], {
      allowFailure: true,
      timeoutMs: 10_000,
    });
    return result.code === 0;
  });

  startProcess('anvil', anvil, [
    '--host',
    '127.0.0.1',
    '--port',
    String(anvilPort),
    '--chain-id',
    '31337',
    '--silent',
  ]);
  await waitUntil('Anvil', async () => {
    const result = await run(cast, ['chain-id', '--rpc-url', anvilRpcUrl], {
      allowFailure: true,
      timeoutMs: 10_000,
    });
    return result.code === 0 && result.stdout.trim() === '31337';
  });

  const funderKeypair = path.join(tempRoot, 'solana-funder.json');
  const recipientSolanaKeypair = path.join(tempRoot, 'solana-recipient.json');
  const solanaConfig = path.join(tempRoot, 'solana-cli.yml');
  await run(solanaKeygen, ['new', '--no-bip39-passphrase', '--force', '--outfile', funderKeypair], {
    timeoutMs: 30_000,
  });
  await run(
    solanaKeygen,
    ['new', '--no-bip39-passphrase', '--force', '--outfile', recipientSolanaKeypair],
    {
      timeoutMs: 30_000,
    },
  );
  const funderPubkey = (
    await run(solanaKeygen, ['pubkey', funderKeypair], { timeoutMs: 10_000 })
  ).stdout.trim();
  const recipientSolanaOwner = (
    await run(solanaKeygen, ['pubkey', recipientSolanaKeypair], { timeoutMs: 10_000 })
  ).stdout.trim();
  await run(solana, ['--url', solanaRpcUrl, 'airdrop', '100', funderPubkey], {
    timeoutMs: 60_000,
  });
  await run(
    solana,
    ['--config', solanaConfig, 'config', 'set', '--url', solanaRpcUrl, '--keypair', funderKeypair],
    {
      timeoutMs: 30_000,
    },
  );

  const splMint = await splAddress(
    [
      'create-token',
      '-C',
      solanaConfig,
      '--fee-payer',
      funderKeypair,
      '--decimals',
      '6',
      '--output',
      'json',
    ],
    'create SPL token',
  );
  const token2022Mint = await splAddress(
    [
      'create-token',
      '-C',
      solanaConfig,
      '--fee-payer',
      funderKeypair,
      '--program-2022',
      '--decimals',
      '6',
      '--transfer-fee-basis-points',
      '100',
      '--transfer-fee-maximum-fee',
      '1',
      '--output',
      'json',
    ],
    'create Token-2022 fee token',
  );

  const solidityPath = path.join(tempRoot, 'MockERC20.sol');
  writeSolidityFixture(solidityPath);
  const forgeOutput = await run(
    forge,
    [
      'create',
      `${solidityPath}:MockERC20`,
      '--rpc-url',
      anvilRpcUrl,
      '--private-key',
      anvilPrivateKey,
      '--broadcast',
      '--constructor-args',
      '1000000000000000000000000',
    ],
    { timeoutMs: 120_000 },
  );
  const deployed = /Deployed to:\s*(0x[a-fA-F0-9]{40})/u.exec(forgeOutput.stdout);
  assert(
    deployed,
    `forge did not report deployed contract:\n${forgeOutput.stdout}\n${forgeOutput.stderr}`,
  );
  const erc20 = deployed[1];
  const evmRecipient = '0x0000000000000000000000000000000000000a11';
  const evmSpender = '0x0000000000000000000000000000000000000b22';

  const config = {
    daemonSocket,
    stateFile,
    rustBinDir: binDir,
    chainName: 'local-anvil',
    chainId: 31337,
    rpcUrl: anvilRpcUrl,
    chains: {
      'local-anvil': {
        chainId: 31337,
        name: 'local-anvil',
        family: 'evm',
        rpcUrl: anvilRpcUrl,
      },
      'solana-devnet': {
        chainId: 900000002,
        name: 'solana-devnet',
        family: 'solana',
        rpcUrl: solanaRpcUrl,
      },
    },
    tokens: {
      liveeth: {
        symbol: 'ETH',
        chains: {
          'local-anvil': {
            chainId: 31337,
            isNative: true,
            decimals: 18,
            defaultPolicy: {
              perTxAmountDecimal: '1',
              dailyAmountDecimal: '5',
              weeklyAmountDecimal: '20',
              maxGasPerChainWei: '1000000000000000000',
              perTxMaxFeePerGasWei: '100000000000',
              perTxMaxPriorityFeePerGasWei: '100000000000',
            },
          },
        },
      },
      liverc20: {
        symbol: 'LAPT',
        chains: {
          'local-anvil': {
            chainId: 31337,
            isNative: false,
            address: erc20,
            decimals: 18,
            defaultPolicy: {
              perTxAmountDecimal: '100',
              dailyAmountDecimal: '200',
              weeklyAmountDecimal: '1000',
              maxGasPerChainWei: '1000000000000000000',
              perTxMaxFeePerGasWei: '100000000000',
              perTxMaxPriorityFeePerGasWei: '100000000000',
            },
          },
        },
      },
      livesol: {
        symbol: 'SOL',
        chains: {
          'solana-devnet': {
            chainId: 900000002,
            isNative: true,
            decimals: 9,
            defaultPolicy: {
              perTxAmountDecimal: '1',
              dailyAmountDecimal: '5',
              weeklyAmountDecimal: '20',
            },
          },
        },
      },
      livespl: {
        symbol: 'LSPL',
        chains: {
          'solana-devnet': {
            chainId: 900000002,
            isNative: false,
            address: splMint,
            decimals: 6,
            defaultPolicy: {
              perTxAmountDecimal: '2',
              dailyAmountDecimal: '2',
              weeklyAmountDecimal: '20',
            },
          },
        },
      },
      live2022: {
        symbol: 'L22',
        manualApprovalPolicies: [
          {
            priority: 1,
            minAmountDecimal: '1',
            maxAmountDecimal: '1',
          },
        ],
        chains: {
          'solana-devnet': {
            chainId: 900000002,
            isNative: false,
            address: token2022Mint,
            decimals: 6,
            defaultPolicy: {
              perTxAmountDecimal: '5',
              dailyAmountDecimal: '5',
              weeklyAmountDecimal: '20',
            },
          },
        },
      },
    },
  };
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });

  startProcess(
    'agentpay-daemon',
    'sudo',
    [
      '-n',
      daemonBin,
      '--non-interactive',
      '--vault-password-stdin',
      '--state-file',
      stateFile,
      '--daemon-socket',
      daemonSocket,
      '--signer-backend',
      'software',
      '--allow-admin-euid',
      String(process.getuid?.() ?? 0),
      '--allow-agent-euid',
      String(process.getuid?.() ?? 0),
    ],
    { stdin: `${vaultPassword}\n` },
  );
  let daemonReadyDiagnostics = 0;
  await waitUntil('AgentPay daemon', async () => {
    const result = await run(adminBin, adminArgs(['list-policies']), {
      stdin: `${vaultPassword}\n`,
      allowFailure: true,
      timeoutMs: 10_000,
    });
    if (result.code !== 0 && daemonReadyDiagnostics < 3) {
      daemonReadyDiagnostics += 1;
      log(
        `daemon readiness probe failed: code=${result.code}; stdout=${result.stdout.trim().slice(0, 400)}; stderr=${result.stderr.trim().slice(0, 400)}`,
      );
    }
    return result.code === 0;
  });

  const bootstrap = await runAdminJson(adminBin, [
    'bootstrap',
    '--from-shared-config',
    '--print-agent-auth-token',
  ]);
  const agentAuthToken = bootstrapField(bootstrap, 'agent_auth_token', 'agentAuthToken');
  const agentKeyId = bootstrapField(bootstrap, 'agent_key_id', 'agentKeyId');
  const vaultPublicKey = bootstrapField(bootstrap, 'vault_public_key', 'vaultPublicKey');
  const solanaPublicKey = bootstrapField(bootstrap, 'solana_public_key', 'solanaPublicKey');
  assert(agentAuthToken && agentAuthToken !== '<redacted>', 'bootstrap did not return agent token');
  assert(agentKeyId, 'bootstrap did not return agent key id');
  assert(vaultPublicKey, 'bootstrap did not return vault public key');
  assert(solanaPublicKey, 'bootstrap did not return Solana public key');
  const evmWallet = evmAddressFromPublicKey(vaultPublicKey);
  const solanaWallet = solanaAddressFromHex(solanaPublicKey);

  config.agentKeyId = agentKeyId;
  config.wallet = {
    vaultKeyId: bootstrapField(bootstrap, 'vault_key_id', 'vaultKeyId'),
    algorithm: bootstrapField(bootstrap, 'vault_key_algorithm', 'vaultKeyAlgorithm') ?? 'secp256k1',
    vaultPublicKey,
    address: evmWallet,
    solanaPublicKey,
    solanaAddress: solanaWallet,
    agentKeyId,
    policyAttachment: bootstrapField(bootstrap, 'policy_attachment', 'policyAttachment'),
    attachedPolicyIds: bootstrapField(bootstrap, 'attached_policy_ids', 'attachedPolicyIds'),
    policyNote: bootstrapField(bootstrap, 'policy_note', 'policyNote'),
  };
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });

  await run(
    cast,
    [
      'send',
      evmWallet,
      '--value',
      '10ether',
      '--rpc-url',
      anvilRpcUrl,
      '--private-key',
      anvilPrivateKey,
    ],
    {
      timeoutMs: 60_000,
    },
  );
  await run(
    cast,
    [
      'send',
      erc20,
      'transfer(address,uint256)',
      evmWallet,
      '1000000000000000000000',
      '--rpc-url',
      anvilRpcUrl,
      '--private-key',
      anvilPrivateKey,
    ],
    { timeoutMs: 60_000 },
  );
  await run(solana, ['--url', solanaRpcUrl, 'airdrop', '100', solanaWallet], {
    timeoutMs: 60_000,
  });
  const agentSplAta = associatedTokenAddress(splMint, solanaWallet, TOKEN_PROGRAM_ID);
  await splJson(
    [
      'create-account',
      '-C',
      solanaConfig,
      '--fee-payer',
      funderKeypair,
      splMint,
      '--owner',
      solanaWallet,
      '--output',
      'json',
    ],
    'create agent SPL ATA',
  );
  await splJson(
    [
      'create-account',
      '-C',
      solanaConfig,
      '--fee-payer',
      funderKeypair,
      splMint,
      '--owner',
      recipientSolanaOwner,
      '--output',
      'json',
    ],
    'create recipient SPL ATA',
  );
  const agent2022Ata = associatedTokenAddress(token2022Mint, solanaWallet, TOKEN_2022_PROGRAM_ID);
  await splJson(
    [
      'create-account',
      '-C',
      solanaConfig,
      '--fee-payer',
      funderKeypair,
      '--program-2022',
      token2022Mint,
      '--owner',
      solanaWallet,
      '--output',
      'json',
    ],
    'create agent Token-2022 ATA',
  );
  await splJson(
    [
      'create-account',
      '-C',
      solanaConfig,
      '--fee-payer',
      funderKeypair,
      '--program-2022',
      token2022Mint,
      '--owner',
      recipientSolanaOwner,
      '--output',
      'json',
    ],
    'create recipient Token-2022 ATA',
  );
  await splJson(
    [
      'mint',
      '-C',
      solanaConfig,
      '--fee-payer',
      funderKeypair,
      splMint,
      '100',
      agentSplAta,
      '--output',
      'json',
    ],
    'mint SPL',
  );
  await splJson(
    [
      'mint',
      '-C',
      solanaConfig,
      '--fee-payer',
      funderKeypair,
      '--program-2022',
      token2022Mint,
      '100',
      agent2022Ata,
      '--output',
      'json',
    ],
    'mint Token-2022',
  );

  const walletProfile = await runJson(pnpm, ['exec', 'tsx', 'src/cli.ts', 'wallet', '--json'], {
    env: envBase,
    timeoutMs: 120_000,
  });
  assert(walletProfile.address === evmWallet, 'wallet profile did not show EVM address');
  assert(
    walletProfile.solanaAddress === solanaWallet,
    'wallet profile did not show Solana address',
  );

  const solTransfer = await runAgentpayJson(
    [
      'transfer-sol',
      '--network',
      'solana-devnet',
      '--to',
      recipientSolanaOwner,
      '--amount',
      '0.1',
      '--broadcast',
      '--rpc-url',
      solanaRpcUrl,
      '--compute-unit-limit',
      '50000',
      '--compute-unit-price-micro-lamports',
      '1',
    ],
    agentAuthToken,
    { agentKeyId },
  );
  assert(solTransfer.network_tx_id, 'SOL transfer did not broadcast');
  const solTx = await waitForSolanaTransaction(solanaRpcUrl, solTransfer.network_tx_id);
  assert(
    solanaTxIncludesProgram(solTx, ComputeBudgetProgram.programId.toBase58()),
    'SOL transfer did not include the Compute Budget program',
  );

  const splTransfer = await runAgentpayJson(
    [
      'transfer-spl',
      '--network',
      'solana-devnet',
      '--mint',
      splMint,
      '--to',
      recipientSolanaOwner,
      '--amount',
      '1',
      '--broadcast',
      '--rpc-url',
      solanaRpcUrl,
      '--compute-unit-limit',
      '60000',
      '--compute-unit-price-micro-lamports',
      '2',
    ],
    agentAuthToken,
    { agentKeyId },
  );
  assert(splTransfer.network_tx_id, 'SPL transfer did not broadcast');
  assert(
    splTransfer.transferInstruction === 'transfer_checked',
    'SPL transfer did not use transfer_checked',
  );
  const splTx = await waitForSolanaTransaction(solanaRpcUrl, splTransfer.network_tx_id);
  assert(
    solanaTxIncludesProgram(splTx, ComputeBudgetProgram.programId.toBase58()),
    'SPL transfer did not include the Compute Budget program',
  );

  const manualTransfer = await startManualSolanaTransfer({
    agentAuthToken,
    agentKeyId,
    rpcUrl: solanaRpcUrl,
    mint: token2022Mint,
    recipient: recipientSolanaOwner,
  });
  const pendingRequest = await waitUntil(
    'manual approval request',
    async () =>
      findPendingManualApproval(
        await runAdminJson(adminBin, ['list-manual-approval-requests'], {
          timeoutMs: 10_000,
        }),
      ),
    45_000,
    1_000,
  );
  await runAdminJson(adminBin, [
    'approve-manual-approval-request',
    '--approval-request-id',
    pendingRequest.id,
    // stdin carries the vault password, so the Rust admin cannot prompt for confirmation.
    '--yes',
  ]);
  const token2022Transfer = await manualTransfer.done;
  assert(token2022Transfer.network_tx_id, 'Token-2022 transfer did not broadcast after approval');
  assert(
    token2022Transfer.transferInstruction === 'transfer_checked_with_fee',
    'Token-2022 fee transfer did not use transfer_checked_with_fee',
  );
  assert(token2022Transfer.transferFeeWei !== null, 'Token-2022 fee transfer did not report fee');

  const dailyDeny = await runAgentpay(
    [
      'transfer-spl',
      '--network',
      'solana-devnet',
      '--mint',
      splMint,
      '--to',
      recipientSolanaOwner,
      '--amount',
      '1.5',
      '--rpc-url',
      solanaRpcUrl,
    ],
    agentAuthToken,
    { agentKeyId, allowFailure: true },
  );
  assert(dailyDeny.code !== 0, 'SPL daily-limit transfer unexpectedly succeeded');
  assert(
    /daily|max spending|limit|policy/iu.test(`${dailyDeny.stdout}\n${dailyDeny.stderr}`),
    `SPL daily-limit denial did not mention policy/limit:\n${dailyDeny.stdout}\n${dailyDeny.stderr}`,
  );

  const nativeTransfer = await runAgentpayJson(
    [
      'transfer-native',
      '--network',
      'local-anvil',
      '--to',
      evmRecipient,
      '--amount',
      '0.01',
      '--broadcast',
      '--rpc-url',
      anvilRpcUrl,
      '--max-fee-per-gas-wei',
      '100000000000',
      '--max-priority-fee-per-gas-wei',
      '1000000000',
    ],
    agentAuthToken,
    { agentKeyId },
  );
  assert(nativeTransfer.networkTxHash, 'native EVM transfer did not broadcast');

  const erc20Transfer = await runAgentpayJson(
    [
      'transfer',
      '--network',
      'local-anvil',
      '--token',
      erc20,
      '--to',
      evmRecipient,
      '--amount',
      '1',
      '--broadcast',
      '--rpc-url',
      anvilRpcUrl,
      '--max-fee-per-gas-wei',
      '100000000000',
      '--max-priority-fee-per-gas-wei',
      '1000000000',
    ],
    agentAuthToken,
    { agentKeyId },
  );
  assert(erc20Transfer.networkTxHash, 'ERC20 transfer did not broadcast');

  const approve = await runAgentpayJson(
    [
      'approve',
      '--network',
      'local-anvil',
      '--token',
      erc20,
      '--spender',
      evmSpender,
      '--amount',
      '2',
      '--broadcast',
      '--rpc-url',
      anvilRpcUrl,
      '--max-fee-per-gas-wei',
      '100000000000',
      '--max-priority-fee-per-gas-wei',
      '1000000000',
    ],
    agentAuthToken,
    { agentKeyId },
  );
  assert(approve.networkTxHash, 'ERC20 approve did not broadcast');

  const recipientTokenBalance = parseCastUint(
    (
      await run(
        cast,
        ['call', erc20, 'balanceOf(address)(uint256)', evmRecipient, '--rpc-url', anvilRpcUrl],
        {
          timeoutMs: 30_000,
        },
      )
    ).stdout,
    'recipient token balance',
  );
  assert(recipientTokenBalance === 1_000_000_000_000_000_000n, 'recipient ERC20 balance mismatch');
  const allowance = parseCastUint(
    (
      await run(
        cast,
        [
          'call',
          erc20,
          'allowance(address,address)(uint256)',
          evmWallet,
          evmSpender,
          '--rpc-url',
          anvilRpcUrl,
        ],
        {
          timeoutMs: 30_000,
        },
      )
    ).stdout,
    'spender allowance',
  );
  assert(allowance === 2_000_000_000_000_000_000n, 'ERC20 allowance mismatch');

  const evmDeny = await runAgentpay(
    [
      'transfer',
      '--network',
      'local-anvil',
      '--token',
      erc20,
      '--to',
      evmRecipient,
      '--amount',
      '500',
      '--rpc-url',
      anvilRpcUrl,
    ],
    agentAuthToken,
    { agentKeyId, allowFailure: true },
  );
  assert(evmDeny.code !== 0, 'ERC20 over-limit transfer unexpectedly succeeded');
  assert(
    /per-transaction|per tx|limit|policy/iu.test(`${evmDeny.stdout}\n${evmDeny.stderr}`),
    `ERC20 over-limit denial did not mention policy/limit:\n${evmDeny.stdout}\n${evmDeny.stderr}`,
  );

  const tuiPane = await verifyTuiInTmux(adminBin);

  const result = {
    tempRoot,
    solanaRpcUrl,
    anvilRpcUrl,
    evmWallet,
    solanaWallet,
    mints: {
      splMint,
      token2022Mint,
    },
    erc20,
    checks: {
      walletProfile: true,
      solTransfer: solTransfer.network_tx_id,
      splTransfer: splTransfer.network_tx_id,
      token2022ManualTransfer: token2022Transfer.network_tx_id,
      splDailyPolicyDenied: true,
      evmNativeTransfer: nativeTransfer.networkTxHash,
      evmErc20Transfer: erc20Transfer.networkTxHash,
      evmApprove: approve.networkTxHash,
      evmPolicyDenied: true,
      tuiInTmux: true,
    },
    tuiPreview: tuiPane,
  };
  const resultPath = path.join(tempRoot, 'result.json');
  fs.writeFileSync(resultPath, JSON.stringify(result, null, 2), { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ ok: true, resultPath, ...result }, null, 2)}\n`);
}

async function cleanup() {
  if (tmuxSession) {
    await run('tmux', ['kill-session', '-t', tmuxSession], {
      allowFailure: true,
      timeoutMs: 10_000,
    }).catch(() => {});
  }
  for (const { name, child } of children.reverse()) {
    if (child.exitCode == null && child.signalCode == null) {
      log(`stopping ${name}`);
      child.kill('SIGTERM');
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 1_000));
  for (const { name, child } of children.reverse()) {
    if (child.exitCode == null && child.signalCode == null) {
      log(`killing ${name}`);
      child.kill('SIGKILL');
    }
  }
  if (rootPassword !== undefined) {
    await runSudo(['rm', '-rf', rootStateDir, rootRunDir], {
      allowFailure: true,
      label: 'sudo remove isolated daemon directories',
    }).catch(() => {});
  }
}

main()
  .catch((error) => {
    console.error(error?.stack ?? error);
    process.exitCode = 1;
  })
  .finally(cleanup);
