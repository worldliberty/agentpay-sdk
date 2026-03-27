import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { encodeFunctionData, keccak256, parseTransaction } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const repoRoot = new URL('..', import.meta.url).pathname;
const CLI_PACKAGE_VERSION = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'),
).version;
const AGENT_KEY_ID = '00000000-0000-0000-0000-000000000123';
const ERC20_TOKEN = '0x0000000000000000000000000000000000000abc';
const TO_ADDRESS = '0x0000000000000000000000000000000000000def';

function makeIsolatedHome() {
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-cli-mocked-home-'));
  const agentpayHome = path.join(homeDir, '.agentpay');
  fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
  return { homeDir, agentpayHome };
}

async function closeServer(server) {
  if (!server) {
    return;
  }
  if (typeof server.closeAllConnections === 'function') {
    server.closeAllConnections();
  }
  await new Promise((resolve) => {
    server.close(() => resolve(undefined));
  });
}

function writeExecutable(filePath, body) {
  fs.writeFileSync(filePath, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
}

const ROOT_HARNESS = [
  "import fs from 'node:fs';",
  'process.geteuid = () => 0;',
  'if (process.env.AGENTPAY_TEST_PLATFORM) {',
  "  Object.defineProperty(process, 'platform', { configurable: true, value: process.env.AGENTPAY_TEST_PLATFORM });",
  '}',
  "if (process.env.AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP === '1') {",
  '  const originalLstatSync = fs.lstatSync;',
  '  const originalStatSync = fs.statSync;',
  '  const originalFstatSync = fs.fstatSync;',
  '  const withRootUid = (stats) => {',
  "    if (!stats || typeof stats !== 'object') {",
  '      return stats;',
  '    }',
  '    return new Proxy(stats, {',
  '      get(target, key, receiver) {',
  "        if (key === 'uid') {",
  '          return 0;',
  '        }',
  '        return Reflect.get(target, key, receiver);',
  '      },',
  '    });',
  '  };',
  '  fs.lstatSync = (...args) => {',
  '    return withRootUid(originalLstatSync(...args));',
  '  };',
  '  fs.statSync = (...args) => {',
  '    return withRootUid(originalStatSync(...args));',
  '  };',
  '  fs.fstatSync = (...args) => {',
  '    return withRootUid(originalFstatSync(...args));',
  '  };',
  '}',
  "if (process.env.AGENTPAY_TEST_FAST_TIME === '1') {",
  '  let fakeNow = 0;',
  '  Date.now = () => {',
  '    fakeNow += 31_000;',
  '    return fakeNow;',
  '  };',
  '}',
  "process.argv = ['node', 'src/cli.ts', ...JSON.parse(process.env.AGENTPAY_CLI_ARGS_JSON)];",
  "await import('./src/cli.ts');",
].join('\n');

function runCli(args, { homeDir, env = {}, input, assumeRoot = false, sudoWrapped = false }) {
  const agentpayHome = path.join(homeDir, '.agentpay');
  const baseEnv = {
    ...process.env,
    HOME: homeDir,
    AGENTPAY_HOME: agentpayHome,
    ...env,
  };

  if (!assumeRoot) {
    return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
      cwd: repoRoot,
      env: baseEnv,
      encoding: 'utf8',
      input,
    });
  }

  const rootEnv = {
    ...baseEnv,
    AGENTPAY_CLI_ARGS_JSON: JSON.stringify(args),
    AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP: baseEnv.AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP ?? '1',
  };
  delete rootEnv.SUDO_UID;
  delete rootEnv.SUDO_GID;
  if (sudoWrapped) {
    if (typeof process.getuid === 'function') {
      rootEnv.SUDO_UID = String(process.getuid());
    }
    if (typeof process.getgid === 'function') {
      rootEnv.SUDO_GID = String(process.getgid());
    }
  }

  return spawnSync(
    process.execPath,
    ['--import', 'tsx', '--input-type=module', '-e', ROOT_HARNESS],
    {
      cwd: repoRoot,
      env: {
        ...baseEnv,
        AGENTPAY_CLI_ARGS_JSON: JSON.stringify(args),
        AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP: '1',
      },
      encoding: 'utf8',
      input,
    },
  );
}

function runCliAsync(args, { homeDir, env = {}, input, assumeRoot = false, sudoWrapped = false }) {
  const agentpayHome = path.join(homeDir, '.agentpay');
  const baseEnv = {
    ...process.env,
    HOME: homeDir,
    AGENTPAY_HOME: agentpayHome,
    ...env,
  };

  const spawnArgs = !assumeRoot
    ? ['--import', 'tsx', 'src/cli.ts', ...args]
    : ['--import', 'tsx', '--input-type=module', '-e', ROOT_HARNESS];

  const runEnv = !assumeRoot
    ? baseEnv
    : {
        ...baseEnv,
        AGENTPAY_CLI_ARGS_JSON: JSON.stringify(args),
        AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP: '1',
      };

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, spawnArgs, {
      cwd: repoRoot,
      env: runEnv,
      stdio: 'pipe',
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
    child.on('close', (status, signal) => {
      resolve({
        status:
          status ??
          (typeof signal === 'string' && typeof os.constants.signals[signal] === 'number'
            ? 128 + os.constants.signals[signal]
            : 1),
        stdout,
        stderr,
      });
    });

    if (input !== undefined) {
      child.stdin?.end(input);
      return;
    }
    child.stdin?.end();
  });
}

function combinedOutput(result) {
  return `${result.stdout ?? ''}${result.stderr ?? ''}`;
}

function writeConfig(agentpayHome, config) {
  fs.writeFileSync(path.join(agentpayHome, 'config.json'), `${JSON.stringify(config, null, 2)}\n`);
}

function writePrivateJson(targetPath, payload) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(targetPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(targetPath, 0o600);
}

function writeBootstrapOutput(targetPath, overrides = {}) {
  writePrivateJson(targetPath, {
    lease_id: 'lease-cli-e2e',
    lease_expires_at: '2099-01-01T00:00:00Z',
    per_tx_policy_id: 'policy-per-tx',
    daily_policy_id: 'policy-daily',
    weekly_policy_id: 'policy-weekly',
    per_tx_max_wei: '1',
    daily_max_wei: '2',
    weekly_max_wei: '3',
    vault_key_id: 'vault-key-cli-e2e',
    vault_public_key: '03abcdef',
    agent_key_id: AGENT_KEY_ID,
    agent_auth_token: 'imported-agent-token',
    network_scope: 'all networks',
    asset_scope: 'all assets',
    recipient_scope: 'all recipients',
    policy_attachment: 'policy_set',
    policy_note: 'cli e2e bootstrap note',
    ...overrides,
  });
}

function installMockSecurityCommand(homeDir) {
  const binDir = path.join(homeDir, 'mock-bin');
  fs.mkdirSync(binDir, { recursive: true, mode: 0o700 });
  const dbPath = path.join(homeDir, 'mock-security-db.json');
  const securityPath = path.join(binDir, 'security');
  const script = `#!/usr/bin/env node
const fs = require('node:fs');

const dbPath = process.env.AGENTPAY_SECURITY_DB;
if (!dbPath) {
  console.error('missing AGENTPAY_SECURITY_DB');
  process.exit(1);
}

const args = process.argv.slice(2);
const command = args[0];

function valueFor(flag) {
  const index = args.indexOf(flag);
  if (index < 0 || index + 1 >= args.length) {
    return undefined;
  }
  return args[index + 1];
}

function readDb() {
  try {
    return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  } catch {
    return {};
  }
}

function writeDb(payload) {
  fs.writeFileSync(dbPath, JSON.stringify(payload), 'utf8');
}

const service = valueFor('-s') ?? '';
const account = valueFor('-a') ?? '';
const key = service + '\\u0000' + account;

if (command === 'add-generic-password') {
  const encoded = valueFor('-X') ?? '';
  const db = readDb();
  db[key] = Buffer.from(encoded, 'hex').toString('utf8');
  writeDb(db);
  process.exit(0);
}

if (command === 'find-generic-password') {
  if (process.env.AGENTPAY_SECURITY_FAIL_FIND === '1') {
    process.stderr.write('mock keychain backend failure');
    process.exit(1);
  }
  const db = readDb();
  if (!(key in db)) {
    process.stderr.write('The specified item could not be found in the keychain.');
    process.exit(44);
  }
  process.stdout.write(String(db[key]));
  process.exit(0);
}

if (command === 'delete-generic-password') {
  const db = readDb();
  if (!(key in db)) {
    process.stderr.write('The specified item could not be found in the keychain.');
    process.exit(44);
  }
  delete db[key];
  writeDb(db);
  process.exit(0);
}

process.stderr.write('unsupported security command');
process.exit(1);
`;
  fs.writeFileSync(securityPath, script, { mode: 0o700 });
  return {
    pathEnv: `${binDir}:${process.env.PATH ?? ''}`,
    dbPath,
  };
}

function startUnixSocket(socketPath) {
  const server = net.createServer();
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => resolve(server));
  });
}

function startMockRpcServer({ txHash, from, to, methodOverrides = {}, methodErrors = {} }) {
  const blockHash = `0x${'1'.repeat(64)}`;
  const logsBloom = `0x${'0'.repeat(512)}`;
  const receipt = {
    transactionHash: txHash,
    transactionIndex: '0x0',
    blockHash,
    blockNumber: '0x64',
    from,
    to,
    cumulativeGasUsed: '0x5208',
    gasUsed: '0x5208',
    contractAddress: null,
    logs: [],
    logsBloom,
    status: '0x1',
    type: '0x2',
    effectiveGasPrice: '0x3b9aca00',
  };
  const tx = {
    blockHash,
    blockNumber: '0x64',
    from,
    gas: '0x5208',
    hash: txHash,
    input: '0x',
    nonce: '0x1',
    to,
    transactionIndex: '0x0',
    value: '0x0',
    type: '0x2',
    chainId: '0x1',
    maxFeePerGas: '0x3b9aca00',
    maxPriorityFeePerGas: '0x3b9aca00',
    accessList: [],
    v: '0x1',
    r: `0x${'2'.repeat(64)}`,
    s: `0x${'3'.repeat(64)}`,
    yParity: '0x1',
  };
  const block = {
    number: '0x64',
    hash: blockHash,
    parentHash: `0x${'0'.repeat(64)}`,
    nonce: '0x0000000000000000',
    sha3Uncles: `0x${'0'.repeat(64)}`,
    logsBloom,
    transactionsRoot: `0x${'0'.repeat(64)}`,
    stateRoot: `0x${'0'.repeat(64)}`,
    receiptsRoot: `0x${'0'.repeat(64)}`,
    miner: from,
    difficulty: '0x0',
    totalDifficulty: '0x0',
    extraData: '0x',
    size: '0x1',
    gasLimit: '0x1c9c380',
    gasUsed: '0x5208',
    timestamp: '0x1',
    transactions: [],
    uncles: [],
    baseFeePerGas: '0x3b9aca00',
  };

  const handleMethod = (method, params) => {
    if (Object.hasOwn(methodErrors, method)) {
      const configured = methodErrors[method];
      throw configured instanceof Error ? configured : new Error(String(configured));
    }
    if (Object.hasOwn(methodOverrides, method)) {
      const override = methodOverrides[method];
      return typeof override === 'function' ? override(params) : override;
    }

    switch (method) {
      case 'eth_chainId':
        return '0x1';
      case 'eth_blockNumber':
        return '0x64';
      case 'eth_getBlockByNumber':
        return block;
      case 'eth_getBalance':
        return '0xde0b6b3a7640000';
      case 'eth_getTransactionCount':
        return '0x1';
      case 'eth_estimateGas':
        return '0x5208';
      case 'eth_gasPrice':
        return '0x3b9aca00';
      case 'eth_maxPriorityFeePerGas':
        return '0x3b9aca00';
      case 'eth_feeHistory':
        return {
          oldestBlock: '0x63',
          baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'],
          gasUsedRatio: [0.5],
          reward: [['0x3b9aca00']],
        };
      case 'eth_getTransactionByHash':
        return tx;
      case 'eth_getTransactionReceipt':
        return receipt;
      case 'eth_getCode':
        return '0x';
      case 'eth_sendRawTransaction':
        return txHash;
      case 'eth_call':
        return `0x${'0'.repeat(63)}a`;
      default:
        throw new Error(`unsupported method: ${method}`);
    }
  };

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      const payload = JSON.parse(body);
      const calls = Array.isArray(payload) ? payload : [payload];
      const responses = calls.map((call) => {
        try {
          return {
            jsonrpc: '2.0',
            id: call.id ?? null,
            result: handleMethod(call.method, call.params),
          };
        } catch (error) {
          return {
            jsonrpc: '2.0',
            id: call.id ?? null,
            error: { code: -32603, message: String(error?.message ?? error) },
          };
        }
      });
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(Array.isArray(payload) ? responses : responses[0]));
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        server,
        rpcUrl: `http://127.0.0.1:${address.port}`,
      });
    });
  });
}

test('root-mode local admin commands mutate chain/token config successfully', () => {
  const { homeDir } = makeIsolatedHome();

  try {
    const addChain = runCli(
      ['admin', 'chain', 'add', 'local', '--chain-id', '31337', '--name', 'Local', '--json'],
      { homeDir, assumeRoot: true },
    );
    assert.equal(addChain.status, 0);

    const switchChain = runCli(
      [
        'admin',
        'chain',
        'switch',
        'local',
        '--rpc-url',
        'http://127.0.0.1:8545',
        '--save',
        '--json',
      ],
      { homeDir, assumeRoot: true },
    );
    assert.equal(switchChain.status, 0);

    const setToken = runCli(
      [
        'admin',
        'token',
        'set-chain',
        'mock',
        'local',
        '--symbol',
        'MOCK',
        '--chain-id',
        '31337',
        '--address',
        ERC20_TOKEN,
        '--decimals',
        '18',
        '--per-tx',
        '1',
        '--daily',
        '2',
        '--weekly',
        '3',
        '--json',
      ],
      { homeDir, assumeRoot: true },
    );
    assert.equal(setToken.status, 0);

    const removeTokenChain = runCli(['admin', 'token', 'remove-chain', 'mock', 'local', '--json'], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(removeTokenChain.status, 0);

    const removeToken = runCli(['admin', 'token', 'remove', 'mock', '--json'], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(removeToken.status, 0);

    const removeChain = runCli(['admin', 'chain', 'remove', 'local', '--json'], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(removeChain.status, 0);

    const configSet = runCli(['config', 'set', 'chainId', '1'], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(configSet.status, 0);

    const configUnset = runCli(['config', 'unset', 'chainId'], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(configUnset.status, 0);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('rpc balance native json uses a chain-neutral formatted field', async () => {
  const { homeDir } = makeIsolatedHome();
  const txHash = keccak256('0x12');
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    txHash,
    from: TO_ADDRESS,
    to: ERC20_TOKEN,
  });

  try {
    const result = await runCliAsync(
      ['rpc', 'balance', '--address', TO_ADDRESS, '--rpc-url', rpcUrl, '--json'],
      { homeDir },
    );
    assert.equal(result.status, 0, combinedOutput(result));

    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.kind, 'native');
    assert.equal(parsed.balanceWei, '1000000000000000000');
    assert.equal(parsed.formatted, '1');
    assert.equal('formattedEth' in parsed, false);
  } finally {
    rpcServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('root version flags print the installed CLI version without creating AgentPay home', () => {
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-cli-version-'));
  const agentpayHome = path.join(homeDir, '.agentpay');

  try {
    const longFlag = runCli(['--version'], { homeDir });
    assert.equal(longFlag.status, 0, combinedOutput(longFlag));
    assert.equal(longFlag.stdout.trim(), CLI_PACKAGE_VERSION);
    assert.equal(fs.existsSync(agentpayHome), false);

    const shortFlag = runCli(['-V'], { homeDir });
    assert.equal(shortFlag.status, 0, combinedOutput(shortFlag));
    assert.equal(shortFlag.stdout.trim(), CLI_PACKAGE_VERSION);
    assert.equal(fs.existsSync(agentpayHome), false);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('admin passthrough uses rust binary for help and enforces admin auth for unknown subcommands', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'admin.sock');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketServer = await startUnixSocket(socketPath);

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-admin'),
      [
        'if [ "$1" = "--help" ] || [ "$1" = "help" ]; then',
        '  echo "mock-admin-help"',
        '  exit 0',
        'fi',
        'echo "mock-admin-passthrough:$*"',
        'exit 7',
      ].join('\n'),
    );

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
    });

    const adminHelp = runCli(['admin'], { homeDir, assumeRoot: true });
    assert.equal(adminHelp.status, 0);
    assert.match(adminHelp.stdout, /mock-admin-help/u);

    const passthrough = runCli(['admin', 'passthrough-unknown'], { homeDir, assumeRoot: true });
    assert.equal(passthrough.status, 1);
    assert.match(
      combinedOutput(passthrough),
      /agentpay admin commands require --vault-password-stdin or a local TTY/u,
    );

    const blocked = runCli(['admin', 'rotate-agent-auth-token'], { homeDir, assumeRoot: true });
    assert.equal(blocked.status, 1);
    assert.match(combinedOutput(blocked), /config agent-auth rotate/u);
  } finally {
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('admin passthrough lifts trailing --json for add-manual-approval-policy', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'admin.sock');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketServer = await startUnixSocket(socketPath);

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-admin'),
      [
        'if [ "$1" != "--json" ]; then',
        '  echo "missing-leading-json" 1>&2',
        '  exit 9',
        'fi',
        'shift',
        'if [ "$1" != "add-manual-approval-policy" ]; then',
        '  echo "unexpected-command:$1" 1>&2',
        '  exit 8',
        'fi',
        'printf "{\\"command\\":\\"add-manual-approval-policy\\",\\"ok\\":true}"',
      ].join('\n'),
    );

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
    });

    const result = runCli(
      [
        'admin',
        'add-manual-approval-policy',
        '--priority',
        '7',
        '--min-amount-wei',
        '10',
        '--max-amount-wei',
        '20',
        '--allow-native-eth',
        '--network',
        '1',
        '--vault-password-stdin',
        '--json',
      ],
      { homeDir, assumeRoot: true, input: 'test-vault-password\n' },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    assert.deepEqual(JSON.parse(result.stdout), {
      command: 'add-manual-approval-policy',
      ok: true,
    });
  } finally {
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('rpc and agent command success paths run with mocked rpc and rust binaries', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const fromAddress = account.address;
  const txForBroadcast = await account.signTransaction({
    chainId: 1,
    nonce: 1,
    to: TO_ADDRESS,
    gas: 21000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 0n,
    data: '0x',
    type: 'eip1559',
  });
  const parsedSigned = parseTransaction(txForBroadcast);
  const signedTxHash = keccak256(txForBroadcast);
  const transferDataHex = encodeFunctionData({
    abi: [
      {
        type: 'function',
        name: 'transfer',
        stateMutability: 'nonpayable',
        inputs: [
          { name: 'to', type: 'address' },
          { name: 'amount', type: 'uint256' },
        ],
        outputs: [{ name: '', type: 'bool' }],
      },
    ],
    functionName: 'transfer',
    args: [TO_ADDRESS, 1_000_000_000_000_000_000n],
  });
  const approveDataHex = encodeFunctionData({
    abi: [
      {
        type: 'function',
        name: 'approve',
        stateMutability: 'nonpayable',
        inputs: [
          { name: 'spender', type: 'address' },
          { name: 'amount', type: 'uint256' },
        ],
        outputs: [{ name: '', type: 'bool' }],
      },
    ],
    functionName: 'approve',
    args: [TO_ADDRESS, 1_000_000_000_000_000_000n],
  });
  const transferBroadcastRawTx = await account.signTransaction({
    chainId: 1,
    nonce: 1,
    to: ERC20_TOKEN,
    gas: 21000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 0n,
    data: transferDataHex,
    type: 'eip1559',
  });
  const approveBroadcastRawTx = await account.signTransaction({
    chainId: 1,
    nonce: 1,
    to: ERC20_TOKEN,
    gas: 21000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 0n,
    data: approveDataHex,
    type: 'eip1559',
  });
  const transferNativeBroadcastRawTx = await account.signTransaction({
    chainId: 1,
    nonce: 1,
    to: TO_ADDRESS,
    gas: 21000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 1_000_000_000_000_000_000n,
    data: '0x',
    type: 'eip1559',
  });

  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    txHash: signedTxHash,
    from: fromAddress,
    to: TO_ADDRESS,
  });

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    transfer|transfer-native|approve|broadcast)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'if [ -z "$cmd" ]; then cmd="unknown"; fi',
        'printf "{\\"command\\":\\"%s\\",\\"network\\":\\"1\\",\\"asset\\":\\"%s\\",\\"counterparty\\":\\"%s\\",\\"amount_wei\\":\\"1000000000000000000\\",\\"estimated_max_gas_spend_wei\\":\\"21000000000000\\",\\"tx_type\\":\\"0x02\\",\\"delegation_enabled\\":false,\\"signature_hex\\":\\"0x11\\",\\"r_hex\\":\\"%s\\",\\"s_hex\\":\\"%s\\",\\"v\\":%s,\\"raw_tx_hex\\":\\"%s\\",\\"tx_hash_hex\\":\\"%s\\"}" "$cmd" "$AGENTPAY_MOCK_TOKEN" "$AGENTPAY_MOCK_TO" "$AGENTPAY_MOCK_R" "$AGENTPAY_MOCK_S" "$AGENTPAY_MOCK_V" "$AGENTPAY_MOCK_RAW_TX" "$AGENTPAY_MOCK_TX_HASH"',
      ].join('\n'),
    );

    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'echo "admin-help"; exit 0');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 1,
      chainName: 'ETH',
      rpcUrl,
      agentKeyId: AGENT_KEY_ID,
      chains: {
        eth: { chainId: 1, name: 'ETH', rpcUrl },
      },
      wallet: {
        address: fromAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
        attachedPolicyIds: ['policy-per-tx', 'policy-daily', 'policy-weekly', 'policy-gas'],
        policyNote: 'test policy note',
        networkScope: 'all networks',
        assetScope: 'all assets',
        recipientScope: 'all recipients',
      },
      tokens: {
        mockerc20: {
          symbol: 'MCK',
          chains: {
            eth: {
              chainId: 1,
              isNative: false,
              address: ERC20_TOKEN,
              decimals: 18,
            },
          },
        },
        eth: {
          symbol: 'ETH',
          chains: {
            eth: {
              chainId: 1,
              isNative: true,
              decimals: 18,
            },
          },
        },
      },
    });

    const sharedAgentArgs = [
      '--agent-key-id',
      AGENT_KEY_ID,
      '--agent-auth-token',
      'test-agent-auth-token',
      '--allow-legacy-agent-auth-source',
      '--daemon-socket',
      socketPath,
      '--json',
    ];
    const mockEnv = {
      AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
      AGENTPAY_MOCK_TO: TO_ADDRESS,
      AGENTPAY_MOCK_RAW_TX: txForBroadcast,
      AGENTPAY_MOCK_TX_HASH: signedTxHash,
      AGENTPAY_MOCK_R: parsedSigned.r ?? `0x${'2'.repeat(64)}`,
      AGENTPAY_MOCK_S: parsedSigned.s ?? `0x${'3'.repeat(64)}`,
      AGENTPAY_MOCK_V: String(parsedSigned.v ?? 1),
    };
    const envForRawTx = (rawTx) => {
      const parsed = parseTransaction(rawTx);
      return {
        ...mockEnv,
        AGENTPAY_MOCK_RAW_TX: rawTx,
        AGENTPAY_MOCK_TX_HASH: keccak256(rawTx),
        AGENTPAY_MOCK_R: parsed.r ?? `0x${'2'.repeat(64)}`,
        AGENTPAY_MOCK_S: parsed.s ?? `0x${'3'.repeat(64)}`,
        AGENTPAY_MOCK_V: String(parsed.v ?? 1),
      };
    };

    const commands = [
      ['rpc', 'chain', '--rpc-url', rpcUrl, '--json'],
      ['rpc', 'block-number', '--rpc-url', rpcUrl, '--json'],
      ['rpc', 'account', '--address', fromAddress, '--rpc-url', rpcUrl, '--json'],
      ['rpc', 'balance', '--address', fromAddress, '--rpc-url', rpcUrl, '--json'],
      [
        'rpc',
        'balance',
        '--address',
        fromAddress,
        '--token',
        ERC20_TOKEN,
        '--decimals',
        '18',
        '--rpc-url',
        rpcUrl,
        '--json',
      ],
      ['rpc', 'nonce', '--address', fromAddress, '--rpc-url', rpcUrl, '--json'],
      ['rpc', 'fees', '--rpc-url', rpcUrl, '--json'],
      [
        'rpc',
        'gas-estimate',
        '--from',
        fromAddress,
        '--to',
        TO_ADDRESS,
        '--rpc-url',
        rpcUrl,
        '--json',
      ],
      ['rpc', 'tx', '--hash', signedTxHash, '--rpc-url', rpcUrl, '--json'],
      ['rpc', 'receipt', '--hash', signedTxHash, '--rpc-url', rpcUrl, '--json'],
      ['rpc', 'code', '--address', TO_ADDRESS, '--rpc-url', rpcUrl, '--json'],
      ['rpc', 'broadcast-raw', '--raw-tx-hex', txForBroadcast, '--rpc-url', rpcUrl, '--json'],
      [
        'transfer',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--to',
        TO_ADDRESS,
        '--amount',
        '1',
        ...sharedAgentArgs,
      ],
      [
        'transfer-native',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--amount',
        '1',
        ...sharedAgentArgs,
      ],
      [
        'approve',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--spender',
        TO_ADDRESS,
        '--amount',
        '1',
        ...sharedAgentArgs,
      ],
      [
        'broadcast',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        '--max-priority-fee-per-gas-wei',
        '1000000000',
        '--nonce',
        '1',
        ...sharedAgentArgs,
      ],
      [
        'tx',
        'broadcast',
        '--from',
        fromAddress,
        '--to',
        TO_ADDRESS,
        '--network',
        'eth',
        '--rpc-url',
        rpcUrl,
        '--daemon-socket',
        socketPath,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--nonce',
        '1',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        '--max-priority-fee-per-gas-wei',
        '1000000000',
        '--reveal-signature',
        '--json',
      ],
      ['wallet', '--json'],
      ['status', '--json'],
      ['repair', '--json'],
      ['admin', 'chain', 'list', '--json'],
      ['admin', 'chain', 'current', '--json'],
      ['admin', 'token', 'list', '--json'],
      ['admin', 'token', 'show', 'mockerc20', '--json'],
      ['config', 'agent-auth', 'status', '--json'],
    ];

    for (const args of commands) {
      const result = await runCliAsync(args, {
        homeDir,
        env: mockEnv,
      });
      assert.equal(
        result.status,
        0,
        `command failed: ${args.join(' ')}\n${combinedOutput(result)}`,
      );
    }

    const transferBroadcastSuccess = await runCliAsync(
      [
        'transfer',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--to',
        TO_ADDRESS,
        '--amount',
        '1',
        '--broadcast',
        '--rpc-url',
        rpcUrl,
        '--from',
        fromAddress,
        '--nonce',
        '1',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        '--max-priority-fee-per-gas-wei',
        '1000000000',
        '--tx-type',
        '0x02',
        ...sharedAgentArgs,
      ],
      {
        homeDir,
        env: envForRawTx(transferBroadcastRawTx),
      },
    );
    assert.equal(transferBroadcastSuccess.status, 0, combinedOutput(transferBroadcastSuccess));
    assert.equal(
      JSON.parse(transferBroadcastSuccess.stdout).signedTxHash,
      keccak256(transferBroadcastRawTx),
    );
    assert.equal(JSON.parse(transferBroadcastSuccess.stdout).networkTxHash, signedTxHash);

    const transferNativeBroadcastSuccess = await runCliAsync(
      [
        'transfer-native',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--amount',
        '1',
        '--broadcast',
        '--rpc-url',
        rpcUrl,
        '--from',
        fromAddress,
        '--nonce',
        '1',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        '--max-priority-fee-per-gas-wei',
        '1000000000',
        '--tx-type',
        '0x02',
        '--no-wait',
        ...sharedAgentArgs,
      ],
      {
        homeDir,
        env: envForRawTx(transferNativeBroadcastRawTx),
      },
    );
    assert.equal(
      transferNativeBroadcastSuccess.status,
      0,
      combinedOutput(transferNativeBroadcastSuccess),
    );
    assert.equal(
      JSON.parse(transferNativeBroadcastSuccess.stdout).signedTxHash,
      keccak256(transferNativeBroadcastRawTx),
    );
    assert.equal(JSON.parse(transferNativeBroadcastSuccess.stdout).networkTxHash, signedTxHash);

    const approveBroadcastSuccess = await runCliAsync(
      [
        'approve',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--spender',
        TO_ADDRESS,
        '--amount',
        '1',
        '--broadcast',
        '--rpc-url',
        rpcUrl,
        '--from',
        fromAddress,
        '--nonce',
        '1',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        '--max-priority-fee-per-gas-wei',
        '1000000000',
        '--tx-type',
        '0x02',
        '--no-wait',
        ...sharedAgentArgs,
      ],
      {
        homeDir,
        env: envForRawTx(approveBroadcastRawTx),
      },
    );
    assert.equal(approveBroadcastSuccess.status, 0, combinedOutput(approveBroadcastSuccess));
    assert.equal(
      JSON.parse(approveBroadcastSuccess.stdout).signedTxHash,
      keccak256(approveBroadcastRawTx),
    );
    assert.equal(JSON.parse(approveBroadcastSuccess.stdout).networkTxHash, signedTxHash);

    const broadcastSuccess = await runCliAsync(
      [
        'broadcast',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        ...sharedAgentArgs,
      ],
      {
        homeDir,
        env: mockEnv,
      },
    );
    assert.equal(broadcastSuccess.status, 0, combinedOutput(broadcastSuccess));
    assert.equal(JSON.parse(broadcastSuccess.stdout).tx_hash_hex, signedTxHash);

    const expectedFailures = [
      [
        'tx',
        'broadcast',
        '--from',
        fromAddress,
        '--to',
        TO_ADDRESS,
        '--network',
        'eth',
        '--rpc-url',
        rpcUrl,
        '--daemon-socket',
        socketPath,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--no-wait',
        '--json',
      ],
    ];

    for (const args of expectedFailures) {
      const result = await runCliAsync(args, {
        homeDir,
        env: mockEnv,
      });
      assert.notEqual(
        result.status,
        0,
        `command unexpectedly succeeded: ${args.join(' ')}\n${combinedOutput(result)}`,
      );
    }
  } finally {
    rpcServer.close();
    socketServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('admin dispatch covers help passthrough, local help override, daemon block, and bootstrap removal', () => {
  const { homeDir } = makeIsolatedHome();

  try {
    const helpSetup = runCli(['admin', 'help', 'setup'], { homeDir });
    assert.equal(helpSetup.status, 0);
    assert.match(helpSetup.stdout, /agentpay admin setup/u);

    const helpTui = runCli(['admin', 'help', 'tui'], { homeDir });
    assert.equal(helpTui.status, 0);
    assert.match(helpTui.stdout, /agentpay admin tui/u);

    const helpReset = runCli(['admin', 'help', 'reset'], { homeDir });
    assert.equal(helpReset.status, 0);
    assert.match(helpReset.stdout, /agentpay admin reset/u);

    const helpUninstall = runCli(['admin', 'help', 'uninstall'], { homeDir });
    assert.equal(helpUninstall.status, 0);
    assert.match(helpUninstall.stdout, /agentpay admin uninstall/u);

    const blockedHelp = runCli(['admin', 'help', 'rotate-agent-auth-token'], { homeDir });
    assert.equal(blockedHelp.status, 0);
    assert.match(combinedOutput(blockedHelp), /config agent-auth rotate/u);

    const chainHelp = runCli(['admin', 'chain', '--help'], { homeDir });
    assert.equal(chainHelp.status, 0);
    assert.match(chainHelp.stdout, /Manage active chain selection/u);

    const daemonBlocked = runCli(['admin', 'daemon'], { homeDir });
    assert.equal(daemonBlocked.status, 1);
    assert.match(combinedOutput(daemonBlocked), /Direct daemon execution is disabled/u);

    const bootstrapRemoved = runCli(['admin', 'bootstrap'], { homeDir });
    assert.equal(bootstrapRemoved.status, 1);
    assert.match(combinedOutput(bootstrapRemoved), /admin bootstrap.*removed/u);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('admin token set-chain validation failures fail closed in root mode', () => {
  const { homeDir } = makeIsolatedHome();

  try {
    const cases = [
      {
        args: [
          'admin',
          'token',
          'set-chain',
          '   ',
          'newchain',
          '--chain-id',
          '1',
          '--native',
          '--decimals',
          '18',
        ],
        expected: /token key is required/u,
      },
      {
        args: [
          'admin',
          'token',
          'set-chain',
          'mock',
          '   ',
          '--chain-id',
          '1',
          '--native',
          '--decimals',
          '18',
        ],
        expected: /chain key is required/u,
      },
      {
        args: [
          'admin',
          'token',
          'set-chain',
          'mock',
          'newchain',
          '--chain-id',
          '1',
          '--native',
          '--address',
          ERC20_TOKEN,
          '--decimals',
          '18',
        ],
        expected: /--native conflicts with --address/u,
      },
      {
        args: ['admin', 'token', 'set-chain', 'mock', 'newchain', '--native', '--decimals', '18'],
        expected: /chainId is required/u,
      },
      {
        args: [
          'admin',
          'token',
          'set-chain',
          'mock',
          'newchain',
          '--chain-id',
          '1',
          '--decimals',
          '18',
        ],
        expected: /pass --native or --address/u,
      },
      {
        args: ['admin', 'token', 'set-chain', 'mock', 'newchain', '--chain-id', '1', '--native'],
        expected: /decimals is required/u,
      },
    ];

    for (const { args, expected } of cases) {
      const result = runCli(args, { homeDir, assumeRoot: true });
      assert.equal(result.status, 1, `command unexpectedly succeeded: ${args.join(' ')}`);
      assert.match(combinedOutput(result), expected);
    }
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('tx broadcast fee and signer edge paths cover zero-priority fees, manual approval, and missing raw tx handling', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const fromAddress = account.address;
  const txForBroadcast = await account.signTransaction({
    chainId: 1,
    nonce: 1,
    to: TO_ADDRESS,
    gas: 21000n,
    maxFeePerGas: 1n,
    maxPriorityFeePerGas: 0n,
    value: 0n,
    data: '0x',
    type: 'eip1559',
  });
  const parsedSigned = parseTransaction(txForBroadcast);
  const signedTxHash = keccak256(txForBroadcast);

  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    txHash: signedTxHash,
    from: fromAddress,
    to: TO_ADDRESS,
    methodOverrides: {
      eth_getBlockByNumber: {
        number: '0x64',
        baseFeePerGas: '0x0',
      },
      eth_gasPrice: '0x0',
      eth_maxPriorityFeePerGas: '0x0',
      eth_feeHistory: {
        oldestBlock: '0x63',
        baseFeePerGas: ['0x0', '0x0'],
        gasUsedRatio: [0.5],
        reward: [['0x0']],
      },
    },
  });

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    transfer|transfer-native|approve|broadcast)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'if [ -z "$cmd" ]; then cmd="unknown"; fi',
        'if [ "$AGENTPAY_AGENT_MODE" = "manual" ]; then',
        '  printf "{\\"command\\":\\"%s\\",\\"approval_request_id\\":\\"approval-123\\",\\"relay_url\\":\\"https://relay.example\\",\\"frontend_url\\":\\"https://frontend.example\\",\\"cli_approval_command\\":\\"agentpay web approve --approval-id approval-123\\"}" "$cmd"',
        `  exit "\${AGENTPAY_AGENT_MANUAL_CODE:-9}"`,
        'fi',
        'if [ "$AGENTPAY_AGENT_MODE" = "manual_non_object" ]; then',
        '  printf "\\"manual approval required\\""',
        `  exit "\${AGENTPAY_AGENT_MANUAL_CODE:-9}"`,
        'fi',
        'if [ "$AGENTPAY_AGENT_MODE" = "manual_invalid_json" ]; then',
        '  printf "{invalid-json"',
        `  exit "\${AGENTPAY_AGENT_MANUAL_CODE:-9}"`,
        'fi',
        'if [ "$AGENTPAY_AGENT_MODE" = "missing_raw" ]; then',
        '  printf "{\\"command\\":\\"%s\\",\\"network\\":\\"1\\",\\"asset\\":\\"%s\\",\\"counterparty\\":\\"%s\\",\\"amount_wei\\":\\"1000000000000000000\\",\\"signature_hex\\":\\"0x11\\",\\"tx_hash_hex\\":\\"%s\\"}" "$cmd" "$AGENTPAY_MOCK_TOKEN" "$AGENTPAY_MOCK_TO" "$AGENTPAY_MOCK_TX_HASH"',
        '  exit 0',
        'fi',
        'printf "{\\"command\\":\\"%s\\",\\"network\\":\\"1\\",\\"asset\\":\\"%s\\",\\"counterparty\\":\\"%s\\",\\"amount_wei\\":\\"1000000000000000000\\",\\"estimated_max_gas_spend_wei\\":\\"21000000000000\\",\\"tx_type\\":\\"0x02\\",\\"delegation_enabled\\":false,\\"signature_hex\\":\\"0x11\\",\\"r_hex\\":\\"%s\\",\\"s_hex\\":\\"%s\\",\\"v\\":%s,\\"raw_tx_hex\\":\\"%s\\",\\"tx_hash_hex\\":\\"%s\\"}" "$cmd" "$AGENTPAY_MOCK_TOKEN" "$AGENTPAY_MOCK_TO" "$AGENTPAY_MOCK_R" "$AGENTPAY_MOCK_S" "$AGENTPAY_MOCK_V" "$AGENTPAY_MOCK_RAW_TX" "$AGENTPAY_MOCK_TX_HASH"',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'echo "admin-help"; exit 0');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 1,
      chainName: 'ETH',
      rpcUrl,
      agentKeyId: AGENT_KEY_ID,
      chains: {
        eth: { chainId: 1, name: 'ETH', rpcUrl },
      },
      wallet: {
        address: fromAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
        attachedPolicyIds: ['policy-per-tx', 'policy-daily', 'policy-weekly', 'policy-gas'],
        policyNote: 'test policy note',
        networkScope: 'all networks',
        assetScope: 'all assets',
        recipientScope: 'all recipients',
      },
    });

    const commonArgs = [
      'tx',
      'broadcast',
      '--from',
      fromAddress,
      '--to',
      TO_ADDRESS,
      '--network',
      'eth',
      '--rpc-url',
      rpcUrl,
      '--daemon-socket',
      socketPath,
      '--agent-key-id',
      AGENT_KEY_ID,
      '--agent-auth-token',
      'test-agent-auth-token',
      '--allow-legacy-agent-auth-source',
      '--nonce',
      '1',
      '--gas-limit',
      '21000',
      '--max-priority-fee-per-gas-wei',
      '0',
      '--no-wait',
      '--json',
    ];

    const feeFallbackFailure = await runCliAsync(commonArgs, {
      homeDir,
      env: {
        AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
        AGENTPAY_MOCK_TO: TO_ADDRESS,
        AGENTPAY_MOCK_RAW_TX: txForBroadcast,
        AGENTPAY_MOCK_TX_HASH: signedTxHash,
        AGENTPAY_MOCK_R: parsedSigned.r ?? `0x${'2'.repeat(64)}`,
        AGENTPAY_MOCK_S: parsedSigned.s ?? `0x${'3'.repeat(64)}`,
        AGENTPAY_MOCK_V: String(parsedSigned.v ?? 1),
      },
    });
    assert.equal(feeFallbackFailure.status, 1, combinedOutput(feeFallbackFailure));
    assert.match(combinedOutput(feeFallbackFailure), /Could not determine maxFeePerGas/u);

    const broadcastZeroPrioritySuccess = await runCliAsync(
      [
        'broadcast',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--value-wei',
        '0',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1',
        '--daemon-socket',
        socketPath,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--json',
      ],
      {
        homeDir,
        env: {
          AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
          AGENTPAY_MOCK_TO: TO_ADDRESS,
          AGENTPAY_MOCK_RAW_TX: txForBroadcast,
          AGENTPAY_MOCK_TX_HASH: signedTxHash,
          AGENTPAY_MOCK_R: parsedSigned.r ?? `0x${'2'.repeat(64)}`,
          AGENTPAY_MOCK_S: parsedSigned.s ?? `0x${'3'.repeat(64)}`,
          AGENTPAY_MOCK_V: String(parsedSigned.v ?? 1),
        },
      },
    );
    assert.equal(
      broadcastZeroPrioritySuccess.status,
      0,
      combinedOutput(broadcastZeroPrioritySuccess),
    );
    assert.equal(JSON.parse(broadcastZeroPrioritySuccess.stdout).tx_hash_hex, signedTxHash);

    const manualApprovalText = await runCliAsync(
      [...commonArgs, '--max-fee-per-gas-wei', '1'].filter((item) => item !== '--json'),
      {
        homeDir,
        env: {
          AGENTPAY_AGENT_MODE: 'manual',
          AGENTPAY_AGENT_MANUAL_CODE: '9',
          AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
          AGENTPAY_MOCK_TO: TO_ADDRESS,
          AGENTPAY_MOCK_RAW_TX: txForBroadcast,
          AGENTPAY_MOCK_TX_HASH: signedTxHash,
          AGENTPAY_MOCK_R: parsedSigned.r ?? `0x${'2'.repeat(64)}`,
          AGENTPAY_MOCK_S: parsedSigned.s ?? `0x${'3'.repeat(64)}`,
          AGENTPAY_MOCK_V: String(parsedSigned.v ?? 1),
        },
      },
    );
    assert.equal(manualApprovalText.status, 9);
    assert.match(manualApprovalText.stdout, /CLI Approval Command:/u);

    const manualApprovalJson = await runCliAsync([...commonArgs, '--max-fee-per-gas-wei', '1'], {
      homeDir,
      env: {
        AGENTPAY_AGENT_MODE: 'manual',
        AGENTPAY_AGENT_MANUAL_CODE: '9',
        AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
        AGENTPAY_MOCK_TO: TO_ADDRESS,
        AGENTPAY_MOCK_RAW_TX: txForBroadcast,
        AGENTPAY_MOCK_TX_HASH: signedTxHash,
        AGENTPAY_MOCK_R: parsedSigned.r ?? `0x${'2'.repeat(64)}`,
        AGENTPAY_MOCK_S: parsedSigned.s ?? `0x${'3'.repeat(64)}`,
        AGENTPAY_MOCK_V: String(parsedSigned.v ?? 1),
      },
    });
    assert.equal(manualApprovalJson.status, 9);
    assert.match(manualApprovalJson.stdout, /"approval_request_id"/u);

    const manualApprovalNonObject = await runCliAsync(
      [...commonArgs, '--max-fee-per-gas-wei', '1'],
      {
        homeDir,
        env: {
          AGENTPAY_AGENT_MODE: 'manual_non_object',
          AGENTPAY_AGENT_MANUAL_CODE: '9',
          AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
          AGENTPAY_MOCK_TO: TO_ADDRESS,
          AGENTPAY_MOCK_RAW_TX: txForBroadcast,
          AGENTPAY_MOCK_TX_HASH: signedTxHash,
          AGENTPAY_MOCK_R: parsedSigned.r ?? `0x${'2'.repeat(64)}`,
          AGENTPAY_MOCK_S: parsedSigned.s ?? `0x${'3'.repeat(64)}`,
          AGENTPAY_MOCK_V: String(parsedSigned.v ?? 1),
        },
      },
    );
    assert.equal(manualApprovalNonObject.status, 1);
    assert.match(combinedOutput(manualApprovalNonObject), /agentpay-agent exited with code 9/u);

    const manualApprovalInvalidJson = await runCliAsync(
      [...commonArgs, '--max-fee-per-gas-wei', '1'],
      {
        homeDir,
        env: {
          AGENTPAY_AGENT_MODE: 'manual_invalid_json',
          AGENTPAY_AGENT_MANUAL_CODE: '9',
          AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
          AGENTPAY_MOCK_TO: TO_ADDRESS,
          AGENTPAY_MOCK_RAW_TX: txForBroadcast,
          AGENTPAY_MOCK_TX_HASH: signedTxHash,
          AGENTPAY_MOCK_R: parsedSigned.r ?? `0x${'2'.repeat(64)}`,
          AGENTPAY_MOCK_S: parsedSigned.s ?? `0x${'3'.repeat(64)}`,
          AGENTPAY_MOCK_V: String(parsedSigned.v ?? 1),
        },
      },
    );
    assert.equal(manualApprovalInvalidJson.status, 1);
    assert.match(combinedOutput(manualApprovalInvalidJson), /agentpay-agent exited with code 9/u);

    const missingRawTx = await runCliAsync([...commonArgs, '--max-fee-per-gas-wei', '1'], {
      homeDir,
      env: {
        AGENTPAY_AGENT_MODE: 'missing_raw',
        AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
        AGENTPAY_MOCK_TO: TO_ADDRESS,
        AGENTPAY_MOCK_RAW_TX: txForBroadcast,
        AGENTPAY_MOCK_TX_HASH: signedTxHash,
        AGENTPAY_MOCK_R: parsedSigned.r ?? `0x${'2'.repeat(64)}`,
        AGENTPAY_MOCK_S: parsedSigned.s ?? `0x${'3'.repeat(64)}`,
        AGENTPAY_MOCK_V: String(parsedSigned.v ?? 1),
      },
    });
    assert.equal(missingRawTx.status, 1);
    assert.match(combinedOutput(missingRawTx), /did not return raw_tx_hex/u);
  } finally {
    rpcServer.close();
    socketServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agent command warns for config/env auth fallback and chain current tolerates rpc failures', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const fromAddress = account.address;
  const txForBroadcast = await account.signTransaction({
    chainId: 1,
    nonce: 1,
    to: ERC20_TOKEN,
    gas: 21000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 0n,
    data: '0x',
    type: 'eip1559',
  });
  const parsedSigned = parseTransaction(txForBroadcast);
  const signedTxHash = keccak256(txForBroadcast);
  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    txHash: signedTxHash,
    from: fromAddress,
    to: TO_ADDRESS,
  });

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    transfer|transfer-native|approve|broadcast)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'if [ -z "$cmd" ]; then cmd="unknown"; fi',
        'printf "{\\"command\\":\\"%s\\",\\"network\\":\\"1\\",\\"asset\\":\\"%s\\",\\"counterparty\\":\\"%s\\",\\"amount_wei\\":\\"1000000000000000000\\",\\"estimated_max_gas_spend_wei\\":\\"21000000000000\\",\\"tx_type\\":\\"0x02\\",\\"delegation_enabled\\":false,\\"signature_hex\\":\\"0x11\\",\\"r_hex\\":\\"%s\\",\\"s_hex\\":\\"%s\\",\\"v\\":%s,\\"raw_tx_hex\\":\\"%s\\",\\"tx_hash_hex\\":\\"%s\\"}" "$cmd" "$AGENTPAY_MOCK_TOKEN" "$AGENTPAY_MOCK_TO" "$AGENTPAY_MOCK_R" "$AGENTPAY_MOCK_S" "$AGENTPAY_MOCK_V" "$AGENTPAY_MOCK_RAW_TX" "$AGENTPAY_MOCK_TX_HASH"',
      ].join('\n'),
    );

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 1,
      chainName: 'ETH',
      rpcUrl,
      agentKeyId: AGENT_KEY_ID,
      agentAuthToken: 'legacy-config-token',
      chains: {
        eth: { chainId: 1, name: 'ETH', rpcUrl },
      },
      wallet: {
        address: fromAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
        attachedPolicyIds: ['policy-per-tx'],
        policyNote: 'test policy note',
        networkScope: 'all networks',
        assetScope: 'all assets',
        recipientScope: 'all recipients',
      },
      tokens: {
        mockerc20: {
          symbol: 'MCK',
          chains: {
            eth: {
              chainId: 1,
              isNative: false,
              address: ERC20_TOKEN,
              decimals: 18,
            },
          },
        },
      },
    });

    const sharedArgs = [
      'transfer',
      '--network',
      'eth',
      '--token',
      ERC20_TOKEN,
      '--to',
      TO_ADDRESS,
      '--amount',
      '1',
      '--agent-key-id',
      AGENT_KEY_ID,
      '--allow-legacy-agent-auth-source',
      '--daemon-socket',
      socketPath,
      '--json',
    ];
    const baseEnv = {
      AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
      AGENTPAY_MOCK_TO: TO_ADDRESS,
      AGENTPAY_MOCK_RAW_TX: txForBroadcast,
      AGENTPAY_MOCK_TX_HASH: signedTxHash,
      AGENTPAY_MOCK_R: parsedSigned.r ?? `0x${'2'.repeat(64)}`,
      AGENTPAY_MOCK_S: parsedSigned.s ?? `0x${'3'.repeat(64)}`,
      AGENTPAY_MOCK_V: String(parsedSigned.v ?? 1),
    };

    const configFallback = await runCliAsync(sharedArgs, { homeDir, env: baseEnv });
    assert.equal(configFallback.status, 0);
    assert.match(configFallback.stderr, /agentAuthToken is being loaded from config\.json/u);

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 1,
      chainName: 'ETH',
      rpcUrl,
      agentKeyId: AGENT_KEY_ID,
      chains: {
        eth: { chainId: 1, name: 'ETH', rpcUrl },
      },
      wallet: {
        address: fromAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
        attachedPolicyIds: ['policy-per-tx'],
        policyNote: 'test policy note',
        networkScope: 'all networks',
        assetScope: 'all assets',
        recipientScope: 'all recipients',
      },
      tokens: {
        mockerc20: {
          symbol: 'MCK',
          chains: {
            eth: {
              chainId: 1,
              isNative: false,
              address: ERC20_TOKEN,
              decimals: 18,
            },
          },
        },
      },
    });

    const envFallback = await runCliAsync(sharedArgs, {
      homeDir,
      env: {
        ...baseEnv,
        AGENTPAY_AGENT_AUTH_TOKEN: 'env-agent-token',
      },
    });
    assert.equal(envFallback.status, 0, combinedOutput(envFallback));
    assert.match(envFallback.stderr, /AGENTPAY_AGENT_AUTH_TOKEN exposes secrets/u);

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 1,
      chainName: 'ETH',
      rpcUrl: 'http://127.0.0.1:1',
      chains: {
        eth: { chainId: 1, name: 'ETH', rpcUrl: 'http://127.0.0.1:1' },
      },
    });
    const chainCurrent = runCli(['admin', 'chain', 'current', '--json'], { homeDir });
    assert.equal(chainCurrent.status, 0);
    assert.equal(JSON.parse(chainCurrent.stdout).rpc, null);
  } finally {
    rpcServer.close();
    socketServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('rpc broadcast-raw reports receipt polling errors in text and json modes without crashing', async () => {
  const { homeDir } = makeIsolatedHome();
  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const rawTx = await account.signTransaction({
    chainId: 1,
    nonce: 1,
    to: TO_ADDRESS,
    gas: 21000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 0n,
    data: '0x',
    type: 'eip1559',
  });
  const txHash = keccak256(rawTx);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    txHash,
    from: account.address,
    to: TO_ADDRESS,
    methodErrors: {
      eth_getTransactionReceipt: 'mock receipt polling failure',
    },
  });

  try {
    const textResult = await runCliAsync(
      ['rpc', 'broadcast-raw', '--raw-tx-hex', rawTx, '--rpc-url', rpcUrl],
      {
        homeDir,
      },
    );
    assert.equal(textResult.status, 0, combinedOutput(textResult));
    assert.match(textResult.stderr, /On-chain receipt polling failed/u);

    const jsonResult = await runCliAsync(
      ['rpc', 'broadcast-raw', '--raw-tx-hex', rawTx, '--rpc-url', rpcUrl, '--json'],
      {
        homeDir,
      },
    );
    assert.equal(jsonResult.status, 0, combinedOutput(jsonResult));
    assert.match(jsonResult.stderr, /"event": "onchainReceiptPollingError"/u);
  } finally {
    rpcServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('config agent-auth lifecycle commands cover set/import/migrate/rotate/revoke/clear paths', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const socketServer = await startUnixSocket(socketPath);
  const { pathEnv, dbPath } = installMockSecurityCommand(homeDir);

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-admin'),
      [
        'for arg in "$@"; do',
        '  if [ "$arg" = "rotate-agent-auth-token" ]; then',
        '    printf "{\\"agent_key_id\\":\\"%s\\",\\"agent_auth_token\\":\\"rotated-agent-token\\",\\"agent_auth_token_redacted\\":false}" "$AGENTPAY_MOCK_AGENT_KEY_ID"',
        '    exit 0',
        '  fi',
        '  if [ "$arg" = "revoke-agent-key" ]; then',
        '    printf "{\\"agent_key_id\\":\\"%s\\",\\"revoked\\":true}" "$AGENTPAY_MOCK_AGENT_KEY_ID"',
        '    exit 0',
        '  fi',
        'done',
        'printf "{}"',
      ].join('\n'),
    );

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      agentAuthToken: 'legacy-config-token',
    });

    const sharedEnv = {
      PATH: pathEnv,
      AGENTPAY_SECURITY_DB: dbPath,
      AGENTPAY_MOCK_AGENT_KEY_ID: AGENT_KEY_ID,
    };

    const setConflict = runCli(
      [
        'config',
        'agent-auth',
        'set',
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'argv-secret-token',
        '--agent-auth-token-stdin',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: sharedEnv,
      },
    );
    assert.equal(setConflict.status, 1);
    assert.match(combinedOutput(setConflict), /conflicts with --agent-auth-token-stdin/u);

    const setInvalidKey = runCli(
      [
        'config',
        'agent-auth',
        'set',
        '--agent-key-id',
        'not-a-uuid',
        '--agent-auth-token',
        'argv-secret-token',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: sharedEnv,
      },
    );
    assert.equal(setInvalidKey.status, 1);
    assert.match(combinedOutput(setInvalidKey), /must be a valid UUID/u);

    const setBlankToken = runCli(
      [
        'config',
        'agent-auth',
        'set',
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        '   ',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: sharedEnv,
      },
    );
    assert.equal(setBlankToken.status, 1);
    assert.match(combinedOutput(setBlankToken), /agentAuthToken is required/u);

    const setFromArgv = runCli(
      [
        'config',
        'agent-auth',
        'set',
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'argv-secret-token',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: sharedEnv,
      },
    );
    assert.equal(setFromArgv.status, 0, combinedOutput(setFromArgv));
    assert.match(setFromArgv.stderr, /exposes secrets in shell history/u);

    const setFromStdin = runCli(
      [
        'config',
        'agent-auth',
        'set',
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token-stdin',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: sharedEnv,
        input: 'stdin-secret-token\n',
      },
    );
    assert.equal(setFromStdin.status, 0, combinedOutput(setFromStdin));

    const keychainReadFailure = runCli(['config', 'show', '--json'], {
      homeDir,
      env: {
        ...sharedEnv,
        AGENTPAY_SECURITY_FAIL_FIND: '1',
      },
    });
    assert.equal(keychainReadFailure.status, 0, combinedOutput(keychainReadFailure));
    assert.equal(JSON.parse(keychainReadFailure.stdout).keychain.agentAuthTokenStored, false);

    const bootstrapConflictPath = path.join(agentpayHome, 'bootstrap-conflict.json');
    writeBootstrapOutput(bootstrapConflictPath);
    const importConflict = runCli(
      [
        'config',
        'agent-auth',
        'import',
        bootstrapConflictPath,
        '--keep-source',
        '--delete-source',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: sharedEnv,
      },
    );
    assert.equal(importConflict.status, 1);
    assert.match(combinedOutput(importConflict), /--keep-source conflicts with --delete-source/u);

    const bootstrapMismatchPath = path.join(agentpayHome, 'bootstrap-mismatch.json');
    writeBootstrapOutput(bootstrapMismatchPath, {
      agent_key_id: '00000000-0000-0000-0000-000000000999',
    });
    const importMismatch = runCli(
      ['config', 'agent-auth', 'import', bootstrapMismatchPath, '--json'],
      {
        homeDir,
        assumeRoot: true,
        env: sharedEnv,
      },
    );
    assert.equal(importMismatch.status, 0, combinedOutput(importMismatch));
    assert.equal(
      JSON.parse(importMismatch.stdout).agentKeyId,
      '00000000-0000-0000-0000-000000000999',
    );

    const bootstrapKeepPath = path.join(agentpayHome, 'bootstrap-keep.json');
    writeBootstrapOutput(bootstrapKeepPath, { agent_auth_token: 'keep-source-token' });
    const importKeep = runCli(
      ['config', 'agent-auth', 'import', bootstrapKeepPath, '--keep-source', '--json'],
      {
        homeDir,
        assumeRoot: true,
        env: sharedEnv,
      },
    );
    assert.equal(importKeep.status, 0, combinedOutput(importKeep));
    assert.match(importKeep.stderr, /still contains a plaintext agent auth token/u);
    assert.equal(JSON.parse(importKeep.stdout).sourceCleanup, 'kept');
    assert.match(fs.readFileSync(bootstrapKeepPath, 'utf8'), /keep-source-token/u);

    const bootstrapDeletePath = path.join(agentpayHome, 'bootstrap-delete.json');
    writeBootstrapOutput(bootstrapDeletePath, { agent_auth_token: 'delete-source-token' });
    const importDelete = runCli(
      ['config', 'agent-auth', 'import', bootstrapDeletePath, '--delete-source', '--json'],
      {
        homeDir,
        assumeRoot: true,
        env: sharedEnv,
      },
    );
    assert.equal(importDelete.status, 0, combinedOutput(importDelete));
    assert.equal(JSON.parse(importDelete.stdout).sourceCleanup, 'deleted');
    assert.equal(fs.existsSync(bootstrapDeletePath), false);

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      agentAuthToken: 'legacy-config-token',
    });
    const bootstrapRedactPath = path.join(agentpayHome, 'bootstrap-redact.json');
    writeBootstrapOutput(bootstrapRedactPath, { agent_auth_token: 'redact-source-token' });
    const importRedact = runCli(['config', 'agent-auth', 'import', bootstrapRedactPath, '--json'], {
      homeDir,
      assumeRoot: true,
      env: sharedEnv,
    });
    assert.equal(importRedact.status, 0, combinedOutput(importRedact));
    assert.equal(JSON.parse(importRedact.stdout).sourceCleanup, 'redacted');
    assert.match(fs.readFileSync(bootstrapRedactPath, 'utf8'), /<redacted>/u);
    assert.equal(
      JSON.parse(fs.readFileSync(path.join(agentpayHome, 'config.json'), 'utf8')).agentAuthToken,
      undefined,
    );

    fs.writeFileSync(dbPath, '{}', 'utf8');
    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      agentAuthToken: 'legacy-migrate-token',
    });
    const migrate = runCli(['config', 'agent-auth', 'migrate', '--json'], {
      homeDir,
      assumeRoot: true,
      env: sharedEnv,
    });
    assert.equal(migrate.status, 0, combinedOutput(migrate));
    assert.equal(JSON.parse(migrate.stdout).agentKeyId, AGENT_KEY_ID);

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
    });
    const clearMissingAgent = runCli(['config', 'agent-auth', 'clear', '--json'], {
      homeDir,
      assumeRoot: true,
      env: sharedEnv,
    });
    assert.equal(clearMissingAgent.status, 1);
    assert.match(combinedOutput(clearMissingAgent), /agentKeyId is required/u);

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
    });
    const clearSuccess = runCli(
      ['config', 'agent-auth', 'clear', '--agent-key-id', AGENT_KEY_ID, '--json'],
      {
        homeDir,
        assumeRoot: true,
        env: sharedEnv,
      },
    );
    assert.equal(clearSuccess.status, 0, combinedOutput(clearSuccess));
    assert.equal(JSON.parse(clearSuccess.stdout).agentKeyId, AGENT_KEY_ID);

    const adminSocketEnv = {
      ...sharedEnv,
      AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP: '1',
    };

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
    });
    const rotateMissingAgent = runCli(
      ['config', 'agent-auth', 'rotate', '--daemon-socket', socketPath, '--json'],
      {
        homeDir,
        assumeRoot: true,
        env: adminSocketEnv,
      },
    );
    assert.equal(rotateMissingAgent.status, 1);
    assert.match(combinedOutput(rotateMissingAgent), /agentKeyId is required/u);

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
    });
    const rotateSuccess = runCli(
      [
        'config',
        'agent-auth',
        'rotate',
        '--daemon-socket',
        socketPath,
        '--vault-password-stdin',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: adminSocketEnv,
        input: 'vault-password\n',
      },
    );
    assert.equal(rotateSuccess.status, 0, combinedOutput(rotateSuccess));
    assert.equal(JSON.parse(rotateSuccess.stdout).agentKeyId, AGENT_KEY_ID);

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
    });
    const revokeMissingAgent = runCli(
      ['config', 'agent-auth', 'revoke', '--daemon-socket', socketPath, '--json'],
      {
        homeDir,
        assumeRoot: true,
        env: adminSocketEnv,
      },
    );
    assert.equal(revokeMissingAgent.status, 1);
    assert.match(combinedOutput(revokeMissingAgent), /agentKeyId is required/u);

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
    });
    const revokeSuccess = runCli(
      [
        'config',
        'agent-auth',
        'revoke',
        '--daemon-socket',
        socketPath,
        '--vault-password-stdin',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: adminSocketEnv,
        input: 'vault-password\n',
      },
    );
    assert.equal(revokeSuccess.status, 0, combinedOutput(revokeSuccess));
    assert.equal(JSON.parse(revokeSuccess.stdout).revoked, true);

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: 'not-a-uuid',
    });
    const statusWithInvalidConfiguredKey = runCli(['config', 'agent-auth', 'status', '--json'], {
      homeDir,
      env: sharedEnv,
    });
    assert.equal(
      statusWithInvalidConfiguredKey.status,
      0,
      combinedOutput(statusWithInvalidConfiguredKey),
    );
    assert.equal(JSON.parse(statusWithInvalidConfiguredKey.stdout).agentKeyId, null);
  } finally {
    socketServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('admin dispatch and local admin edge branches are exercised', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const socketServer = await startUnixSocket(socketPath);

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-admin'),
      [
        'if [ "$1" = "--help" ] || [ "$1" = "help" ]; then',
        '  echo "agentpay-admin help on stderr" 1>&2',
        '  exit 0',
        'fi',
        'echo "passthrough:$*" 1>&2',
        'exit 7',
      ].join('\n'),
    );

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 1,
      chainName: 'ETH',
      chains: {
        eth: { chainId: 1, name: 'ETH', rpcUrl: 'https://eth.llamarpc.com' },
      },
    });

    const directAdminHelpCommands = [
      ['admin', 'setup', '--help'],
      ['admin', 'tui', '--help'],
      ['admin', 'reset', '--help'],
      ['admin', 'uninstall', '--help'],
      ['admin', 'help', 'tui'],
      ['admin', 'help', 'setup'],
      ['admin', 'help', 'reset'],
      ['admin', 'help', 'uninstall'],
    ];
    for (const args of directAdminHelpCommands) {
      const result = runCli(args, { homeDir });
      assert.equal(
        result.status,
        0,
        `command failed: ${args.join(' ')}\n${combinedOutput(result)}`,
      );
    }

    const adminHelpFromRust = runCli(['admin'], { homeDir });
    assert.equal(adminHelpFromRust.status, 0, combinedOutput(adminHelpFromRust));
    assert.match(adminHelpFromRust.stderr, /agentpay admin help on stderr/u);

    const unknownToken = runCli(['admin', 'token', 'show', 'unknown-token'], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(unknownToken.status, 1);
    assert.match(combinedOutput(unknownToken), /unknown token selector/u);

    const activatedChain = runCli(
      ['admin', 'chain', 'add', 'local', '--chain-id', '31337', '--activate', '--json'],
      { homeDir, assumeRoot: true },
    );
    assert.equal(activatedChain.status, 0, combinedOutput(activatedChain));

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 1,
      chainName: 'ETH',
      chains: {
        eth: { chainId: 1, name: 'ETH', rpcUrl: 'https://eth.llamarpc.com' },
      },
      tokens: {
        legacy: {
          symbol: 'LEG',
          chains: {
            eth: {
              chainId: 1,
              isNative: false,
              address: ERC20_TOKEN,
              decimals: 18,
              defaultPolicy: {
                perTxAmount: 1,
                weeklyAmount: 3,
              },
            },
          },
        },
      },
    });
    const legacyToken = runCli(['admin', 'token', 'set-chain', 'legacy', 'eth', '--json'], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(legacyToken.status, 0, combinedOutput(legacyToken));
    assert.deepEqual(JSON.parse(legacyToken.stdout).saved.chains[0].defaultPolicy, {
      perTxAmountDecimal: '1',
      weeklyAmountDecimal: '3',
    });

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 1,
      chainName: 'ETH',
      chains: {
        eth: { chainId: 1, name: 'ETH', rpcUrl: 'https://eth.llamarpc.com' },
      },
      tokens: {
        broken: {
          symbol: 'BROKEN',
          chains: {
            eth: {
              chainId: 1,
              isNative: false,
              decimals: 18,
            },
          },
        },
      },
    });
    const brokenToken = runCli(['admin', 'token', 'set-chain', 'broken', 'eth', '--json'], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(brokenToken.status, 1);
    assert.match(combinedOutput(brokenToken), /address .* valid EVM address|address is required/u);

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 1,
      chainName: 'ETH',
      chains: {
        eth: { chainId: 1, name: 'ETH', rpcUrl: 'https://eth.llamarpc.com' },
      },
    });
    const passthrough = runCli(['admin', 'raw-subcommand', '--vault-password-stdin'], {
      homeDir,
      assumeRoot: true,
      env: {
        AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP: '1',
      },
      input: 'vault-password\n',
    });
    assert.equal(passthrough.status, 7, combinedOutput(passthrough));
    assert.match(passthrough.stderr, /passthrough:raw-subcommand/u);
  } finally {
    socketServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('cli validation, amount rewrite, and receipt timeout branches are exercised', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const socketServer = await startUnixSocket(socketPath);
  const { pathEnv, dbPath } = installMockSecurityCommand(homeDir);
  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const fromAddress = account.address;
  const rawTx = await account.signTransaction({
    chainId: 1,
    nonce: 1,
    to: TO_ADDRESS,
    gas: 21000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 0n,
    data: '0x',
    type: 'eip1559',
  });
  const txHash = keccak256(rawTx);
  const parsed = parseTransaction(rawTx);
  const transferRawTx = await account.signTransaction({
    chainId: 1,
    nonce: 1,
    to: ERC20_TOKEN,
    gas: 21000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 0n,
    data: encodeFunctionData({
      abi: [
        {
          type: 'function',
          name: 'transfer',
          stateMutability: 'nonpayable',
          inputs: [
            { name: 'recipient', type: 'address' },
            { name: 'amount', type: 'uint256' },
          ],
          outputs: [{ name: '', type: 'bool' }],
        },
      ],
      functionName: 'transfer',
      args: [TO_ADDRESS, 1_000_000_000_000_000_000n],
    }),
    type: 'eip1559',
  });
  const transferTxHash = keccak256(transferRawTx);
  const parsedTransfer = parseTransaction(transferRawTx);
  const approveRawTx = await account.signTransaction({
    chainId: 1,
    nonce: 1,
    to: ERC20_TOKEN,
    gas: 21000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 0n,
    data: encodeFunctionData({
      abi: [
        {
          type: 'function',
          name: 'approve',
          stateMutability: 'nonpayable',
          inputs: [
            { name: 'spender', type: 'address' },
            { name: 'amount', type: 'uint256' },
          ],
          outputs: [{ name: '', type: 'bool' }],
        },
      ],
      functionName: 'approve',
      args: [TO_ADDRESS, 1_000_000_000_000_000_000n],
    }),
    type: 'eip1559',
  });
  const approveTxHash = keccak256(approveRawTx);
  const parsedApprove = parseTransaction(approveRawTx);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    txHash,
    from: fromAddress,
    to: TO_ADDRESS,
  });
  const { server: timeoutRpcServer, rpcUrl: timeoutRpcUrl } = await startMockRpcServer({
    txHash,
    from: fromAddress,
    to: TO_ADDRESS,
    methodOverrides: {
      eth_getTransactionReceipt: null,
    },
  });

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    transfer|transfer-native|approve|broadcast)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'if [ "$AGENTPAY_AGENT_MODE" = "policy_error" ]; then',
        '  echo "per transaction max 1 < requested 2" 1>&2',
        '  exit 12',
        'fi',
        'if [ "$AGENTPAY_AGENT_MODE" = "manual" ]; then',
        '  printf "{\\"command\\":\\"%s\\",\\"approval_request_id\\":\\"approval-999\\",\\"cli_approval_command\\":\\"agentpay web approve --approval-id approval-999\\"}" "$cmd"',
        '  exit 9',
        'fi',
        'if [ "$AGENTPAY_AGENT_MODE" = "manual_changing_id" ]; then',
        `  counter_file="\${AGENTPAY_AGENT_MANUAL_COUNTER_FILE:?missing AGENTPAY_AGENT_MANUAL_COUNTER_FILE}"`,
        '  count=0',
        '  if [ -f "$counter_file" ]; then',
        '    count=$(cat "$counter_file")',
        '  fi',
        '  count=$((count + 1))',
        '  printf "%s" "$count" > "$counter_file"',
        '  approval_id="approval-999"',
        '  if [ "$count" -gt 1 ]; then',
        '    approval_id="approval-1000"',
        '  fi',
        '  printf "{\\"command\\":\\"%s\\",\\"approval_request_id\\":\\"%s\\",\\"cli_approval_command\\":\\"agentpay web approve --approval-id %s\\"}" "$cmd" "$approval_id" "$approval_id"',
        '  exit 9',
        'fi',
        'if [ "$AGENTPAY_AGENT_MODE" = "manual_until_file" ] && [ ! -f "$AGENTPAY_AGENT_MANUAL_FILE" ]; then',
        '  printf "{\\"command\\":\\"%s\\",\\"approval_request_id\\":\\"approval-999\\",\\"cli_approval_command\\":\\"agentpay web approve --approval-id approval-999\\"}" "$cmd"',
        '  exit 9',
        'fi',
        'printf "{\\"command\\":\\"%s\\",\\"network\\":\\"1\\",\\"asset\\":\\"%s\\",\\"counterparty\\":\\"%s\\",\\"amount_wei\\":\\"1000000000000000000\\",\\"estimated_max_gas_spend_wei\\":\\"21000000000000\\",\\"tx_type\\":\\"0x02\\",\\"delegation_enabled\\":false,\\"signature_hex\\":\\"0x11\\",\\"r_hex\\":\\"%s\\",\\"s_hex\\":\\"%s\\",\\"v\\":%s,\\"raw_tx_hex\\":\\"%s\\",\\"tx_hash_hex\\":\\"%s\\"}" "$cmd" "$AGENTPAY_MOCK_TOKEN" "$AGENTPAY_MOCK_TO" "$AGENTPAY_MOCK_R" "$AGENTPAY_MOCK_S" "$AGENTPAY_MOCK_V" "$AGENTPAY_MOCK_RAW_TX" "$AGENTPAY_MOCK_TX_HASH"',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    const baseConfig = {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 1,
      chainName: 'ETH',
      rpcUrl,
      agentKeyId: AGENT_KEY_ID,
      chains: {
        eth: { chainId: 1, name: 'ETH', rpcUrl },
      },
      wallet: {
        address: fromAddress,
        vaultKeyId: 'vault-key-cli-validation',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
        attachedPolicyIds: ['policy-per-tx'],
        policyNote: 'cli validation note',
        networkScope: 'all networks',
        assetScope: 'all assets',
        recipientScope: 'all recipients',
      },
      tokens: {
        mockerc20: {
          symbol: 'MCK',
          chains: {
            eth: {
              chainId: 1,
              isNative: false,
              address: ERC20_TOKEN,
              decimals: 18,
            },
          },
        },
        eth: {
          symbol: 'ETH',
          chains: {
            eth: {
              chainId: 1,
              isNative: true,
              decimals: 18,
            },
          },
        },
      },
    };
    writeConfig(agentpayHome, baseConfig);

    const setAgentKeyId = runCli(['config', 'set', 'agentKeyId', AGENT_KEY_ID], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(setAgentKeyId.status, 0, combinedOutput(setAgentKeyId));

    const setRpcUrl = runCli(['config', 'set', 'rpcUrl', rpcUrl], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(setRpcUrl.status, 0, combinedOutput(setRpcUrl));

    const setChainName = runCli(['config', 'set', 'chainName', 'eth'], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(setChainName.status, 0, combinedOutput(setChainName));

    const setInvalidChainId = runCli(['config', 'set', 'chainId', '0'], {
      homeDir,
      assumeRoot: true,
    });
    assert.equal(setInvalidChainId.status, 1);
    assert.match(combinedOutput(setInvalidChainId), /must be greater than zero/u);

    const oversizedStdin = runCli(
      [
        'config',
        'agent-auth',
        'set',
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token-stdin',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: {
          PATH: pathEnv,
          AGENTPAY_SECURITY_DB: dbPath,
        },
        input: `${'x'.repeat(17_000)}\n`,
      },
    );
    assert.equal(oversizedStdin.status, 1);
    assert.match(combinedOutput(oversizedStdin), /must not exceed 16384 bytes/u);

    const sharedAgentAuth = [
      '--agent-key-id',
      AGENT_KEY_ID,
      '--allow-legacy-agent-auth-source',
      '--daemon-socket',
      socketPath,
      '--json',
    ];
    const sharedEnv = {
      AGENTPAY_AGENT_AUTH_TOKEN: 'env-agent-auth-token',
      AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
      AGENTPAY_MOCK_TO: TO_ADDRESS,
      AGENTPAY_MOCK_RAW_TX: rawTx,
      AGENTPAY_MOCK_TX_HASH: txHash,
      AGENTPAY_MOCK_R: parsed.r ?? `0x${'2'.repeat(64)}`,
      AGENTPAY_MOCK_S: parsed.s ?? `0x${'3'.repeat(64)}`,
      AGENTPAY_MOCK_V: String(parsed.v ?? 1),
    };
    const transferSharedEnv = {
      ...sharedEnv,
      AGENTPAY_MOCK_RAW_TX: transferRawTx,
      AGENTPAY_MOCK_TX_HASH: transferTxHash,
      AGENTPAY_MOCK_R: parsedTransfer.r ?? `0x${'2'.repeat(64)}`,
      AGENTPAY_MOCK_S: parsedTransfer.s ?? `0x${'3'.repeat(64)}`,
      AGENTPAY_MOCK_V: String(parsedTransfer.v ?? 1),
    };

    const invalidAddress = runCli(
      [
        'broadcast',
        '--network',
        'eth',
        '--to',
        'not-an-address',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1',
        ...sharedAgentAuth,
      ],
      { homeDir, env: sharedEnv },
    );
    assert.equal(invalidAddress.status, 1);
    assert.match(combinedOutput(invalidAddress), /to must be a valid EVM address/u);

    const invalidHex = runCli(
      [
        'broadcast',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--data-hex',
        'not-hex',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1',
        ...sharedAgentAuth,
      ],
      { homeDir, env: sharedEnv },
    );
    assert.equal(invalidHex.status, 1);
    assert.match(combinedOutput(invalidHex), /dataHex must be valid hex/u);

    const invalidNonce = runCli(
      [
        'broadcast',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--nonce',
        'abc',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1',
        ...sharedAgentAuth,
      ],
      { homeDir, env: sharedEnv },
    );
    assert.equal(invalidNonce.status, 1);
    assert.match(combinedOutput(invalidNonce), /nonce must be a non-negative integer/u);

    const oversizedNonce = runCli(
      [
        'broadcast',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--nonce',
        '9007199254740992',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1',
        ...sharedAgentAuth,
      ],
      { homeDir, env: sharedEnv },
    );
    assert.equal(oversizedNonce.status, 1);
    assert.match(combinedOutput(oversizedNonce), /nonce must be a safe integer/u);

    const invalidGasLimit = runCli(
      [
        'broadcast',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--gas-limit',
        '0',
        '--max-fee-per-gas-wei',
        '1',
        ...sharedAgentAuth,
      ],
      { homeDir, env: sharedEnv },
    );
    assert.equal(invalidGasLimit.status, 1);
    assert.match(combinedOutput(invalidGasLimit), /gasLimit must be greater than zero/u);

    const invalidValueWei = runCli(
      [
        'broadcast',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--value-wei',
        'not-an-integer',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1',
        ...sharedAgentAuth,
      ],
      { homeDir, env: sharedEnv },
    );
    assert.equal(invalidValueWei.status, 1);
    assert.match(
      combinedOutput(invalidValueWei),
      /valueWei must be a non-negative integer string/u,
    );

    const missingSocketHome = makeIsolatedHome();
    try {
      writeConfig(missingSocketHome.agentpayHome, {
        ...baseConfig,
        daemonSocket: undefined,
      });
      const defaultDaemonSocketFailure = runCli(
        [
          'transfer',
          '--network',
          'eth',
          '--token',
          ERC20_TOKEN,
          '--to',
          TO_ADDRESS,
          '--amount',
          '1',
          '--agent-key-id',
          AGENT_KEY_ID,
          '--allow-legacy-agent-auth-source',
          '--json',
        ],
        { homeDir: missingSocketHome.homeDir, env: sharedEnv },
      );
      assert.equal(defaultDaemonSocketFailure.status, 1);
      assert.match(combinedOutput(defaultDaemonSocketFailure), /does not exist/u);
    } finally {
      fs.rmSync(missingSocketHome.homeDir, { recursive: true, force: true });
    }

    writeConfig(agentpayHome, baseConfig);

    const transferPolicyError = runCli(
      [
        'transfer',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--to',
        TO_ADDRESS,
        '--amount',
        '1',
        ...sharedAgentAuth,
      ],
      {
        homeDir,
        env: {
          ...sharedEnv,
          AGENTPAY_AGENT_MODE: 'policy_error',
        },
      },
    );
    assert.equal(transferPolicyError.status, 1);
    assert.match(
      combinedOutput(transferPolicyError),
      /per transaction max .* MCK .* requested .* MCK/u,
    );

    const transferNativePolicyError = runCli(
      [
        'transfer-native',
        '--network',
        'eth',
        '--to',
        TO_ADDRESS,
        '--amount',
        '1',
        ...sharedAgentAuth,
      ],
      {
        homeDir,
        env: {
          ...sharedEnv,
          AGENTPAY_AGENT_MODE: 'policy_error',
        },
      },
    );
    assert.equal(transferNativePolicyError.status, 1);
    assert.match(
      combinedOutput(transferNativePolicyError),
      /per transaction max .* ETH .* requested .* ETH/u,
    );

    const approvePolicyError = runCli(
      [
        'approve',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--spender',
        TO_ADDRESS,
        '--amount',
        '1',
        ...sharedAgentAuth,
      ],
      {
        homeDir,
        env: {
          ...sharedEnv,
          AGENTPAY_AGENT_MODE: 'policy_error',
        },
      },
    );
    assert.equal(approvePolicyError.status, 1);
    assert.match(
      combinedOutput(approvePolicyError),
      /per transaction max .* MCK .* requested .* MCK/u,
    );

    const transferApprovalMarkerPath = path.join(homeDir, 'transfer-manual-approval-ready');
    const transferBroadcastManual = runCliAsync(
      [
        'transfer',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--to',
        TO_ADDRESS,
        '--amount',
        '1',
        '--broadcast',
        '--rpc-url',
        rpcUrl,
        '--from',
        fromAddress,
        '--nonce',
        '1',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        '--max-priority-fee-per-gas-wei',
        '1000000000',
        '--tx-type',
        '0x02',
        '--no-wait',
        ...sharedAgentAuth,
      ],
      {
        homeDir,
        env: {
          ...transferSharedEnv,
          AGENTPAY_AGENT_MODE: 'manual_until_file',
          AGENTPAY_AGENT_MANUAL_FILE: transferApprovalMarkerPath,
        },
      },
    );
    await new Promise((resolve) => setTimeout(resolve, 2500));
    fs.writeFileSync(transferApprovalMarkerPath, 'approved');
    const transferBroadcastApproved = await transferBroadcastManual;
    assert.equal(transferBroadcastApproved.status, 0, combinedOutput(transferBroadcastApproved));
    assert.match(transferBroadcastApproved.stderr, /approval_request_id/u);
    assert.match(transferBroadcastApproved.stderr, /manualApprovalPending/u);
    assert.match(transferBroadcastApproved.stdout, /"networkTxHash"/u);

    const changedApprovalCounterPath = path.join(homeDir, 'manual-approval-counter.txt');
    const transferBroadcastChangedApproval = await runCliAsync(
      [
        'transfer',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--to',
        TO_ADDRESS,
        '--amount',
        '1',
        '--broadcast',
        '--rpc-url',
        rpcUrl,
        '--from',
        fromAddress,
        '--nonce',
        '1',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        '--max-priority-fee-per-gas-wei',
        '1000000000',
        '--tx-type',
        '0x02',
        '--no-wait',
        ...sharedAgentAuth,
      ],
      {
        homeDir,
        env: {
          ...transferSharedEnv,
          AGENTPAY_AGENT_MODE: 'manual_changing_id',
          AGENTPAY_AGENT_MANUAL_COUNTER_FILE: changedApprovalCounterPath,
        },
      },
    );
    assert.equal(transferBroadcastChangedApproval.status, 1);
    assert.match(
      combinedOutput(transferBroadcastChangedApproval),
      /manual approval request changed while waiting for a decision/u,
    );

    const transferBroadcastTimedOut = await runCliAsync(
      [
        'transfer',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--to',
        TO_ADDRESS,
        '--amount',
        '1',
        '--broadcast',
        '--rpc-url',
        rpcUrl,
        '--from',
        fromAddress,
        '--nonce',
        '1',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        '--max-priority-fee-per-gas-wei',
        '1000000000',
        '--tx-type',
        '0x02',
        '--no-wait',
        ...sharedAgentAuth,
      ],
      {
        homeDir,
        assumeRoot: true,
        env: {
          ...transferSharedEnv,
          AGENTPAY_AGENT_MODE: 'manual',
          AGENTPAY_TEST_FAST_TIME: '1',
          AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP: '1',
          AGENTPAY_TEST_MANUAL_APPROVAL_TIMEOUT_MS: '1000',
        },
      },
    );
    assert.equal(transferBroadcastTimedOut.status, 1);
    assert.match(
      combinedOutput(transferBroadcastTimedOut),
      /Timed out after 1s waiting for manual approval decision/u,
    );

    const approveSharedEnv = {
      ...sharedEnv,
      AGENTPAY_MOCK_TOKEN: ERC20_TOKEN,
      AGENTPAY_MOCK_TO: ERC20_TOKEN,
      AGENTPAY_MOCK_RAW_TX: approveRawTx,
      AGENTPAY_MOCK_TX_HASH: approveTxHash,
      AGENTPAY_MOCK_R: parsedApprove.r ?? `0x${'4'.repeat(64)}`,
      AGENTPAY_MOCK_S: parsedApprove.s ?? `0x${'5'.repeat(64)}`,
      AGENTPAY_MOCK_V: String(parsedApprove.v ?? 1),
    };
    const approveApprovalMarkerPath = path.join(homeDir, 'approve-manual-approval-ready');
    const approveBroadcastManual = runCliAsync(
      [
        'approve',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--spender',
        TO_ADDRESS,
        '--amount',
        '1',
        '--broadcast',
        '--rpc-url',
        rpcUrl,
        '--from',
        fromAddress,
        '--nonce',
        '1',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        '--max-priority-fee-per-gas-wei',
        '1000000000',
        '--tx-type',
        '0x02',
        '--no-wait',
        ...sharedAgentAuth,
      ],
      {
        homeDir,
        env: {
          ...approveSharedEnv,
          AGENTPAY_AGENT_MODE: 'manual_until_file',
          AGENTPAY_AGENT_MANUAL_FILE: approveApprovalMarkerPath,
        },
      },
    );
    await new Promise((resolve) => setTimeout(resolve, 2500));
    fs.writeFileSync(approveApprovalMarkerPath, 'approved');
    const approveBroadcastApproved = await approveBroadcastManual;
    assert.equal(approveBroadcastApproved.status, 0, combinedOutput(approveBroadcastApproved));
    assert.match(approveBroadcastApproved.stderr, /approval_request_id/u);
    assert.match(approveBroadcastApproved.stderr, /manualApprovalPending/u);
    assert.match(approveBroadcastApproved.stdout, /"networkTxHash"/u);

    const approveBroadcastWaitJson = await runCliAsync(
      [
        'approve',
        '--network',
        'eth',
        '--token',
        ERC20_TOKEN,
        '--spender',
        TO_ADDRESS,
        '--amount',
        '1',
        '--broadcast',
        '--rpc-url',
        rpcUrl,
        '--from',
        fromAddress,
        '--nonce',
        '1',
        '--gas-limit',
        '21000',
        '--max-fee-per-gas-wei',
        '1000000000',
        '--max-priority-fee-per-gas-wei',
        '1000000000',
        '--tx-type',
        '0x02',
        ...sharedAgentAuth,
      ],
      {
        homeDir,
        env: approveSharedEnv,
      },
    );
    assert.equal(approveBroadcastWaitJson.status, 0, combinedOutput(approveBroadcastWaitJson));
    assert.match(approveBroadcastWaitJson.stderr, /"event": "onchainReceiptPending"/u);
    assert.match(approveBroadcastWaitJson.stderr, /"event": "onchainReceipt"/u);

    const textReceipt = await runCliAsync(
      ['rpc', 'broadcast-raw', '--raw-tx-hex', rawTx, '--rpc-url', rpcUrl],
      {
        homeDir,
      },
    );
    assert.equal(textReceipt.status, 0, combinedOutput(textReceipt));
    assert.match(textReceipt.stderr, /On-chain receipt:/u);

    const timeoutReceipt = await runCliAsync(
      ['rpc', 'broadcast-raw', '--raw-tx-hex', rawTx, '--rpc-url', timeoutRpcUrl],
      {
        homeDir,
        assumeRoot: true,
        env: {
          AGENTPAY_TEST_FAST_TIME: '1',
        },
      },
    );
    assert.equal(timeoutReceipt.status, 0, combinedOutput(timeoutReceipt));
    assert.match(timeoutReceipt.stderr, /Timed out after 30s waiting for on-chain receipt/u);

    const timeoutReceiptJson = await runCliAsync(
      ['rpc', 'broadcast-raw', '--raw-tx-hex', rawTx, '--rpc-url', timeoutRpcUrl, '--json'],
      {
        homeDir,
        assumeRoot: true,
        env: {
          AGENTPAY_TEST_FAST_TIME: '1',
        },
      },
    );
    assert.equal(timeoutReceiptJson.status, 0, combinedOutput(timeoutReceiptJson));
    assert.match(timeoutReceiptJson.stderr, /"event": "onchainReceiptTimeout"/u);
  } finally {
    timeoutRpcServer.close();
    rpcServer.close();
    socketServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('admin resume-manual-approval-request replays an approved broadcast request using stored request details', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const socketServer = await startUnixSocket(socketPath);
  const { pathEnv, dbPath } = installMockSecurityCommand(homeDir);
  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const fromAddress = account.address;
  const approvalRequestId = '040856f5-541b-4a45-a805-8d74295d3084';
  const approvalAgentKeyId = 'f8468ff8-f3d6-4364-9a4d-b9a1a4b49742';
  const transferCalldata = encodeFunctionData({
    abi: [
      {
        type: 'function',
        name: 'transfer',
        stateMutability: 'nonpayable',
        inputs: [
          { name: 'recipient', type: 'address' },
          { name: 'amount', type: 'uint256' },
        ],
        outputs: [{ name: '', type: 'bool' }],
      },
    ],
    functionName: 'transfer',
    args: [TO_ADDRESS, 15_000_000_000_000_000_000n],
  });
  const rawTx = await account.signTransaction({
    chainId: 56,
    nonce: 2,
    to: ERC20_TOKEN,
    gas: 65000n,
    maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 0n,
    data: transferCalldata,
    type: 'eip1559',
  });
  const txHash = keccak256(rawTx);
  const parsed = parseTransaction(rawTx);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    txHash,
    from: fromAddress,
    to: ERC20_TOKEN,
    methodOverrides: {
      eth_chainId: '0x38',
    },
  });

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  if [ "$arg" = "broadcast" ]; then',
        '    cmd="$arg"',
        '    break',
        '  fi',
        'done',
        'if [ "$cmd" != "broadcast" ]; then',
        '  echo "unexpected command" 1>&2',
        '  exit 1',
        'fi',
        'printf "{\\"command\\":\\"broadcast\\",\\"network\\":\\"56\\",\\"asset\\":\\"erc20:' +
          ERC20_TOKEN.toLowerCase() +
          '\\",\\"counterparty\\":\\"' +
          TO_ADDRESS.toLowerCase() +
          '\\",\\"amount_wei\\":\\"15000000000000000000\\",\\"estimated_max_gas_spend_wei\\":\\"130000000000000\\",\\"tx_type\\":\\"0x02\\",\\"delegation_enabled\\":false,\\"signature_hex\\":\\"0x11\\",\\"r_hex\\":\\"' +
          (parsed.r ?? `0x${'2'.repeat(64)}`) +
          '\\",\\"s_hex\\":\\"' +
          (parsed.s ?? `0x${'3'.repeat(64)}`) +
          '\\",\\"v\\":' +
          String(parsed.v ?? 1) +
          ',\\"raw_tx_hex\\":\\"' +
          rawTx +
          '\\",\\"tx_hash_hex\\":\\"' +
          txHash +
          '\\"}"',
      ].join('\n'),
    );
    writeExecutable(
      path.join(rustBinDir, 'agentpay-admin'),
      [
        'for arg in "$@"; do',
        '  if [ "$arg" = "list-manual-approval-requests" ]; then',
        '    printf "[{\\"id\\":\\"' +
          approvalRequestId +
          '\\",\\"agent_key_id\\":\\"' +
          approvalAgentKeyId +
          '\\",\\"status\\":\\"approved\\",\\"action\\":{\\"kind\\":\\"BroadcastTx\\",\\"tx\\":{\\"chain_id\\":56,\\"nonce\\":2,\\"to\\":\\"' +
          ERC20_TOKEN +
          '\\",\\"value_wei\\":\\"0\\",\\"data_hex\\":\\"' +
          transferCalldata +
          '\\",\\"gas_limit\\":65000,\\"max_fee_per_gas_wei\\":\\"2000000000\\",\\"max_priority_fee_per_gas_wei\\":\\"1000000000\\",\\"tx_type\\":2,\\"delegation_enabled\\":false}},\\"chain_id\\":56,\\"asset\\":\\"erc20:' +
          ERC20_TOKEN.toLowerCase() +
          '\\",\\"recipient\\":\\"' +
          TO_ADDRESS.toLowerCase() +
          '\\",\\"amount_wei\\":\\"15000000000000000000\\"}]"',
        '    exit 0',
        '  fi',
        'done',
        'printf "[]"',
      ].join('\n'),
    );

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 56,
      chainName: 'bsc',
      rpcUrl,
      chains: {
        bsc: {
          chainId: 56,
          name: 'BSC',
          rpcUrl,
        },
      },
      wallet: {
        address: fromAddress,
        vaultKeyId: 'vault-key-resume',
        vaultPublicKey: '03abcdef',
        agentKeyId: approvalAgentKeyId,
        policyAttachment: 'policy_set',
        attachedPolicyIds: ['policy-manual'],
        policyNote: 'resume test',
        networkScope: 'all networks',
        assetScope: 'all assets',
        recipientScope: 'all recipients',
      },
    });

    const storeAgentAuth = runCli(
      [
        'config',
        'agent-auth',
        'set',
        '--agent-key-id',
        approvalAgentKeyId,
        '--agent-auth-token-stdin',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: {
          PATH: pathEnv,
          AGENTPAY_SECURITY_DB: dbPath,
          AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP: '1',
        },
        input: 'resume-agent-auth-token\n',
      },
    );
    assert.equal(storeAgentAuth.status, 0, combinedOutput(storeAgentAuth));

    const resumed = await runCliAsync(
      [
        'admin',
        'resume-manual-approval-request',
        '--approval-request-id',
        approvalRequestId,
        '--vault-password-stdin',
        '--no-wait',
        '--json',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: {
          PATH: pathEnv,
          AGENTPAY_SECURITY_DB: dbPath,
          AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP: '1',
        },
        input: 'vault-password\n',
      },
    );
    assert.equal(resumed.status, 0, combinedOutput(resumed));
    assert.match(resumed.stdout, /"command": "resume-manual-approval-request"/u);
    assert.match(resumed.stdout, /"approvalRequestId": "040856f5-541b-4a45-a805-8d74295d3084"/u);
    assert.match(resumed.stdout, /"networkTxHash":/u);
  } finally {
    rpcServer.close();
    socketServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('config agent-auth rotate reports recovery commands for stale admin daemon socket overrides', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const socketServer = await startUnixSocket(socketPath);

  try {
    writeConfig(agentpayHome, {
      agentKeyId: AGENT_KEY_ID,
      daemonSocket: socketPath,
    });

    const rotated = runCli(
      ['config', 'agent-auth', 'rotate', '--agent-key-id', AGENT_KEY_ID, '--non-interactive', '--json'],
      { homeDir },
    );
    assert.notEqual(rotated.status, 0);

    const output = combinedOutput(rotated);
    assert.match(output, /must be owned by root/u);
    assert.match(output, /agentpay config unset daemonSocket/u);
    assert.match(output, /agentpay status --strict/u);
    assert.match(output, /agentpay admin setup --reuse-existing-wallet/u);
  } finally {
    socketServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('admin resume-manual-approval-request rejects pending approvals', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const socketServer = await startUnixSocket(socketPath);

  try {
    writeExecutable(path.join(rustBinDir, 'agentpay-agent'), 'printf "{}"');
    writeExecutable(
      path.join(rustBinDir, 'agentpay-admin'),
      [
        'printf "[{\\"id\\":\\"11111111-1111-4111-8111-111111111111\\",\\"agent_key_id\\":\\"' +
          AGENT_KEY_ID +
          '\\",\\"status\\":\\"pending\\",\\"action\\":{\\"kind\\":\\"BroadcastTx\\",\\"tx\\":{\\"chain_id\\":56,\\"nonce\\":1,\\"to\\":\\"' +
          ERC20_TOKEN +
          '\\",\\"value_wei\\":\\"0\\",\\"data_hex\\":\\"0x\\",\\"gas_limit\\":21000,\\"max_fee_per_gas_wei\\":\\"1\\",\\"max_priority_fee_per_gas_wei\\":\\"1\\",\\"tx_type\\":2,\\"delegation_enabled\\":false}},\\"chain_id\\":56,\\"asset\\":\\"erc20:' +
          ERC20_TOKEN.toLowerCase() +
          '\\",\\"recipient\\":\\"' +
          TO_ADDRESS.toLowerCase() +
          '\\",\\"amount_wei\\":\\"1\\"}]"',
      ].join('\n'),
    );
    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chains: {
        bsc: { chainId: 56, name: 'BSC', rpcUrl: 'https://bsc.drpc.org' },
      },
      wallet: {
        address: '0x1234567890123456789012345678901234567890',
        vaultKeyId: 'vault-key-resume',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    const resumed = runCli(
      [
        'admin',
        'resume-manual-approval-request',
        '--approval-request-id',
        '11111111-1111-4111-8111-111111111111',
        '--vault-password-stdin',
        '--no-wait',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: {
          AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP: '1',
        },
        input: 'vault-password\n',
      },
    );
    assert.equal(resumed.status, 1);
    assert.match(combinedOutput(resumed), /is still pending; approve it before resuming/u);
  } finally {
    socketServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('admin resume-manual-approval-request rejects non-broadcast manual approvals', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const socketServer = await startUnixSocket(socketPath);

  try {
    writeExecutable(path.join(rustBinDir, 'agentpay-agent'), 'printf "{}"');
    writeExecutable(
      path.join(rustBinDir, 'agentpay-admin'),
      [
        'printf "[{\\"id\\":\\"22222222-2222-4222-8222-222222222222\\",\\"agent_key_id\\":\\"' +
          AGENT_KEY_ID +
          '\\",\\"status\\":\\"approved\\",\\"action\\":{\\"kind\\":\\"Transfer\\",\\"chain_id\\":56,\\"token\\":\\"' +
          ERC20_TOKEN +
          '\\",\\"to\\":\\"' +
          TO_ADDRESS +
          '\\",\\"amount_wei\\":\\"1\\"},\\"chain_id\\":56,\\"asset\\":\\"erc20:' +
          ERC20_TOKEN.toLowerCase() +
          '\\",\\"recipient\\":\\"' +
          TO_ADDRESS.toLowerCase() +
          '\\",\\"amount_wei\\":\\"1\\"}]"',
      ].join('\n'),
    );
    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chains: {
        bsc: { chainId: 56, name: 'BSC', rpcUrl: 'https://bsc.drpc.org' },
      },
      wallet: {
        address: '0x1234567890123456789012345678901234567890',
        vaultKeyId: 'vault-key-resume',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    const resumed = runCli(
      [
        'admin',
        'resume-manual-approval-request',
        '--approval-request-id',
        '22222222-2222-4222-8222-222222222222',
        '--vault-password-stdin',
        '--no-wait',
      ],
      {
        homeDir,
        assumeRoot: true,
        env: {
          AGENTPAY_TEST_MOCK_ROOT_OWNERSHIP: '1',
        },
        input: 'vault-password\n',
      },
    );
    assert.equal(resumed.status, 1);
    assert.match(combinedOutput(resumed), /is not a resumable broadcast transaction/u);
  } finally {
    socketServer.close();
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});
