import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os, { constants as osConstants } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const extension = process.platform === 'win32' ? '.exe' : '';
const MIN_RUST_VERSION = {
  major: 1,
  minor: 87,
  patch: 0,
};
const rustBins = [
  'agentpay-daemon',
  'agentpay-admin',
  'agentpay-agent',
  'agentpay-system-keychain',
];
const RERUN_INSTRUCTIONS =
  'After installing prerequisites, rerun the source install steps from this repo checkout: `npm run build && npm run install:cli-launcher && npm run install:rust-binaries`.';

function fileUrlToPathForPlatform(fileUrl, platform = process.platform) {
  if (platform === process.platform) {
    return fileURLToPath(fileUrl);
  }

  const parsed = new URL(fileUrl);
  if (parsed.protocol !== 'file:') {
    throw new TypeError(`[agentpay] Expected a file URL, received ${parsed.protocol}`);
  }

  if (platform === 'win32') {
    const pathname = decodeURIComponent(parsed.pathname).replace(/\//g, '\\');
    if (parsed.hostname) {
      return `\\\\${parsed.hostname}${pathname}`;
    }
    if (/^\\[a-zA-Z]:/.test(pathname)) {
      return pathname.slice(1);
    }
    return pathname;
  }

  return decodeURIComponent(parsed.pathname);
}

export function resolveRepoRootFromMetaUrl(
  metaUrl = import.meta.url,
  platform = process.platform,
) {
  const scriptPath = fileUrlToPathForPlatform(metaUrl, platform);
  const pathImpl = platform === 'win32' ? path.win32 : path.posix;
  return pathImpl.resolve(pathImpl.dirname(scriptPath), '..');
}

const repoRoot = resolveRepoRootFromMetaUrl(import.meta.url);

function decodeOutput(value) {
  if (!value) {
    return '';
  }
  return value.toString().trim();
}

function formatMinimumRustVersion() {
  return `${MIN_RUST_VERSION.major}.${MIN_RUST_VERSION.minor}.${MIN_RUST_VERSION.patch}`;
}

function parseRustVersion(output) {
  const match = output.match(/\b(\d+)\.(\d+)\.(\d+)(?:[-+][^\s]+)?\b/);
  if (!match) {
    return null;
  }
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

function compareVersions(left, right) {
  if (left.major !== right.major) {
    return left.major - right.major;
  }
  if (left.minor !== right.minor) {
    return left.minor - right.minor;
  }
  return left.patch - right.patch;
}

function runCheck(spawnSyncImpl, command, args, options = {}) {
  return spawnSyncImpl(command, args, {
    cwd: repoRoot,
    stdio: 'pipe',
    ...options,
  });
}

function signalExitCode(signal) {
  if (!signal) {
    return 1;
  }

  const signalNumber = osConstants.signals[signal];
  return typeof signalNumber === 'number' ? 128 + signalNumber : 128;
}

function normalizedExitCode(status, signal) {
  return status ?? signalExitCode(signal);
}

function throwSignaledCheckFailure(commandLabel, signal, exitCode) {
  throw new Error(
    `[agentpay] ${commandLabel} was terminated by ${signal} (exit code ${exitCode}).\n` +
      `[agentpay] ${RERUN_INSTRUCTIONS}`,
  );
}

function resolveAgentPayPaths(env) {
  const agentpayHome = env.AGENTPAY_HOME?.trim() || path.join(os.homedir(), '.agentpay');
  return {
    agentpayHome,
    binDir: path.join(agentpayHome, 'bin'),
  };
}

function resolveHelperScripts(binDir) {
  return [
    {
      source: path.join(repoRoot, 'scripts', 'launchd', 'run-agentpay-daemon.sh'),
      destination: path.join(binDir, 'run-agentpay-daemon.sh'),
    },
    {
      source: path.join(repoRoot, 'scripts', 'launchd', 'install-user-daemon.sh'),
      destination: path.join(binDir, 'install-user-daemon.sh'),
    },
    {
      source: path.join(repoRoot, 'scripts', 'launchd', 'uninstall-user-daemon.sh'),
      destination: path.join(binDir, 'uninstall-user-daemon.sh'),
    },
  ];
}

function resolveCliEntrypoint() {
  return path.join(repoRoot, 'dist', 'cli.cjs');
}

function escapePosixShellArgument(value) {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function installCliLauncher({
  binDir,
  cliEntrypoint = resolveCliEntrypoint(),
  platform = process.platform,
  allowMissingEntrypoint = false,
} = {}) {
  if (!binDir) {
    throw new Error('[agentpay] binDir is required to install the CLI launcher.');
  }

  fs.mkdirSync(binDir, { recursive: true, mode: 0o700 });

  if (!fs.existsSync(cliEntrypoint)) {
    if (allowMissingEntrypoint) {
      return false;
    }
    throw new Error(
      `[agentpay] CLI entrypoint was not found at ${cliEntrypoint}. Run \`npm run build\` first.`,
    );
  }

  if (platform === 'win32') {
    const destination = path.join(binDir, 'agentpay.cmd');
    const escaped = cliEntrypoint.replace(/"/g, '""');
    fs.writeFileSync(destination, `@echo off\r\nnode "${escaped}" %*\r\n`, {
      mode: 0o755,
    });
    return true;
  }

  const destination = path.join(binDir, 'agentpay');
  const script = `#!/bin/sh\nexec node ${escapePosixShellArgument(cliEntrypoint)} "$@"\n`;
  fs.writeFileSync(destination, script, { mode: 0o755 });
  fs.chmodSync(destination, 0o755);
  return true;
}

function checkCargoAvailable(spawnSyncImpl) {
  const result = runCheck(spawnSyncImpl, 'cargo', ['--version']);
  const exitCode = normalizedExitCode(result.status, result.signal);
  if (exitCode === 0) {
    return;
  }
  if (result.signal) {
    throwSignaledCheckFailure('Rust toolchain check (`cargo --version`)', result.signal, exitCode);
  }

  const detail = decodeOutput(result.stderr) || decodeOutput(result.stdout);
  const lines = [
    '[agentpay] Rust toolchain was not found on PATH.',
    '[agentpay] Install Rust from https://rustup.rs.',
  ];
  if (detail) {
    lines.push(`[agentpay] cargo check output: ${detail}`);
  }
  lines.push(`[agentpay] ${RERUN_INSTRUCTIONS}`);
  throw new Error(lines.join('\n'));
}

function checkRustcVersion(spawnSyncImpl) {
  const result = runCheck(spawnSyncImpl, 'rustc', ['--version']);
  const exitCode = normalizedExitCode(result.status, result.signal);
  if (exitCode !== 0) {
    if (result.signal) {
      throwSignaledCheckFailure('Rust compiler check (`rustc --version`)', result.signal, exitCode);
    }

    const detail = decodeOutput(result.stderr) || decodeOutput(result.stdout);
    const lines = [
      '[agentpay] Rust compiler was not found on PATH.',
      `[agentpay] Install Rust ${formatMinimumRustVersion()} or newer from https://rustup.rs.`,
    ];
    if (detail) {
      lines.push(`[agentpay] rustc check output: ${detail}`);
    }
    lines.push(`[agentpay] ${RERUN_INSTRUCTIONS}`);
    throw new Error(lines.join('\n'));
  }

  const versionOutput = decodeOutput(result.stdout) || decodeOutput(result.stderr);
  const parsedVersion = parseRustVersion(versionOutput);
  if (!parsedVersion) {
    throw new Error(
      `[agentpay] Unable to determine the installed Rust compiler version from: ${versionOutput || '<empty output>'}`,
    );
  }

  if (compareVersions(parsedVersion, MIN_RUST_VERSION) < 0) {
    throw new Error(
      `[agentpay] Rust ${formatMinimumRustVersion()} or newer is required; found ${versionOutput}.\n` +
        `[agentpay] Update Rust with \`rustup update\`.\n` +
        `[agentpay] ${RERUN_INSTRUCTIONS}`,
    );
  }
}

function checkMacOsToolchainAvailable(spawnSyncImpl, platform) {
  if (platform !== 'darwin') {
    return;
  }

  const result = runCheck(spawnSyncImpl, 'xcrun', ['--sdk', 'macosx', '--find', 'clang']);
  const exitCode = normalizedExitCode(result.status, result.signal);
  if (exitCode === 0) {
    return;
  }
  if (result.signal) {
    throwSignaledCheckFailure(
      'macOS Command Line Tools check (`xcrun --sdk macosx --find clang`)',
      result.signal,
      exitCode,
    );
  }

  const detail = decodeOutput(result.stderr) || decodeOutput(result.stdout);
  const lines = [
    '[agentpay] macOS Command Line Tools were not found or are not configured.',
    '[agentpay] Install them with `xcode-select --install`.',
  ];
  if (detail) {
    lines.push(`[agentpay] xcrun check output: ${detail}`);
  }
  lines.push(`[agentpay] ${RERUN_INSTRUCTIONS}`);
  throw new Error(lines.join('\n'));
}

export function verifyRustInstallPrerequisites({
  spawnSyncImpl = spawnSync,
  platform = process.platform,
} = {}) {
  checkCargoAvailable(spawnSyncImpl);
  checkRustcVersion(spawnSyncImpl);
  checkMacOsToolchainAvailable(spawnSyncImpl, platform);
}

export function installRustBinaries({
  spawnSyncImpl = spawnSync,
  env = process.env,
  platform = process.platform,
} = {}) {
  if (env.AGENTPAY_SKIP_RUST_INSTALL === '1') {
    return 0;
  }

  verifyRustInstallPrerequisites({ spawnSyncImpl, platform });

  const { agentpayHome, binDir } = resolveAgentPayPaths(env);
  const helperScripts = resolveHelperScripts(binDir);

  fs.mkdirSync(binDir, { recursive: true, mode: 0o700 });
  const build = spawnSyncImpl(
    'cargo',
    [
      'build',
      '--locked',
      '--release',
      '-p',
      'agentpay-daemon',
      '-p',
      'agentpay-admin',
      '-p',
      'agentpay-agent',
    ],
    { cwd: repoRoot, stdio: 'inherit' },
  );
  const buildExitCode = normalizedExitCode(build.status, build.signal);
  if (buildExitCode !== 0) {
    return buildExitCode;
  }

  for (const binary of rustBins) {
    const source = path.join(repoRoot, 'target', 'release', binary + extension);
    const destination = path.join(binDir, binary + extension);
    fs.copyFileSync(source, destination);
    if (platform !== 'win32') {
      fs.chmodSync(destination, 0o755);
    }
  }

  for (const script of helperScripts) {
    fs.copyFileSync(script.source, script.destination);
    if (platform !== 'win32') {
      fs.chmodSync(script.destination, 0o755);
    }
  }

  const configPath = path.join(agentpayHome, 'config.json');
  if (!fs.existsSync(configPath)) {
    fs.writeFileSync(
      configPath,
      `${JSON.stringify(
        {
          daemonSocket: path.join(agentpayHome, 'daemon.sock'),
          stateFile: path.join(agentpayHome, 'daemon-state.enc'),
          rustBinDir: binDir,
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );
  }

  return 0;
}

function isDirectExecution() {
  return (
    Boolean(process.argv[1]) &&
    import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
  );
}

if (isDirectExecution()) {
  try {
    process.exitCode = installRustBinaries();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}
