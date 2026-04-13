import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const scriptPath = path.join(process.cwd(), 'scripts', 'installer.sh');
const systemPath = process.env.PATH ?? '';
const pathShimMarker = '# agentpay-sdk one-click PATH shim';

function currentBundlePlatform() {
  return process.platform === 'darwin' ? 'macos' : process.platform === 'linux' ? 'linux' : process.platform;
}

function currentBundleArch() {
  return process.arch === 'x64' ? 'x64' : process.arch === 'arm64' ? 'arm64' : process.arch;
}

function runtimeEntriesForPlatform(platform) {
  const entries = new Map([
    [
      'agentpay-daemon',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake agentpay-daemon $*"\n',
    ],
    [
      'agentpay-admin',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake agentpay-admin $*"\n',
    ],
    [
      'agentpay-agent',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake agentpay-agent $*"\n',
    ],
  ]);

  if (platform === 'macos') {
    entries.set(
      'agentpay-system-keychain',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake agentpay-system-keychain $*"\n',
    );
    entries.set(
      'run-agentpay-daemon.sh',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake run-agentpay-daemon $*"\n',
    );
    entries.set(
      'install-user-daemon.sh',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake install-user-daemon $*"\n',
    );
    entries.set(
      'uninstall-user-daemon.sh',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake uninstall-user-daemon $*"\n',
    );
  } else if (platform === 'linux') {
    entries.set(
      'run-agentpay-daemon.sh',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake run-agentpay-daemon $*"\n',
    );
    entries.set(
      'agentpay-daemon-password-helper.sh',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake agentpay-daemon-password-helper $*"\n',
    );
    entries.set(
      'install-system-daemon.sh',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake install-system-daemon $*"\n',
    );
    entries.set(
      'uninstall-system-daemon.sh',
      '#!/usr/bin/env bash\nset -euo pipefail\necho "fake uninstall-system-daemon $*"\n',
    );
  }

  return entries;
}

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeExecutable(filePath, contents) {
  fs.writeFileSync(filePath, contents, 'utf8');
  fs.chmodSync(filePath, 0o755);
}

async function createFakeBundle(
  bundleDir,
  {
    omit = [],
    omitAgentTemplates = [],
    platform = currentBundlePlatform(),
    arch = currentBundleArch(),
  } = {},
) {
  await fsp.mkdir(path.join(bundleDir, 'app', 'dist'), { recursive: true });
  await fsp.mkdir(path.join(bundleDir, 'app', 'node_modules'), { recursive: true });
  await fsp.mkdir(path.join(bundleDir, 'runtime', 'bin'), { recursive: true });
  await fsp.mkdir(path.join(bundleDir, 'skills', 'agentpay-sdk', 'agents'), {
    recursive: true,
  });

  await fsp.writeFile(
    path.join(bundleDir, 'bundle-manifest.json'),
    `${JSON.stringify(
      {
        packageName: '@worldlibertyfinancial/agentpay-sdk',
        version: '0.0.0-test',
        platform,
        arch,
        bundleFormatVersion: 1,
      },
      null,
      2,
    )}\n`,
  );
  await fsp.writeFile(
    path.join(bundleDir, 'app', 'package.json'),
    JSON.stringify({ name: '@worldlibertyfinancial/agentpay-sdk', version: '0.0.0-test' }),
  );
  await fsp.writeFile(
    path.join(bundleDir, 'app', 'dist', 'cli.cjs'),
    [
      '#!/usr/bin/env node',
      'const args = process.argv.slice(2);',
      "if (args[0] === '--help') { console.log('fake agentpay'); process.exit(0); }",
      "if (args[0] === '--version' || args[0] === '-V') { console.log('0.0.0-test'); process.exit(0); }",
      "if (args[0] === '__print_agentpay_home') { console.log(process.env.AGENTPAY_HOME || ''); process.exit(0); }",
      "if (args[0] === 'admin' && args[1] === 'setup') { console.log('fake admin setup'); process.exit(0); }",
      "console.log(`fake agentpay ${args.join(' ')}`.trim());",
    ].join('\n'),
    'utf8',
  );

  const runtimeEntries = runtimeEntriesForPlatform(platform);

  for (const [entry, contents] of runtimeEntries) {
    if (omit.includes(entry)) {
      continue;
    }
    writeExecutable(path.join(bundleDir, 'runtime', 'bin', entry), contents);
  }

  await fsp.writeFile(
    path.join(bundleDir, 'skills', 'agentpay-sdk', 'SKILL.md'),
    '# Fixture skill\n',
  );
  const agentTemplates = new Map([
    ['AGENTS.md', '# Fixture agents\n'],
    ['CLAUDE.md', '# Fixture Claude adapter\n'],
    ['GEMINI.md', '# Fixture Gemini adapter\n'],
    ['copilot-instructions.md', '# Fixture Copilot adapter\n'],
    ['cline-agentpay-sdk.md', '# Fixture Cline adapter\n'],
    ['cursor-agentpay-sdk.mdc', '# Fixture cursor adapter\n'],
  ]);
  for (const [fileName, contents] of agentTemplates) {
    if (omitAgentTemplates.includes(fileName)) {
      continue;
    }
    await fsp.writeFile(
      path.join(bundleDir, 'skills', 'agentpay-sdk', 'agents', fileName),
      contents,
    );
  }
}

function createBundleArchive(bundleDir, archivePath) {
  const parentDir = path.dirname(bundleDir);
  const bundleName = path.basename(bundleDir);
  const result = spawnSync('tar', ['-czf', archivePath, '-C', parentDir, bundleName], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

function installFakeNode(binDir, { version = 'v24.6.0' } = {}) {
  writeExecutable(
    path.join(binDir, 'node'),
    `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "--version" ]]; then
  echo ${JSON.stringify(version)}
  exit 0
fi
exec ${JSON.stringify(process.execPath)} "$@"
`,
  );
}

function installFakeXattr(binDir, logPath) {
  writeExecutable(
    path.join(binDir, 'xattr'),
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> ${JSON.stringify(logPath)}
`,
  );
}

function installFakeUname(binDir, { kernelName, machine }) {
  writeExecutable(
    path.join(binDir, 'uname'),
    `#!/usr/bin/env bash
set -euo pipefail
case "\${1:-}" in
  -s)
    echo ${JSON.stringify(kernelName)}
    ;;
  -m)
    echo ${JSON.stringify(machine)}
    ;;
  *)
    echo ${JSON.stringify(kernelName)}
    ;;
esac
`,
  );
}

function installFakeHomebrew(binDir, prefixDir) {
  writeExecutable(
    path.join(binDir, 'brew'),
    `#!/usr/bin/env bash
set -euo pipefail
prefix=${JSON.stringify(prefixDir)}
node_prefix="$prefix/node@20"
case "\${1:-}" in
  shellenv)
    cat <<EOF_BREW_SHELLENV
export HOMEBREW_PREFIX="$prefix"
export PATH="$prefix/bin:\$PATH"
EOF_BREW_SHELLENV
    ;;
  --prefix)
    if [[ "\${2:-}" == "node@20" ]]; then
      echo "$node_prefix"
    else
      echo "$prefix"
    fi
    ;;
  install)
    mkdir -p "$node_prefix/bin"
    cat > "$node_prefix/bin/node" <<'EOF_BREW_NODE'
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "--version" ]]; then
  echo 'v24.6.0'
  exit 0
fi
exec ${JSON.stringify(process.execPath)} "$@"
EOF_BREW_NODE
    chmod 755 "$node_prefix/bin/node"
    ;;
  *)
    ;;
esac
`,
  );
}

function installFakeCurl(binDir, { expectedUrl, archivePath, failureMessage = '' }) {
  writeExecutable(
    path.join(binDir, 'curl'),
    `#!/usr/bin/env bash
set -euo pipefail
output=""
url=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -o)
      output="$2"
      shift 2
      ;;
    -fsSL|-f|-s|-S|-L)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done
if [[ -z "$url" ]]; then
  echo "missing curl url" >&2
  exit 1
fi
if [[ "$url" != ${JSON.stringify(expectedUrl)} ]]; then
  echo "unexpected curl url: $url" >&2
  exit 1
fi
if [[ -n ${JSON.stringify(failureMessage)} ]]; then
  echo ${JSON.stringify(failureMessage)} >&2
  exit 22
fi
if [[ -z "$output" ]]; then
  echo "missing curl output" >&2
  exit 1
fi
cp ${JSON.stringify(archivePath)} "$output"
`,
  );
}

async function publishInstallerAsset(destinationPath, { releaseRepo, releaseTag }) {
  const source = await fsp.readFile(scriptPath, 'utf8');
  const published = source
    .replaceAll('__AGENTPAY_PUBLIC_RELEASE_REPO__', releaseRepo)
    .replaceAll('__AGENTPAY_PUBLIC_RELEASE_TAG__', releaseTag);
  await fsp.writeFile(destinationPath, published, { mode: 0o755 });
}

function runShellScript({
  scriptFile,
  args = [],
  cwd,
  homeDir,
  installDir,
  fakeBinDir,
  input,
  extraEnv = {},
  pathValue,
}) {
  return spawnSync('bash', [scriptFile, ...args], {
    cwd: cwd ?? process.cwd(),
    encoding: 'utf8',
    input,
    env: {
      ...process.env,
      HOME: homeDir,
      PATH: pathValue ?? `${fakeBinDir}:${systemPath}`,
      SHELL: '/bin/zsh',
      TERM: 'dumb',
      AGENTPAY_SETUP_USE_STDIN: '1',
      ...(installDir ? { AGENTPAY_SETUP_DIR: installDir } : {}),
      ...extraEnv,
    },
  });
}

function runInstaller(options) {
  return runShellScript({
    scriptFile: scriptPath,
    ...options,
  });
}

test('installer.sh exposes a stable help entrypoint', () => {
  const result = spawnSync('bash', [scriptPath, '--help'], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });

  assert.equal(result.status, 0);
  assert.match(result.stdout, /AgentPay SDK one-click bootstrap/u);
  assert.match(result.stdout, /AGENTPAY_SDK_BUNDLE_URL/u);
  assert.match(result.stdout, /no local Rust build/u);
  assert.equal(result.stderr, '');
});

test('installer can complete a fresh bundle-based install and rerun without duplicating shell exports', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-test-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  const xattrLogPath = path.join(sandboxDir, 'xattr.log');
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await fsp.writeFile(
    path.join(homeDir, '.zshrc'),
    [
      'export PATH="$HOME/.local/bin:$PATH"',
      'alias ll="ls -la"',
      '',
    ].join('\n'),
    'utf8',
  );
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);
  installFakeXattr(fakeBinDir, xattrLogPath);

  const firstRun = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: `${installDir}\n`,
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
    },
  });

  assert.equal(firstRun.status, 0, firstRun.stderr || firstRun.stdout);
  assert.match(firstRun.stdout, /AgentPay SDK install complete/u);
  assert.match(firstRun.stdout, /Run now in this shell:/u);
  assert.match(firstRun.stdout, /agentpay --help/u);
  assert.match(firstRun.stdout, /Current-shell shim:/u);
  assert.ok(fs.existsSync(path.join(installDir, 'bin', 'agentpay')));
  assert.equal(fs.statSync(path.join(installDir, 'bin')).mode & 0o777, 0o700);
  assert.ok(fs.existsSync(path.join(installDir, 'app', 'dist', 'cli.cjs')));
  assert.ok(fs.existsSync(path.join(installDir, 'app', 'node_modules')));
  assert.ok(
    fs.existsSync(path.join(installDir, 'one-click-install-manifest.json')),
  );
  assert.ok(fs.existsSync(path.join(fakeBinDir, 'agentpay')));
  assert.match(fs.readFileSync(path.join(fakeBinDir, 'agentpay'), 'utf8'), new RegExp(pathShimMarker.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'u'));
  assert.equal(fs.existsSync(path.join(installDir, 'bin')), true);
  if (process.platform === 'darwin') {
    const xattrLog = await fsp.readFile(xattrLogPath, 'utf8');
    assert.match(xattrLog, /-dr com\.apple\.quarantine/u);
    assert.match(xattrLog, new RegExp(installDir.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'u'));
  }

  const immediateVersion = spawnSync('agentpay', ['--version'], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: homeDir,
      PATH: `${fakeBinDir}:${systemPath}`,
    },
  });
  assert.equal(immediateVersion.status, 0, immediateVersion.stderr || immediateVersion.stdout);
  assert.equal(immediateVersion.stdout.trim(), '0.0.0-test');

  const directLauncherHome = spawnSync(
    path.join(installDir, 'bin', 'agentpay'),
    ['__print_agentpay_home'],
    {
      cwd: process.cwd(),
      encoding: 'utf8',
      env: {
        ...process.env,
        HOME: homeDir,
        PATH: `${fakeBinDir}:${systemPath}`,
      },
    },
  );
  assert.equal(directLauncherHome.status, 0, directLauncherHome.stderr || directLauncherHome.stdout);
  assert.equal(directLauncherHome.stdout.trim(), installDir);

  const shimLauncherHome = spawnSync('agentpay', ['__print_agentpay_home'], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: homeDir,
      PATH: `${fakeBinDir}:${systemPath}`,
    },
  });
  assert.equal(shimLauncherHome.status, 0, shimLauncherHome.stderr || shimLauncherHome.stdout);
  assert.equal(shimLauncherHome.stdout.trim(), installDir);

  const manifest = JSON.parse(
    await fsp.readFile(path.join(installDir, 'one-click-install-manifest.json'), 'utf8'),
  );
  assert.deepEqual(manifest.pathShimPaths, [path.join(fakeBinDir, 'agentpay')]);

  const secondRun = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: `${installDir}\n`,
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
    },
  });

  assert.equal(secondRun.status, 0, secondRun.stderr || secondRun.stdout);

  const zshrc = await fsp.readFile(path.join(homeDir, '.zshrc'), 'utf8');
  const blockMatches = zshrc.match(/# >>> agentpay-sdk >>>/gu) ?? [];
  assert.equal(blockMatches.length, 1);
  assert.match(zshrc, /export PATH="\$HOME\/\.local\/bin:\$PATH"/u);
  assert.match(zshrc, /alias ll="ls -la"/u);
});

test('installer falls back to shell reload instructions when an earlier PATH entry already owns agentpay', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-shim-conflict-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);
  writeExecutable(
    path.join(fakeBinDir, 'agentpay'),
    '#!/usr/bin/env bash\nset -euo pipefail\necho external agentpay\n',
  );

  const result = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: `${installDir}\n`,
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
    },
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /Your current shell still needs the updated PATH:/u);
  assert.match(result.stdout, /Current-shell shim was skipped:/u);
  assert.match(result.stdout, /already exists and is not managed by this installer/u);
  assert.doesNotMatch(fs.readFileSync(path.join(fakeBinDir, 'agentpay'), 'utf8'), new RegExp(pathShimMarker.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'u'));
  const manifest = JSON.parse(
    await fsp.readFile(path.join(installDir, 'one-click-install-manifest.json'), 'utf8'),
  );
  assert.deepEqual(manifest.pathShimPaths, []);
});

test('installer defaults to ~/.agentpay when no explicit install directory is provided', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-default-root-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const defaultInstallDir = path.join(homeDir, '.agentpay');
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);

  const result = runInstaller({
    homeDir,
    installDir: undefined,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
    },
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, new RegExp(defaultInstallDir.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'u'));
  assert.ok(fs.existsSync(path.join(defaultInstallDir, 'bin', 'agentpay')));
  assert.ok(fs.existsSync(path.join(defaultInstallDir, 'config.json')) === false);
});

test('installer falls through to bundle download when published release repo and tag were not injected', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-release-download-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const installDir = path.join(sandboxDir, 'install-root');
  const bundleName = `agentpay-sdk-${currentBundlePlatform()}-${currentBundleArch()}.tar.gz`;
  const unresolvedBundleUrl =
    `https://github.com/__AGENTPAY_PUBLIC_RELEASE_REPO__/releases/download/__AGENTPAY_PUBLIC_RELEASE_TAG__/${bundleName}`;
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  installFakeCurl(fakeBinDir, {
    expectedUrl: unresolvedBundleUrl,
    archivePath: path.join(sandboxDir, 'unused.tar.gz'),
    failureMessage: 'fixture curl failure',
  });

  const result = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Could not download the AgentPay SDK bundle/u);
  assert.match(result.stderr, /__AGENTPAY_PUBLIC_RELEASE_REPO__/u);
  assert.match(result.stderr, /__AGENTPAY_PUBLIC_RELEASE_TAG__/u);
  assert.doesNotMatch(result.stderr, /Installer release metadata was not injected/u);
});

test('published installer asset accepts injected release metadata and resolves the default bundle URL', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-published-installer-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  const publishedScriptPath = path.join(sandboxDir, 'installer-published.sh');
  const releaseRepo = 'acme/agentpay-sdk';
  const releaseTag = 'v9.9.9';
  const bundleName = `agentpay-sdk-${currentBundlePlatform()}-${currentBundleArch()}.tar.gz`;
  const expectedBundleUrl = `https://github.com/${releaseRepo}/releases/download/${releaseTag}/${bundleName}`;
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  await publishInstallerAsset(publishedScriptPath, { releaseRepo, releaseTag });
  installFakeCurl(fakeBinDir, { expectedUrl: expectedBundleUrl, archivePath });
  installFakeNode(fakeBinDir);

  const result = runShellScript({
    scriptFile: publishedScriptPath,
    homeDir,
    installDir,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
    },
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.doesNotMatch(result.stderr, /Installer release metadata was not injected/u);
  assert.match(result.stdout, /AgentPay SDK install complete/u);
  assert.ok(fs.existsSync(path.join(installDir, 'bin', 'agentpay')));
});

test('installer accepts a Linux runtime bundle without macOS-only helper entries', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-linux-bundle-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await createFakeBundle(fixtureBundleDir, { platform: 'linux', arch: 'x64' });
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);
  installFakeUname(fakeBinDir, { kernelName: 'Linux', machine: 'x86_64' });

  const result = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
    },
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /AgentPay SDK install complete/u);
  assert.match(result.stdout, /Managed wallet setup is supported on macOS and Linux/u);
  assert.ok(fs.existsSync(path.join(installDir, 'bin', 'agentpay')));
  assert.ok(fs.existsSync(path.join(installDir, 'bin', 'agentpay-daemon')));
  assert.ok(fs.existsSync(path.join(installDir, 'bin', 'agentpay-admin')));
  assert.ok(fs.existsSync(path.join(installDir, 'bin', 'agentpay-agent')));
  assert.equal(fs.existsSync(path.join(installDir, 'bin', 'agentpay-system-keychain')), false);
  assert.equal(fs.existsSync(path.join(installDir, 'bin', 'agentpay-daemon-password-helper.sh')), true);
});

test('installer rejects a runtime bundle built for a different platform', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-platform-mismatch-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await createFakeBundle(fixtureBundleDir, { platform: 'macos', arch: 'x64' });
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);
  installFakeUname(fakeBinDir, { kernelName: 'Linux', machine: 'x86_64' });

  const result = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /did not contain a usable AgentPay SDK runtime bundle/u);
});

test('installer does not install a Cursor adapter when no cursor workspace is available', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-cursor-skip-');
  const neutralCwd = path.join(sandboxDir, 'neutral-cwd');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  await fsp.mkdir(neutralCwd, { recursive: true });
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);

  const result = runInstaller({
    cwd: neutralCwd,
    homeDir,
    installDir,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'yes',
    },
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.doesNotMatch(result.stdout, /Installing Cursor workspace adapter/u);
  const manifest = JSON.parse(
    await fsp.readFile(path.join(installDir, 'one-click-install-manifest.json'), 'utf8'),
  );
  assert.deepEqual(manifest.cursorArtifactPaths, []);
});

test('installer auto-installs detected Codex and generic agents skill targets', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-codex-');
  const neutralCwd = path.join(sandboxDir, 'neutral-cwd');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  const cursorWorkspace = path.join(sandboxDir, 'cursor-workspace');
  await fsp.mkdir(neutralCwd, { recursive: true });
  await fsp.mkdir(path.join(homeDir, '.codex'), { recursive: true });
  await fsp.mkdir(path.join(homeDir, '.agents'), { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await fsp.mkdir(cursorWorkspace, { recursive: true });
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);

  const result = runInstaller({
    cwd: neutralCwd,
    homeDir,
    installDir,
    fakeBinDir,
    input: `${installDir}\n`,
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_INSTALL_SKILLS: 'auto',
      AGENTPAY_SETUP_CURSOR_WORKSPACE: cursorWorkspace,
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
    },
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.ok(
    fs.existsSync(path.join(homeDir, '.codex', 'skills', 'agentpay-sdk', 'SKILL.md')),
  );
  assert.ok(
    fs.existsSync(path.join(homeDir, '.agents', 'skills', 'agentpay-sdk', 'SKILL.md')),
  );
});

test('installer can install all AI integrations when requested explicitly', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-skills-defaults-');
  const workspaceDir = path.join(sandboxDir, 'workspace');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  const cursorWorkspace = path.join(sandboxDir, 'cursor-workspace');
  await fsp.mkdir(workspaceDir, { recursive: true });
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await fsp.mkdir(cursorWorkspace, { recursive: true });
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);

  const result = runInstaller({
    cwd: workspaceDir,
    homeDir,
    installDir,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'yes',
      AGENTPAY_SETUP_WORKSPACE: workspaceDir,
      AGENTPAY_SETUP_CURSOR_WORKSPACE: cursorWorkspace,
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
    },
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.ok(
    fs.existsSync(path.join(homeDir, '.codex', 'skills', 'agentpay-sdk', 'SKILL.md')),
  );
  assert.ok(
    fs.existsSync(path.join(homeDir, '.agents', 'skills', 'agentpay-sdk', 'SKILL.md')),
  );
  assert.ok(
    fs.existsSync(path.join(homeDir, '.openclaw', 'skills', 'agentpay-sdk', 'SKILL.md')),
  );
  assert.ok(
    fs.existsSync(path.join(homeDir, '.claude', 'skills', 'agentpay-sdk', 'SKILL.md')),
  );
  assert.ok(fs.existsSync(path.join(workspaceDir, 'AGENTS.md')));
  assert.ok(fs.existsSync(path.join(workspaceDir, 'CLAUDE.md')));
  assert.ok(fs.existsSync(path.join(workspaceDir, 'GEMINI.md')));
  assert.ok(fs.existsSync(path.join(workspaceDir, '.github', 'copilot-instructions.md')));
  assert.ok(fs.existsSync(path.join(workspaceDir, '.clinerules', 'agentpay-sdk.md')));
  assert.ok(
    fs.existsSync(path.join(cursorWorkspace, '.cursor', 'rules', 'agentpay-sdk.mdc')),
  );
});

test('skills-only install tolerates bundles missing newer adapter templates', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-legacy-skills-');
  const workspaceDir = path.join(sandboxDir, 'workspace');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const cursorWorkspace = path.join(sandboxDir, 'cursor-workspace');
  await fsp.mkdir(workspaceDir, { recursive: true });
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await fsp.mkdir(cursorWorkspace, { recursive: true });
  await createFakeBundle(fixtureBundleDir, {
    omitAgentTemplates: ['GEMINI.md', 'copilot-instructions.md', 'cline-agentpay-sdk.md'],
  });
  createBundleArchive(fixtureBundleDir, archivePath);

  const result = runInstaller({
    args: ['--skills-only'],
    cwd: workspaceDir,
    homeDir,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'yes',
      AGENTPAY_SETUP_WORKSPACE: workspaceDir,
      AGENTPAY_SETUP_CURSOR_WORKSPACE: cursorWorkspace,
    },
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stderr, /missing some optional adapters/u);
  assert.ok(
    fs.existsSync(path.join(homeDir, '.codex', 'skills', 'agentpay-sdk', 'SKILL.md')),
  );
  assert.ok(fs.existsSync(path.join(workspaceDir, 'AGENTS.md')));
  assert.ok(fs.existsSync(path.join(workspaceDir, 'CLAUDE.md')));
  assert.ok(fs.existsSync(path.join(cursorWorkspace, '.cursor', 'rules', 'agentpay-sdk.mdc')));
  assert.ok(fs.existsSync(path.join(workspaceDir, 'GEMINI.md')) === false);
  assert.ok(
    fs.existsSync(path.join(workspaceDir, '.github', 'copilot-instructions.md')) === false,
  );
  assert.ok(
    fs.existsSync(path.join(workspaceDir, '.clinerules', 'agentpay-sdk.md')) === false,
  );
});

test('installer fails closed when the bundle is missing a required runtime entry', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-runtime-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await createFakeBundle(fixtureBundleDir, { omit: ['agentpay-daemon'] });
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);

  const result = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: `${installDir}\n`,
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /did not contain a usable AgentPay SDK runtime bundle/u);
});

test('installer rejects legacy relay setup flags with a clear error', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-relay-legacy-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);

  const result = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: `${installDir}\n`,
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_RELAY_MODE: 'remote',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Relay setup is not part of the one-click installer/u);
});

test('installer rejects admin setup in non-interactive mode with a clear message', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-admin-tty-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir);

  const result = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'yes',
    },
  });

  assert.notEqual(result.status, 0);
  if (process.platform === 'darwin' || process.platform === 'linux') {
    assert.match(result.stderr, /requires a local TTY for secure password prompts/u);
  } else {
    assert.match(result.stderr, /is not supported on this platform yet/u);
  }
});

test('installer fails clearly when Homebrew bootstrap would be required without a local TTY', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-homebrew-tty-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir, { version: 'v18.19.0' });

  const result = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
      AGENTPAY_SETUP_SKIP_SYSTEM_BREW_LOOKUP: '1',
    },
    pathValue: `${fakeBinDir}:/usr/bin:/bin:/usr/sbin:/sbin`,
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Homebrew bootstrap requires a local TTY/u);
  assert.match(result.stderr, /Install Homebrew manually first/u);
});

test('installer can bootstrap Node via Homebrew when node is missing', async () => {
  const sandboxDir = makeTempDir('agentpay-setup-node-brew-');
  const homeDir = path.join(sandboxDir, 'home');
  const fakeBinDir = path.join(sandboxDir, 'fake-bin');
  const fakeBrewPrefix = path.join(sandboxDir, 'fake-brew-prefix');
  const fixtureBundleDir = path.join(sandboxDir, 'fixture-bundle');
  const archivePath = path.join(sandboxDir, 'fixture-bundle.tar.gz');
  const installDir = path.join(sandboxDir, 'install-root');
  await fsp.mkdir(homeDir, { recursive: true });
  await fsp.mkdir(fakeBinDir, { recursive: true });
  await fsp.mkdir(fakeBrewPrefix, { recursive: true });
  await createFakeBundle(fixtureBundleDir);
  createBundleArchive(fixtureBundleDir, archivePath);
  installFakeNode(fakeBinDir, { version: 'v18.19.0' });
  installFakeHomebrew(fakeBinDir, fakeBrewPrefix);

  const result = runInstaller({
    homeDir,
    installDir,
    fakeBinDir,
    input: '',
    extraEnv: {
      AGENTPAY_SDK_BUNDLE_URL: `file://${archivePath}`,
      AGENTPAY_SETUP_ASSUME_DEFAULTS: '1',
      AGENTPAY_SETUP_INSTALL_SKILLS: 'no',
      AGENTPAY_SETUP_RUN_ADMIN_SETUP: 'no',
    },
    pathValue: `${fakeBinDir}:/usr/bin:/bin:/usr/sbin:/sbin`,
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.ok(fs.existsSync(path.join(fakeBrewPrefix, 'node@20', 'bin', 'node')));
  assert.ok(fs.existsSync(path.join(installDir, 'bin', 'agentpay')));
});
