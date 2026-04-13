#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(scriptPath), '..');
const commonRuntimeBinaries = ['agentpay-daemon', 'agentpay-admin', 'agentpay-agent'];
const macosRuntimeBinaries = ['agentpay-system-keychain'];
const macosHelperScripts = [
  'run-agentpay-daemon.sh',
  'install-user-daemon.sh',
  'uninstall-user-daemon.sh',
];
const linuxHelperScripts = [
  'run-agentpay-daemon.sh',
  'agentpay-daemon-password-helper.sh',
  'install-system-daemon.sh',
  'uninstall-system-daemon.sh',
];

function die(message) {
  process.stderr.write(`[agentpay-bundle] ${message}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  const options = {
    output: '',
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case '--output':
      case '-o':
        options.output = argv[index + 1] ?? '';
        index += 1;
        break;
      case '--help':
      case '-h':
        process.stdout.write(
          [
            'Build a precompiled AgentPay installer bundle.',
            '',
            'Usage:',
            '  node scripts/build-installer-bundle.mjs --output <archive.tar.gz>',
            '',
            'Prerequisites:',
            '  - pnpm install has completed',
            '  - npm run build has completed',
            '  - cargo build --locked --release for the AgentPay SDK runtime binaries has completed',
          ].join('\n') + '\n',
        );
        process.exit(0);
      default:
        die(`Unknown option: ${argument}`);
    }
  }

  if (!options.output) {
    options.output = path.join(repoRoot, defaultArchiveFileName());
  }

  return options;
}

function bundlePlatformLabel(platform = process.platform) {
  switch (platform) {
    case 'darwin':
      return 'macos';
    case 'linux':
      return 'linux';
    default:
      die(`the installer bundle is currently built only on macOS or Linux, not ${platform}`);
  }
}

function archLabel(arch = process.arch) {
  return arch === 'arm64' ? 'arm64' : arch === 'x64' ? 'x64' : arch;
}

function defaultArchiveFileName(platform = process.platform, arch = process.arch) {
  return `agentpay-sdk-${bundlePlatformLabel(platform)}-${archLabel(arch)}.tar.gz`;
}

function runtimeBinariesForPlatform(platform = process.platform) {
  if (platform === 'darwin') {
    return [...commonRuntimeBinaries, ...macosRuntimeBinaries];
  }
  return [...commonRuntimeBinaries];
}

function helperScriptsForPlatform(platform = process.platform) {
  if (platform === 'darwin') {
    return [...macosHelperScripts];
  }
  if (platform === 'linux') {
    return [...linuxHelperScripts];
  }
  return [];
}

function assertExists(targetPath, label) {
  if (!fs.existsSync(targetPath)) {
    die(`${label} is missing at ${targetPath}`);
  }
}

function copyExecutable(sourcePath, destinationPath) {
  fs.copyFileSync(sourcePath, destinationPath);
  fs.chmodSync(destinationPath, 0o755);
}

function createTempRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bundle-'));
}

function tarDirectory(sourceDir, outputPath) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  const tar = spawnSync('tar', ['-czf', outputPath, '-C', sourceDir, '.'], {
    cwd: repoRoot,
    stdio: 'pipe',
  });
  if (tar.status !== 0) {
    const detail = tar.stderr?.toString('utf8').trim() || tar.stdout?.toString('utf8').trim();
    die(`failed to create bundle archive: ${detail || 'tar exited with an error'}`);
  }
}

function stageProductionNodeModules(packageName, targetDir) {
  const deploy = spawnSync(
    'pnpm',
    ['--filter', packageName, 'deploy', '--legacy', '--prod', '--ignore-scripts', targetDir],
    {
      cwd: repoRoot,
      stdio: 'pipe',
    },
  );
  if (deploy.status !== 0) {
    const detail = deploy.stderr?.toString('utf8').trim() || deploy.stdout?.toString('utf8').trim();
    die(
      `failed to stage production app dependencies with pnpm deploy: ${detail || 'pnpm exited with an error'}`,
    );
  }
}

function main() {
  const { output } = parseArgs(process.argv.slice(2));
  const packageJsonPath = path.join(repoRoot, 'package.json');
  const distDir = path.join(repoRoot, 'dist');
  const cliEntrypoint = path.join(distDir, 'cli.cjs');
  const runtimeDir = path.join(repoRoot, 'target', 'release');
  const skillsDir = path.join(repoRoot, 'skills', 'agentpay-sdk');
  const runtimeBinaries = runtimeBinariesForPlatform();
  const helperScripts = helperScriptsForPlatform();

  bundlePlatformLabel();

  assertExists(packageJsonPath, 'package.json');
  assertExists(distDir, 'dist output');
  assertExists(cliEntrypoint, 'CLI entrypoint');
  assertExists(skillsDir, 'AgentPay skill pack');
  assertExists(path.join(skillsDir, 'agents', 'AGENTS.md'), 'AGENTS adapter');
  assertExists(path.join(skillsDir, 'agents', 'CLAUDE.md'), 'Claude adapter');
  assertExists(path.join(skillsDir, 'agents', 'GEMINI.md'), 'Gemini adapter');
  assertExists(path.join(skillsDir, 'agents', 'copilot-instructions.md'), 'Copilot adapter');
  assertExists(path.join(skillsDir, 'agents', 'cline-agentpay-sdk.md'), 'Cline adapter');
  assertExists(path.join(skillsDir, 'agents', 'cursor-agentpay-sdk.mdc'), 'Cursor adapter');

  for (const binary of runtimeBinaries) {
    assertExists(path.join(runtimeDir, binary), `runtime binary ${binary}`);
  }
  for (const helper of helperScripts) {
    assertExists(
      path.join(repoRoot, 'scripts', process.platform === 'darwin' ? 'launchd' : 'systemd', helper),
      `managed daemon helper ${helper}`,
    );
  }

  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const stagingRoot = createTempRoot();
  const bundleRoot = path.join(stagingRoot, 'bundle');
  const appRoot = path.join(bundleRoot, 'app');
  const bundleRuntimeDir = path.join(bundleRoot, 'runtime', 'bin');
  const bundleSkillsDir = path.join(bundleRoot, 'skills');
  const deployRoot = path.join(stagingRoot, 'deploy');

  try {
    fs.mkdirSync(appRoot, { recursive: true });
    fs.mkdirSync(bundleRuntimeDir, { recursive: true });
    fs.mkdirSync(bundleSkillsDir, { recursive: true });

    fs.copyFileSync(packageJsonPath, path.join(appRoot, 'package.json'));
    fs.cpSync(distDir, path.join(appRoot, 'dist'), { recursive: true });
    stageProductionNodeModules(packageJson.name, deployRoot);
    assertExists(path.join(deployRoot, 'node_modules'), 'production app node_modules');
    fs.cpSync(path.join(deployRoot, 'node_modules'), path.join(appRoot, 'node_modules'), {
      recursive: true,
      verbatimSymlinks: true,
    });

    for (const binary of runtimeBinaries) {
      copyExecutable(path.join(runtimeDir, binary), path.join(bundleRuntimeDir, binary));
    }
    for (const helper of helperScripts) {
      copyExecutable(
        path.join(
          repoRoot,
          'scripts',
          process.platform === 'darwin' ? 'launchd' : 'systemd',
          helper,
        ),
        path.join(bundleRuntimeDir, helper),
      );
    }

    fs.cpSync(skillsDir, path.join(bundleSkillsDir, 'agentpay-sdk'), { recursive: true });

    const manifest = {
      packageName: packageJson.name,
      version: packageJson.version,
      platform: bundlePlatformLabel(),
      arch: archLabel(),
      createdAt: new Date().toISOString(),
      bundleFormatVersion: 1,
      files: {
        cliEntrypoint: 'app/dist/cli.cjs',
        appNodeModulesDir: 'app/node_modules',
        runtimeBinDir: 'runtime/bin',
        skillsDir: 'skills/agentpay-sdk',
      },
    };
    fs.writeFileSync(
      path.join(bundleRoot, 'bundle-manifest.json'),
      `${JSON.stringify(manifest, null, 2)}\n`,
      'utf8',
    );

    tarDirectory(bundleRoot, path.resolve(output));
    process.stdout.write(`${path.resolve(output)}\n`);
  } finally {
    fs.rmSync(stagingRoot, { recursive: true, force: true });
  }
}

main();
