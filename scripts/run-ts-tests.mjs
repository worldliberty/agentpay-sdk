#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const isolatedRunnerPath = path.join(repoRoot, 'scripts', 'run-tests-isolated.mjs');
const testRoot = path.join(repoRoot, 'test');

function collectTestFiles(dirPath) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const entryPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectTestFiles(entryPath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.test.mjs')) {
      files.push(entryPath);
    }
  }

  return files;
}

function resolveRequestedTestFiles(args) {
  if (args.length === 0) {
    return collectTestFiles(testRoot).sort();
  }

  return args.map((value) => path.resolve(repoRoot, value));
}

const requestedFiles = resolveRequestedTestFiles(process.argv.slice(2));

if (requestedFiles.length === 0) {
  console.error('no TypeScript test files were found');
  process.exit(1);
}

for (const testFile of requestedFiles) {
  if (!fs.existsSync(testFile)) {
    console.error(`test file not found: ${path.relative(repoRoot, testFile)}`);
    process.exit(1);
  }
}

const result = spawnSync(
  process.execPath,
  [
    isolatedRunnerPath,
    '--',
    process.execPath,
    '--import',
    'tsx',
    '--test',
    ...requestedFiles.map((value) => path.relative(repoRoot, value)),
  ],
  {
    cwd: repoRoot,
    env: {
      ...process.env,
      // Tests spawn the real CLI; none of them may phone home. Tests that exercise telemetry
      // itself override this and point both destinations at a local server.
      AGENTPAY_TELEMETRY: '0',
    },
    stdio: 'inherit',
  },
);

if (result.error) {
  console.error(`failed to run isolated TypeScript tests: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  process.kill(process.pid, result.signal);
}

process.exit(result.status ?? 1);
