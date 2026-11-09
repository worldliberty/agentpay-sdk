#!/usr/bin/env node
/** `agentpay` entry point. */
import { runCli } from './program.js';

runCli(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`agentpay: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  },
);
