import type { Command } from 'commander';
import { bitrefillCliPlugin } from './bitrefill.js';
import { solayerCliPlugin } from './solayer.js';
import { type CliPluginContext, registerCliPlugins } from './types.js';

const BUILTIN_CLI_PLUGINS = [bitrefillCliPlugin, solayerCliPlugin];

export function registerBuiltinCliPlugins(program: Command, context: CliPluginContext): void {
  registerCliPlugins(program, context, BUILTIN_CLI_PLUGINS);
}
