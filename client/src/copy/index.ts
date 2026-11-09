/**
 * All user-facing text, in one place so wording stays consistent across commands and screens.
 * Components and commands import `copy` instead of writing strings inline.
 */
import { commands } from './commands.js';
import { common } from './common.js';
import { errors } from './errors.js';
import { networks } from './networks.js';
import { onboarding } from './onboarding.js';
import { screens } from './screens.js';

export const copy = { common, errors, commands, networks, onboarding, screens } as const;

/** A message plus the single next action the user should take. */
export interface Guidance {
  message: string;
  next: string;
}
