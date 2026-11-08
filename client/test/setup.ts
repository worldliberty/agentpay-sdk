/**
 * Runs before every test file: a private HOME and AGENTPAY_HOME, no color, and no inherited
 * AgentPay variables, so tests never touch the real keychain, sockets, or configuration.
 */
import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const home = mkdtempSync(join(tmpdir(), 'ap-'));
const agentpayHome = join(home, '.agentpay');
mkdirSync(agentpayHome, { mode: 0o700 });

for (const key of Object.keys(process.env)) {
  if (key.startsWith('AGENTPAY_')) {
    delete process.env[key];
  }
}
process.env.HOME = home;
process.env.AGENTPAY_HOME = agentpayHome;
process.env.NO_COLOR = '1';
process.env.FORCE_COLOR = '0';
