/** The per-user AgentPay directory (`$AGENTPAY_HOME`, else `~/.agentpay`) and files in it. */
import { homedir } from 'node:os';
import { join } from 'node:path';

export function agentpayHome(env: NodeJS.ProcessEnv): string {
  const explicit = env.AGENTPAY_HOME?.trim();
  return explicit ? explicit : join(env.HOME?.trim() || homedir(), '.agentpay');
}

export const homeFiles = {
  /** Non-secret client state: the agent key id and the enrolled Touch ID credential id. */
  clientState: (home: string) => join(home, 'client.json'),
  /** Legacy TypeScript CLI configuration (read only, for its `agentKeyId`). */
  legacyConfig: (home: string) => join(home, 'config.json'),
  /** The `agentpay-auth` Secure Enclave key file. */
  adminKey: (home: string) => join(home, 'admin-key.json'),
  /** Fallback token files when no keychain is available (Linux without Secret Service). */
  agentAuthDir: (home: string) => join(home, 'agent-auth'),
  /** Environment file for the paying proxy (contains its secret URL). */
  proxyEnv: (home: string) => join(home, 'proxy.env'),
  proxyCa: (home: string) => join(home, 'proxy-ca.pem'),
};
