import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const installScriptPath = new URL('../scripts/launchd/install-user-daemon.sh', import.meta.url);
const runnerScriptPath = new URL('../scripts/launchd/run-agentpay-daemon.sh', import.meta.url);

test('launchd install flow wires the root-only keychain helper into daemon setup', () => {
  const installScript = fs.readFileSync(installScriptPath, 'utf8');
  const runnerScript = fs.readFileSync(runnerScriptPath, 'utf8');

  assert.match(installScript, /--keychain-helper <path>/);
  assert.match(
    installScript,
    /install -o root -g wheel -m 700 "\$keychain_helper" "\$temp_keychain_helper"/,
  );
  assert.match(installScript, /"\$managed_keychain_helper" replace-generic-password/);
  assert.match(
    installScript,
    /specified item already exists\|already exists in the keychain\|errSecDuplicateItem/,
  );
  assert.match(installScript, /\/usr\/bin\/security delete-generic-password/);
  assert.match(installScript, /<key>AGENTPAY_KEYCHAIN_HELPER<\/key>/);

  assert.match(runnerScript, /require_var "AGENTPAY_KEYCHAIN_HELPER"/);
  assert.match(runnerScript, /"\$AGENTPAY_KEYCHAIN_HELPER" read-generic-password/);
});
