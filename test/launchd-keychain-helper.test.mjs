import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import test from 'node:test';

const installScriptPath = new URL('../scripts/launchd/install-user-daemon.sh', import.meta.url);
const runnerScriptPath = new URL('../scripts/launchd/run-agentpay-daemon.sh', import.meta.url);

function extractShellFunction(script, name) {
  const start = script.indexOf(`${name}() {`);
  assert.ok(start >= 0, `missing shell function ${name}`);
  const end = script.indexOf('\n}\n', start);
  assert.ok(end > start, `unterminated shell function ${name}`);
  return script.slice(start, end + 3);
}

function runSecretLineReader(script, stdin) {
  const program = [
    extractShellFunction(script, 'read_secret_line_from_stdin'),
    "read_secret_line_from_stdin 'vault password' vault_password",
    "read_secret_line_from_stdin 'relay daemon token' relay_daemon_token",
    'printf \'%s|%s\' "$vault_password" "$relay_daemon_token"',
  ].join('\n');
  return spawnSync('/bin/bash', ['-c', program], { input: stdin, encoding: 'utf8' });
}

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

test('launchd install flow reads the relay daemon token from stdin, never from argv or the environment', () => {
  const installScript = fs.readFileSync(installScriptPath, 'utf8');

  assert.match(installScript, /--relay-token-stdin\)/u);
  assert.match(installScript, /read_secret_line_from_stdin 'vault password' vault_password/u);
  assert.match(
    installScript,
    /read_secret_line_from_stdin 'relay daemon token' relay_daemon_token/u,
  );
  assert.doesNotMatch(installScript, /\$\{AGENTPAY_RELAY_DAEMON_TOKEN:-/u);
  assert.doesNotMatch(installScript, /<<</u);
  assert.match(
    installScript,
    /printf '%s\\n' "\$vault_password" \| "\$managed_keychain_helper" replace-generic-password/u,
  );

  const ok = runSecretLineReader(installScript, 'vault secret\r\nrelay-token\n');
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.stdout, 'vault secret|relay-token');

  const noTrailingNewline = runSecretLineReader(installScript, 'vault-secret\nrelay-token');
  assert.equal(noTrailingNewline.status, 0, noTrailingNewline.stderr);
  assert.equal(noTrailingNewline.stdout, 'vault-secret|relay-token');

  const missingToken = runSecretLineReader(installScript, 'vault-secret\n');
  assert.notEqual(missingToken.status, 0);
  assert.match(missingToken.stderr, /relay daemon token must not be empty or whitespace/u);
});

test('launchd runner pipes the vault password instead of using a here-string', () => {
  const runnerScript = fs.readFileSync(runnerScriptPath, 'utf8');

  assert.doesNotMatch(runnerScript, /<<</u);
  assert.match(runnerScript, /< <\(printf '%s\\n' "\$vault_password"\)/u);
});
