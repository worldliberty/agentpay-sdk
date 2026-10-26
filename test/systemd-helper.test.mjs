import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import test from 'node:test';

const installScriptPath = new URL('../scripts/systemd/install-system-daemon.sh', import.meta.url);
const helperScriptPath = new URL(
  '../scripts/systemd/agentpay-daemon-password-helper.sh',
  import.meta.url,
);
const runnerScriptPath = new URL('../scripts/systemd/run-agentpay-daemon.sh', import.meta.url);

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

test('systemd install flow wires quoted environment values and relay token file into daemon setup', () => {
  const installScript = fs.readFileSync(installScriptPath, 'utf8');

  assert.match(installScript, /--password-helper <path>/);
  assert.match(
    installScript,
    /install_private_file "managed relay daemon token file" "\$relay_token_file" "\$relay_daemon_token"/,
  );
  assert.match(installScript, /rm -f "\$relay_token_file"/);
  assert.match(installScript, /quote_systemd_env_assignment/);
  assert.match(
    installScript,
    /quote_systemd_env_assignment AGENTPAY_DAEMON_SOCKET "\$daemon_socket"/,
  );
  assert.match(installScript, /Environment=\$env_daemon_socket/);
  assert.match(
    installScript,
    /quote_systemd_env_assignment AGENTPAY_RELAY_DAEMON_TOKEN_FILE "\$relay_token_file"/,
  );
  assert.match(installScript, /Environment=\$env_relay_token_file/);
});

test('systemd password helper preserves exact password file contents', () => {
  const helperScript = fs.readFileSync(helperScriptPath, 'utf8');

  assert.match(helperScript, /cat "\$password_file"/);
  assert.doesNotMatch(helperScript, /tr -d|sed -e/u);
});

test('systemd install flow reads the relay daemon token from stdin, never from argv or the environment', () => {
  const installScript = fs.readFileSync(installScriptPath, 'utf8');

  assert.match(installScript, /--relay-token-stdin\)/u);
  assert.match(installScript, /read_secret_line_from_stdin 'vault password' vault_password/u);
  assert.match(
    installScript,
    /read_secret_line_from_stdin 'relay daemon token' relay_daemon_token/u,
  );
  assert.doesNotMatch(installScript, /\$\{AGENTPAY_RELAY_DAEMON_TOKEN:-/u);
  assert.doesNotMatch(installScript, /<<</u);

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

test('systemd runner pipes the vault password instead of using a here-string', () => {
  const runnerScript = fs.readFileSync(runnerScriptPath, 'utf8');

  assert.doesNotMatch(runnerScript, /<<</u);
  assert.match(runnerScript, /< <\(printf '%s\\n' "\$vault_password"\)/u);
});

test('systemd unit applies sandbox hardening while keeping state and socket dirs writable', () => {
  const installScript = fs.readFileSync(installScriptPath, 'utf8');

  for (const directive of [
    'NoNewPrivileges=yes',
    'ProtectSystem=strict',
    'ProtectHome=yes',
    'ReadWritePaths=$read_write_paths',
    'PrivateTmp=yes',
    'UMask=077',
    'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
    'LockPersonality=yes',
    'MemoryDenyWriteExecute=yes',
    'SystemCallFilter=@system-service',
  ]) {
    assert.ok(installScript.includes(`\n${directive}\n`), `missing unit directive ${directive}`);
  }
  assert.match(
    installScript,
    /read_write_paths="\$\(quote_systemd_path "\$state_dir"\) \$\(quote_systemd_path "\$socket_dir"\)"/u,
  );
});
