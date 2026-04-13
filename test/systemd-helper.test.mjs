import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const installScriptPath = new URL('../scripts/systemd/install-system-daemon.sh', import.meta.url);
const helperScriptPath = new URL(
  '../scripts/systemd/agentpay-daemon-password-helper.sh',
  import.meta.url,
);

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
