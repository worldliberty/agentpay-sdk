import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { writeBackup } from '../src/app/services.js';
import type { WalletBackupExport } from '../src/generated/index.js';
import { HomeScreen } from '../src/screens/Home.js';
import { type TestContext, testContext } from './helpers/context.js';
import { body } from './helpers/fake-daemon.js';
import { fixture, fixtureData } from './helpers/fixtures.js';
import { render, waitFor } from './helpers/ink.js';
import { wallet } from './helpers/services.js';

describe('backup reminder', () => {
  let t: TestContext | null = null;
  afterEach(async () => {
    await t?.close();
    t = null;
  });

  it('records a backup that reads back intact, keyed by the wallet address', async () => {
    t = await testContext({
      euid: 0,
      signer: (call) =>
        call.method === 'ExportWalletBackup'
          ? body(fixture('rpc/ExportWalletBackup.response.json'))
          : { close: true },
    });
    const exported = fixtureData<WalletBackupExport>('rpc/ExportWalletBackup.response.json');
    const path = join(mkdtempSync(join(tmpdir(), 'apb-')), 'backup.json');
    await writeBackup(
      t.context.admin({ relay: false }),
      path,
      'correct horse battery',
      'agentpay admin wallet-backup export',
      undefined,
      t.context.state,
    );
    expect(readFileSync(path, 'utf8')).toContain(exported.backup_json.slice(0, 20));
    const at = t.context.state.read().backups[exported.summary.address.toLowerCase()];
    expect(at && Date.parse(at)).toBeGreaterThan(0);
  });

  it('Home reminds until the wallet is backed up, then shows the date', async () => {
    const base = { wallet, pendingApprovals: 0 };
    const missing = render(
      <HomeScreen
        load={async () => ({
          ...base,
          security: { touchId: 'on' as const, backedUpAt: null, notifications: true },
        })}
        onAction={() => {}}
      />,
    );
    const frame = await waitFor(missing.lastFrame, 'No backup of this wallet yet');
    expect(frame).toContain('Touch ID on · Approval alerts on');

    const done = render(
      <HomeScreen
        load={async () => ({
          ...base,
          security: {
            touchId: 'off' as const,
            backedUpAt: '2026-11-06T10:00:00.000Z',
            notifications: null,
          },
        })}
        onAction={() => {}}
      />,
    );
    const ok = await waitFor(done.lastFrame, 'Backed up 2026-11-06');
    expect(ok).toContain('Touch ID off · Backed up 2026-11-06');
    expect(ok).not.toContain('No backup');
  });
});
