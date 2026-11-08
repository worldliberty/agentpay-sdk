/**
 * Security: Touch ID approvals on/off (Phantom/Marcus security toggles), approval alerts on/off,
 * and backups.
 */

import { useState } from 'react';
import { copy, type Guidance } from '../copy/index.js';
import { guidanceFor } from '../errors.js';
import { Menu, Spinner } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { Rows, Screen } from '../ui/layout.js';
import { glyph, T } from '../ui/theme.js';
import { BackupForm, backupHints } from './BackupForm.js';
import type { AppServices } from './types.js';
import { useAsync } from './use-async.js';

type Services = Pick<
  AppServices,
  | 'touchIdState'
  | 'enableTouchId'
  | 'disableTouchId'
  | 'exportBackup'
  | 'defaultBackupPath'
  | 'alertsState'
  | 'enableAlerts'
  | 'disableAlerts'
>;

export function SecurityScreen({ services, onBack }: { services: Services; onBack: () => void }) {
  const s = copy.screens.security;
  const state = useAsync(() => services.touchIdState());
  const alerts = useAsync(() => services.alertsState());
  const [mode, setMode] = useState<'menu' | 'busy' | 'backup'>('menu');
  const [hints, setHints] = useState<string[]>(backupHints('path'));
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<Guidance | null>(null);

  useInput(
    (input, key) => {
      if (key.escape || input === 'q') {
        onBack();
      }
    },
    { isActive: mode === 'menu' },
  );

  const toggleAlerts = async (enable: boolean) => {
    setMode('busy');
    setError(null);
    try {
      await (enable ? services.enableAlerts() : services.disableAlerts());
      setNotice(enable ? s.alertsTurnedOn : s.alertsTurnedOff);
      alerts.reload();
    } catch (failure) {
      setError(guidanceFor(failure));
    } finally {
      setMode('menu');
    }
  };

  const toggle = async (enable: boolean) => {
    setMode('busy');
    setError(null);
    try {
      await (enable ? services.enableTouchId() : services.disableTouchId());
      setNotice(enable ? copy.commands.admin.touchIdOn : copy.commands.admin.touchIdOff);
      state.reload();
    } catch (failure) {
      setError(guidanceFor(failure));
    } finally {
      setMode('menu');
    }
  };

  if (mode === 'backup') {
    return (
      <Screen title={copy.onboarding.backup.title} hints={hints}>
        <BackupForm
          services={services}
          allowSkip={false}
          onFieldChange={(field) => setHints(backupHints(field))}
          onBack={() => setMode('menu')}
          onDone={(path) => {
            setMode('menu');
            if (path) {
              setNotice(copy.onboarding.backup.written(path));
            }
          }}
        />
      </Screen>
    );
  }

  const touchId = state.status === 'ready' ? state.value : null;
  /** `null` while loading, or where alerts are not available. */
  const alertsOn = alerts.status === 'ready' ? alerts.value : null;
  const k = copy.common.keys;
  return (
    <Screen
      title={s.title}
      hints={mode === 'busy' ? [] : [k.select, k.confirm, k.back]}
      error={state.status === 'error' ? state.error : error}
    >
      {touchId ? (
        <Rows
          rows={[
            {
              label: s.touchId,
              value:
                touchId === 'on'
                  ? s.touchIdOn
                  : touchId === 'off'
                    ? s.touchIdOff
                    : s.touchIdUnavailable,
              tone: touchId === 'on' ? 'success' : 'muted',
            },
            ...(alertsOn === null
              ? []
              : [
                  {
                    label: s.alerts,
                    value: alertsOn ? s.alertsOn : s.alertsOff,
                    tone: alertsOn ? ('success' as const) : ('muted' as const),
                  },
                ]),
            { label: s.backup, value: s.backupHint },
          ]}
        />
      ) : (
        <Spinner label={copy.common.loading} />
      )}
      {notice ? <T tone="success">{`${glyph.check} ${notice}`}</T> : null}
      {mode === 'busy' ? <Spinner label={copy.common.working} /> : null}
      {mode === 'menu' && touchId ? (
        <Menu
          items={[
            touchId === 'on'
              ? { value: 'disable', label: s.disable }
              : { value: 'enable', label: s.enable, disabled: touchId === 'unavailable' },
            ...(alertsOn === null
              ? []
              : [
                  alertsOn
                    ? { value: 'alerts-off', label: s.alertsDisable }
                    : { value: 'alerts-on', label: s.alertsEnable },
                ]),
            { value: 'backup', label: s.exportBackup },
            { value: 'back', label: s.back },
          ]}
          onSelect={(value) => {
            setNotice(null);
            if (value === 'back') {
              onBack();
            } else if (value === 'alerts-on' || value === 'alerts-off') {
              void toggleAlerts(value === 'alerts-on');
            } else if (value === 'backup') {
              setHints(backupHints('path'));
              setMode('backup');
            } else {
              void toggle(value === 'enable');
            }
          }}
        />
      ) : null}
    </Screen>
  );
}
