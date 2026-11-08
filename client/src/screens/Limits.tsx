/** Spending limits screen: load, edit with the shared editor (tokens can be added), save. */

import { useEffect, useState } from 'react';
import { copy, type Guidance } from '../copy/index.js';
import { guidanceFor } from '../errors.js';
import { type LimitRow, setCount } from '../limits/model.js';
import { Spinner } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { Screen } from '../ui/layout.js';
import { glyph, T } from '../ui/theme.js';
import type { AddTokenMode } from './AddTokenForm.js';
import { LimitsWithTokens, limitsTableHints } from './LimitsWithTokens.js';
import type { AppServices } from './types.js';
import { useAsync } from './use-async.js';

export function LimitsScreen({
  services,
  onBack,
}: {
  services: Pick<AppServices, 'loadLimits' | 'saveLimits' | 'tokenNetworks' | 'lookupToken'>;
  onBack: () => void;
}) {
  const s = copy.screens.limits;
  const loaded = useAsync(() => services.loadLimits());
  const [rows, setRows] = useState<LimitRow[] | null>(null);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<Guidance | null>(null);
  const [adding, setAdding] = useState<AddTokenMode | null>(null);
  const [editing, setEditing] = useState(false);

  const loadedRows = loaded.status === 'ready' ? loaded.value : null;
  useEffect(() => {
    if (loadedRows) {
      setRows(loadedRows);
      setDirty(false);
    }
  }, [loadedRows]);

  const save = async () => {
    if (!rows || !dirty) {
      setNotice(s.unchanged);
      return;
    }
    if (setCount(rows) === 0) {
      setError({ message: copy.onboarding.limits.atLeastOne, next: copy.common.keys.adjust });
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await services.saveLimits(rows);
      setDirty(false);
      setNotice(s.saved);
    } catch (failure) {
      setError(guidanceFor(failure));
    } finally {
      setSaving(false);
    }
  };

  useInput(
    (input, key) => {
      if (key.escape || input === 'q') {
        onBack();
      } else if (key.return) {
        void save();
      } else if (input === 'r' && loaded.status === 'error') {
        loaded.reload();
      }
    },
    { isActive: !saving && adding === null && !editing },
  );

  const k = copy.common.keys;
  return (
    <Screen
      title={s.title}
      hints={
        saving
          ? []
          : adding || editing
            ? limitsTableHints(adding, editing)
            : [...limitsTableHints(null), `enter ${s.save.toLowerCase()}`, k.back]
      }
      error={loaded.status === 'error' ? loaded.error : error}
    >
      {adding ? null : <T>{s.body}</T>}
      {loaded.status === 'loading' ? <Spinner label={copy.common.loading} /> : null}
      {rows ? (
        <LimitsWithTokens
          rows={rows}
          services={services}
          isActive={!saving}
          onAddingChange={setAdding}
          onEditingChange={setEditing}
          onChange={(next) => {
            setRows(next);
            setDirty(true);
            setNotice(null);
          }}
        />
      ) : null}
      {saving ? <Spinner label={copy.onboarding.limits.saving} /> : null}
      {notice ? <T tone="success">{`${glyph.check} ${notice}`}</T> : null}
    </Screen>
  );
}
