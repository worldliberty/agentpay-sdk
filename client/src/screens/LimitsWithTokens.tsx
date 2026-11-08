/**
 * The spending limits table with "add a token" built in: `a` opens the add-token form in place
 * of the table, and the token comes back as a new row, selected, for the user to give a limit
 * or block. Used by the setup wizard and by the Limits screen.
 */

import { useState } from 'react';
import { copy } from '../copy/index.js';
import type { LimitRow } from '../limits/model.js';
import { useInput } from '../ui/input.js';
import { T } from '../ui/theme.js';
import { AddTokenForm, type AddTokenMode, addTokenHints } from './AddTokenForm.js';
import { LimitsEditor, limitEditHints, limitsHints } from './LimitsEditor.js';
import type { TokenServices } from './types.js';

/** Key hints for the table, an amount being typed, or the add-token form while it is open. */
export function limitsTableHints(
  adding: AddTokenMode | null,
  editing = false,
  { blockRest = false }: { blockRest?: boolean } = {},
): string[] {
  if (adding) {
    return addTokenHints(adding);
  }
  if (editing) {
    return limitEditHints;
  }
  const k = copy.common.keys;
  return [...limitsHints, ...(blockRest ? [k.blockRest] : []), k.addToken];
}

export function LimitsWithTokens({
  rows,
  onChange,
  services,
  isActive = true,
  onAddingChange,
  onEditingChange,
}: {
  rows: readonly LimitRow[];
  onChange: (rows: LimitRow[]) => void;
  services: TokenServices;
  isActive?: boolean;
  /** The add-token form's mode while it is open (`null` when the table is shown). */
  onAddingChange?: (mode: AddTokenMode | null) => void;
  /** An amount is being typed into a cell. */
  onEditingChange?: (editing: boolean) => void;
}) {
  const [editing, setEditingState] = useState(false);
  const setEditing = (next: boolean) => {
    setEditingState(next);
    onEditingChange?.(next);
  };
  const t = copy.onboarding.tokens;
  const [adding, setAddingState] = useState(false);
  const [focusId, setFocusId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const setAdding = (open: boolean) => {
    setAddingState(open);
    onAddingChange?.(open ? 'network' : null);
  };
  useInput(
    (input) => {
      if (input === 'a') {
        setNotice(null);
        setAdding(true);
      }
    },
    { isActive: isActive && !adding && !editing },
  );
  if (adding) {
    return (
      <AddTokenForm
        services={services}
        onModeChange={(mode) => onAddingChange?.(mode)}
        onCancel={() => setAdding(false)}
        onAdded={({ row, verified }) => {
          const existing = rows.find(
            (r) =>
              r.network === row.network && JSON.stringify(r.asset) === JSON.stringify(row.asset),
          );
          if (existing) {
            setFocusId(existing.id);
            setNotice(t.alreadyListed(existing.symbol, existing.networkName));
          } else {
            onChange([...rows, row]);
            setFocusId(row.id);
            setNotice(t.found(row.symbol, row.decimals, row.networkName, verified));
          }
          setAdding(false);
        }}
      />
    );
  }
  return (
    <>
      <LimitsEditor
        rows={rows}
        onChange={onChange}
        isActive={isActive}
        focusId={focusId}
        onEditingChange={setEditing}
      />
      {notice ? <T tone="success">{notice}</T> : null}
    </>
  );
}
