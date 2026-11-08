/**
 * Spending limits editor: one row per asset with recommended values, +/- steppers (Jomo), and
 * usage bars "used of limit · left · rolling window" for the selected row (Bevel weekly limits).
 */
import { Box } from 'ink';
import { useEffect, useState } from 'react';
import { copy } from '../copy/index.js';
import { displayAmount } from '../format/amount.js';
import {
  blockUndecided,
  hasOrderProblem,
  isNoLimit,
  LIMIT_FIELDS,
  type LimitField,
  type LimitRow,
  remaining,
  setRowField,
  stepRow,
  toggleExcluded,
  undecidedCount,
} from '../limits/model.js';
import { Stepper, UsageBar, usageRatio } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { glyph, T, type Tone } from '../ui/theme.js';

const COLUMN = { asset: 10, network: 16, status: 14 } as const;

function statusLabel(row: LimitRow): { text: string; tone: Tone } {
  const l = copy.onboarding.limits;
  switch (row.status) {
    case 'recommended':
      return { text: l.recommended, tone: 'success' };
    case 'custom':
      return { text: l.custom, tone: 'accent' };
    case 'excluded':
      return { text: l.excluded, tone: 'muted' };
    case 'unset':
      return { text: l.unset, tone: 'warning' };
  }
}

function pad(text: string, width: number): string {
  return text.length >= width ? `${text.slice(0, width - 2)}… ` : text.padEnd(width);
}

export const limitsHints = [
  copy.common.keys.select,
  copy.common.keys.move,
  copy.common.keys.amount,
  copy.common.keys.exclude,
];

/** Hints while an amount is being typed into a cell. */
export const limitEditHints = [copy.common.keys.confirm, copy.common.keys.cancel];

function UsageLines({ row }: { row: LimitRow }) {
  const s = copy.screens.limits;
  const lines: { used: string | null; limit: string; window: string }[] = [
    { used: row.usage?.dailyUsed ?? null, limit: row.daily, window: s.resetsDaily },
    { used: row.usage?.weeklyUsed ?? null, limit: row.weekly, window: s.resetsWeekly },
  ];
  return (
    <Box flexDirection="column" marginLeft={2}>
      {lines.map(({ used, limit, window }) => {
        if (used === null || !limit || isNoLimit(limit, row.decimals)) {
          return null;
        }
        const r = remaining(limit, used, row.decimals);
        const caption = [
          s.used(displayAmount(used), displayAmount(limit), row.symbol),
          s.left(displayAmount(r.left), row.symbol),
          window,
        ].join(` ${glyph.separator} `);
        return <UsageBar key={window} ratio={usageRatio(r.used, r.limit)} caption={caption} />;
      })}
    </Box>
  );
}

export function LimitsEditor({
  rows,
  onChange,
  isActive = true,
  focusId,
  onEditingChange,
}: {
  rows: readonly LimitRow[];
  onChange: (rows: LimitRow[]) => void;
  isActive?: boolean;
  /** Moves the selection to this row when it changes (a token just added). */
  focusId?: string | null;
  /** Typing an amount into a cell: enter and esc belong to the cell meanwhile. */
  onEditingChange?: (editing: boolean) => void;
}) {
  /** The amount being typed into the focused cell, or `null`. */
  const [draft, setDraftState] = useState<string | null>(null);
  const [invalid, setInvalid] = useState(false);
  const setDraft = (next: string | null) => {
    setDraftState(next);
    setInvalid(false);
    if ((next === null) !== (draft === null)) {
      onEditingChange?.(next !== null);
    }
  };
  const [selected, setSelected] = useState(() =>
    Math.max(0, focusId ? rows.findIndex((row) => row.id === focusId) : 0),
  );
  useEffect(() => {
    const index = focusId ? rows.findIndex((row) => row.id === focusId) : -1;
    if (index >= 0) {
      setSelected(index);
    }
  }, [focusId, rows]);
  const [field, setField] = useState<LimitField>('perTx');
  const l = copy.onboarding.limits;

  const update = (index: number, change: (row: LimitRow) => LimitRow) => {
    onChange(rows.map((row, i) => (i === index ? change(row) : row)));
  };

  useInput(
    (input, key) => {
      // Typed fast or pasted, several characters arrive as one input.
      if (draft !== null) {
        if (key.return) {
          const row = rows[selected];
          const next = row ? setRowField(row, field, draft) : null;
          if (next) {
            update(selected, () => next);
            setDraft(null);
          } else {
            setInvalid(true);
          }
        } else if (key.escape) {
          setDraft(null);
        } else if (key.backspace || key.delete) {
          setDraftState(draft.slice(0, -1));
          setInvalid(false);
        } else if (/^[0-9.]+$/u.test(input)) {
          setDraftState(draft + input);
          setInvalid(false);
        }
        return;
      }
      const fieldIndex = LIMIT_FIELDS.indexOf(field);
      if (/^[0-9.]+$/u.test(input)) {
        setDraft(input);
      } else if (input === 'X') {
        onChange(blockUndecided(rows));
      } else if (key.upArrow) {
        setSelected((i) => Math.max(0, i - 1));
      } else if (key.downArrow) {
        setSelected((i) => Math.min(rows.length - 1, i + 1));
      } else if (key.leftArrow) {
        setField(LIMIT_FIELDS[Math.max(0, fieldIndex - 1)] ?? field);
      } else if (key.rightArrow || key.tab) {
        setField(LIMIT_FIELDS[Math.min(LIMIT_FIELDS.length - 1, fieldIndex + 1)] ?? field);
      } else if (input === '+' || input === '=') {
        update(selected, (row) => stepRow(row, field, 1));
      } else if (input === '-' || input === '_') {
        update(selected, (row) => stepRow(row, field, -1));
      } else if (input === 'x') {
        update(selected, toggleExcluded);
      }
    },
    { isActive },
  );

  const current = rows[selected];
  const undecided = undecidedCount(rows);
  return (
    <Box flexDirection="column">
      <Box>
        <T tone="muted">{`  ${pad(l.columns.asset, COLUMN.asset)}${pad(l.columns.network, COLUMN.network)}`}</T>
        {LIMIT_FIELDS.map((name) => (
          <Box key={name} width={14}>
            <T tone={name === field ? 'accent' : 'muted'}>{l.columns[name]}</T>
          </Box>
        ))}
        <T tone="muted">{l.columns.status}</T>
      </Box>
      {rows.map((row, index) => {
        const focused = index === selected && isActive;
        const status = statusLabel(row);
        const blocked = row.status === 'excluded';
        return (
          <Box key={row.id}>
            <T tone="accent">{focused ? `${glyph.pointer} ` : '  '}</T>
            <T bold={focused} tone={blocked ? 'muted' : 'default'}>
              {pad(row.symbol, COLUMN.asset)}
            </T>
            <T tone="muted">{pad(row.networkName, COLUMN.network)}</T>
            {LIMIT_FIELDS.map((name) => (
              <Box key={name} width={14}>
                {focused && name === field && draft !== null ? (
                  <T tone={invalid ? 'danger' : 'accent'} bold>{` ${draft}▏`}</T>
                ) : blocked ? (
                  <T tone="muted">{'      —'}</T>
                ) : (
                  <Stepper
                    value={
                      !row[name]
                        ? ''
                        : isNoLimit(row[name], row.decimals)
                          ? copy.screens.limits.noLimit
                          : displayAmount(row[name])
                    }
                    focused={focused && name === field}
                  />
                )}
              </Box>
            ))}
            <T tone={status.tone}>{status.text}</T>
          </Box>
        );
      })}
      {current?.usage && current.status !== 'excluded' ? <UsageLines row={current} /> : null}
      <Box marginTop={1} flexDirection="column">
        {invalid && current ? (
          <T tone="danger">{l.invalidAmount(current.symbol, current.decimals)}</T>
        ) : null}
        {current && hasOrderProblem(current) ? <T tone="warning">{l.orderWarning}</T> : null}
        <T tone={undecided > 0 ? 'warning' : 'success'}>
          {undecided > 0 ? l.remaining(undecided) : `${glyph.check} ${l.ready}`}
        </T>
      </Box>
    </Box>
  );
}
