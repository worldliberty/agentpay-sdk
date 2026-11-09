/** Interactive controls: menu, text field, stepper, usage bar, spinner, and task list. */
import { Box, Text } from 'ink';
import { useEffect, useRef, useState } from 'react';
import { useInput } from './input.js';
import { glyph, T, type Tone } from './theme.js';

export interface MenuItem<V extends string> {
  value: V;
  label: string;
  hint?: string;
  disabled?: boolean;
}

/** A vertical list; ↑↓ moves, enter selects. Disabled items are skipped. */
export function Menu<V extends string>({
  items,
  onSelect,
  isActive = true,
  initial = 0,
  onHighlight,
}: {
  items: readonly MenuItem<V>[];
  onSelect: (value: V) => void;
  isActive?: boolean;
  initial?: number;
  /** Told which item is highlighted (on mount and on every move). */
  onHighlight?: (value: V) => void;
}) {
  // Never open on a disabled row (Touch ID where it does not exist): take the next one that
  // can be chosen, so "↓ enter" means the same thing on every machine.
  const firstEnabled = (from: number) => {
    for (let step = 0; step < items.length; step += 1) {
      const candidate = (from + step) % items.length;
      if (!items[candidate]?.disabled) {
        return candidate;
      }
    }
    return from;
  };
  const start = firstEnabled(initial);
  const [index, setIndexState] = useState(start);
  // Keys can arrive in one batch (fast typing, paste): read the latest selection, not the one
  // from the last render, so "↓ enter" always picks the row it moved to.
  const current = useRef(start);
  const setIndex = (next: number) => {
    current.current = next;
    setIndexState(next);
    const item = items[next];
    if (item) {
      onHighlight?.(item.value);
    }
  };
  // biome-ignore lint/correctness/useExhaustiveDependencies: report the first highlight once.
  useEffect(() => {
    const item = items[start];
    if (item) {
      onHighlight?.(item.value);
    }
  }, []);
  const move = (delta: 1 | -1) => {
    for (let step = 1; step <= items.length; step += 1) {
      const next = (current.current + delta * step + items.length) % items.length;
      if (!items[next]?.disabled) {
        setIndex(next);
        return;
      }
    }
  };
  useInput(
    (_input, key) => {
      if (key.upArrow) {
        move(-1);
      } else if (key.downArrow) {
        move(1);
      } else if (key.return) {
        const item = items[current.current];
        if (item && !item.disabled) {
          onSelect(item.value);
        }
      }
    },
    { isActive },
  );
  const labelWidth = Math.max(...items.map((item) => item.label.length)) + 2;
  return (
    <Box flexDirection="column">
      {items.map((item, i) => {
        const selected = i === index && isActive;
        const tone: Tone = item.disabled ? 'muted' : selected ? 'accent' : 'default';
        return (
          <Box key={item.value}>
            <Box width={2} flexShrink={0}>
              <T tone="accent">{selected ? glyph.pointer : ' '}</T>
            </Box>
            <Box width={item.hint ? labelWidth : undefined} flexShrink={0}>
              <T tone={tone} bold={selected}>
                {item.label}
              </T>
            </Box>
            {item.hint ? <T tone="muted">{item.hint}</T> : null}
          </Box>
        );
      })}
    </Box>
  );
}

/**
 * A one-line text input. Typed characters append, backspace deletes, enter submits. With `mask`
 * the value is shown as bullets (passphrases).
 */
export function TextField({
  label,
  value,
  onChange,
  onSubmit,
  mask = false,
  hint,
  error,
  isActive = true,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  onSubmit?: () => void;
  mask?: boolean;
  hint?: string | undefined;
  error?: string | null | undefined;
  isActive?: boolean;
}) {
  useInput(
    (input, key) => {
      if (key.return) {
        onSubmit?.();
      } else if (key.backspace || key.delete) {
        onChange(value.slice(0, -1));
      } else if (
        !key.ctrl &&
        !key.meta &&
        !key.tab &&
        !key.escape &&
        input &&
        !/[\r\n]/u.test(input)
      ) {
        onChange(value + input);
      }
    },
    { isActive },
  );
  const shown = mask ? '•'.repeat(value.length) : value;
  return (
    <Box flexDirection="column">
      <Box gap={1}>
        <T tone={isActive ? 'accent' : 'muted'}>{isActive ? glyph.pointer : ' '}</T>
        <T bold={isActive}>{label}</T>
      </Box>
      <Box marginLeft={2}>
        <Text>{shown}</Text>
        {isActive ? <Text inverse> </Text> : null}
      </Box>
      {error ? (
        <Box marginLeft={2}>
          <T tone="danger">{error}</T>
        </Box>
      ) : hint ? (
        <Box marginLeft={2}>
          <T tone="muted">{hint}</T>
        </Box>
      ) : null}
    </Box>
  );
}

/** "− 10 +" with the value highlighted when focused (Jomo-style stepper). */
export function Stepper({
  value,
  focused,
  width = 8,
}: {
  value: string;
  focused: boolean;
  width?: number;
}) {
  const text = value === '' ? '—' : value;
  const padded = text.length >= width ? text : text.padStart(width);
  return (
    <Box>
      <T tone={focused ? 'accent' : 'muted'}>{`${glyph.minus} `}</T>
      <T bold={focused} inverse={focused}>
        {padded}
      </T>
      <T tone={focused ? 'accent' : 'muted'}>{` ${glyph.plus}`}</T>
    </Box>
  );
}

/** Ratio of two base-unit amounts, clamped to [0, 1]. */
export function usageRatio(used: bigint, limit: bigint): number {
  if (limit <= 0n) {
    return used > 0n ? 1 : 0;
  }
  const permille = Number((used * 1000n) / limit);
  return Math.min(1, Math.max(0, permille / 1000));
}

/** "█████░░░░░ 40 of 100 USD1 used · 60 USD1 left · rolling 24 h" (Bevel-style usage bar). */
export function UsageBar({
  ratio,
  caption,
  width = 20,
}: {
  ratio: number;
  caption: string;
  width?: number;
}) {
  const filled = Math.round(ratio * width);
  const tone: Tone = ratio >= 0.9 ? 'danger' : ratio >= 0.7 ? 'warning' : 'accent';
  return (
    <Box gap={1}>
      <Text>
        <T tone={tone}>{glyph.barFull.repeat(filled)}</T>
        <T tone="muted">{glyph.barEmpty.repeat(width - filled)}</T>
      </Text>
      <T tone="muted">{caption}</T>
    </Box>
  );
}

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'] as const;

export function Spinner({ label }: { label: string }) {
  const [frame, setFrame] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => setFrame((f) => (f + 1) % SPINNER_FRAMES.length), 80);
    return () => clearInterval(timer);
  }, []);
  return (
    <Box gap={1}>
      <T tone="accent">{SPINNER_FRAMES[frame] ?? ''}</T>
      <Text>{label}</Text>
    </Box>
  );
}

export type TaskState = 'pending' | 'running' | 'done' | 'failed';

/** A checklist of long-running steps ("Creating your wallet"). */
export function TaskList({ tasks }: { tasks: readonly { label: string; state: TaskState }[] }) {
  return (
    <Box flexDirection="column">
      {tasks.map((task) =>
        task.state === 'running' ? (
          <Spinner key={task.label} label={task.label} />
        ) : (
          <Box key={task.label} gap={1}>
            <T
              tone={
                task.state === 'done' ? 'success' : task.state === 'failed' ? 'danger' : 'muted'
              }
            >
              {task.state === 'done'
                ? glyph.check
                : task.state === 'failed'
                  ? glyph.cross
                  : glyph.stepTodo}
            </T>
            <T tone={task.state === 'pending' ? 'muted' : 'default'}>{task.label}</T>
          </Box>
        ),
      )}
    </Box>
  );
}
