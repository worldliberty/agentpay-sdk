/**
 * Rendering and keyboard input for Ink screens under test.
 *
 * Ink 6 renders through React's concurrent reconciler: a key press only schedules the state
 * update, and the re-render and the effects that re-subscribe `useInput` handlers to the new
 * state run later on React's scheduler. Waiting a fixed time after each key is therefore a race:
 * on a loaded machine the next key reaches the handler of the previous render (stale state, so
 * `↓` then `enter` picks the old item). Every interaction here runs inside React's `act()`,
 * which drains all React work (renders, effects, updates they cause) before it resolves, so the
 * next key always meets the current screen, independent of machine speed.
 */
import { render as inkRender } from 'ink-testing-library';
import { act, type ReactElement } from 'react';
import { afterEach } from 'vitest';

// Tells React that this environment drives updates through `act()`.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

export const KEY = {
  enter: '\r',
  escape: '\u001B',
  up: '\u001B[A',
  down: '\u001B[B',
  right: '\u001B[C',
  left: '\u001B[D',
  space: ' ',
  backspace: '\u007F',
} as const;

type View = ReturnType<typeof inkRender>;

const views: View[] = [];

// Unmount every screen after its test, so no spinner or pending load updates a later test.
afterEach(() => {
  act(() => {
    for (const view of views.splice(0)) {
      view.unmount();
    }
  });
});

const nextMacrotask = () => new Promise<void>((resolve) => setImmediate(resolve));

/** Renders `tree` and runs its mount effects (first loads, input subscriptions). */
export function render(tree: ReactElement): View {
  let view: View | undefined;
  act(() => {
    view = inkRender(tree);
  });
  if (!view) {
    throw new Error('render did not run');
  }
  views.push(view);
  return view;
}

/** Writes each key and lets React apply everything it causes before the next one. */
export async function press(
  stdin: { write(data: string): void },
  ...keys: string[]
): Promise<void> {
  for (const key of keys) {
    await act(async () => {
      stdin.write(key);
      // Ink holds a lone ESC for one macrotask to tell it apart from an escape sequence.
      await nextMacrotask();
    });
  }
}

/**
 * Polls `frame()` until it contains `text`. Each poll lets pending I/O (fake daemons, service
 * promises) complete inside `act()`, so when `text` is found the screen that drew it is fully
 * committed and its input handlers are current. The timeout only bounds a test that would
 * otherwise hang; nothing waits on it to pass.
 */
export async function waitFor(
  frame: () => string | undefined,
  text: string,
  timeoutMs = 2000,
): Promise<string> {
  const start = Date.now();
  for (;;) {
    const current = frame() ?? '';
    if (current.includes(text)) {
      return current;
    }
    if (Date.now() - start > timeoutMs) {
      throw new Error(`timed out waiting for "${text}" in:\n${current}`);
    }
    await act(() => new Promise<void>((resolve) => setTimeout(resolve, 10)));
  }
}
