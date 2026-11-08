import { useCallback, useEffect, useRef, useState } from 'react';
import type { Guidance } from '../copy/index.js';
import { guidanceFor } from '../errors.js';

export type AsyncState<T> =
  | { status: 'loading' }
  | { status: 'ready'; value: T }
  | { status: 'error'; error: Guidance };

export interface AsyncControls {
  /** Loads again, showing the loading state. */
  reload: () => void;
  /** Loads again in the background: the current value stays until the new one arrives, and a
   * failed refresh keeps it (a refresh is not worth an error screen). */
  refresh: () => void;
}

/** Runs `load` on mount (and on `reload`/`refresh`) and tracks its state. */
export function useAsync<T>(load: () => Promise<T>): AsyncState<T> & AsyncControls {
  const [state, setState] = useState<AsyncState<T>>({ status: 'loading' });
  const [generation, setGeneration] = useState(0);
  const quiet = useRef(false);
  // biome-ignore lint/correctness/useExhaustiveDependencies: `generation` re-runs the load on purpose.
  useEffect(() => {
    let cancelled = false;
    const background = quiet.current;
    quiet.current = false;
    if (!background) {
      setState({ status: 'loading' });
    }
    load().then(
      (value) => {
        if (!cancelled) {
          setState({ status: 'ready', value });
        }
      },
      (error: unknown) => {
        if (!cancelled && !background) {
          setState({ status: 'error', error: guidanceFor(error) });
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [generation]);
  const reload = useCallback(() => setGeneration((g) => g + 1), []);
  const refresh = useCallback(() => {
    quiet.current = true;
    setGeneration((g) => g + 1);
  }, []);
  return { ...state, reload, refresh };
}

/** Calls `tick` every `ms` while mounted (and `enabled`). */
export function useInterval(tick: () => void, ms: number, enabled = true): void {
  const latest = useRef(tick);
  latest.current = tick;
  useEffect(() => {
    if (!enabled) {
      return;
    }
    const id = setInterval(() => latest.current(), ms);
    return () => clearInterval(id);
  }, [ms, enabled]);
}
