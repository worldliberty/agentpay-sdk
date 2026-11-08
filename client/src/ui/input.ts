/**
 * Ink's `useInput`, paused while something on top owns the keyboard. The sudo password prompt
 * keeps the screen underneath mounted (so its pending action resumes), and without this the
 * hidden screen would also receive every key typed into the password: `esc` would leave it and
 * letters would fire its shortcuts. Screens import `useInput` from here, never from `ink`.
 */
import { useInput as useInkInput } from 'ink';
import { createContext, useContext } from 'react';

/** `true` for the subtree under an overlay that has taken the keyboard. */
export const InputPaused = createContext(false);

type Handler = Parameters<typeof useInkInput>[0];

export function useInput(handler: Handler, options: { isActive?: boolean } = {}): void {
  const paused = useContext(InputPaused);
  useInkInput(handler, { isActive: (options.isActive ?? true) && !paused });
}
