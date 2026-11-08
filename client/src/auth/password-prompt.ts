/**
 * Asking for the user's password from inside the terminal UI. sudo cannot prompt on the
 * terminal while Ink owns it (raw mode, redraws), so the relay asks here instead and hands the
 * password to `sudo -S` on stdin. The UI subscribes while it is on screen; with no subscriber
 * (plain command output), `ask` answers `undefined` and sudo prompts on the terminal itself.
 */

export interface PasswordRequest {
  /** What the password is for ("approve sending 50 USD1 to 0x5aed…"). */
  reason: string;
  /** 1 for the first try; higher after a wrong password. */
  attempt: number;
  answer(password: string | null): void;
}

export interface PasswordPrompter {
  /**
   * The password, `null` when the user cancelled, or `undefined` when nothing on screen can
   * ask (no UI subscribed).
   */
  ask(reason: string, attempt: number): Promise<string | null | undefined>;
  /** The UI shows each request until it answers; returns the unsubscribe function. */
  subscribe(listener: (request: PasswordRequest) => void): () => void;
}

export function createPasswordPrompter(): PasswordPrompter {
  let listener: ((request: PasswordRequest) => void) | null = null;
  return {
    ask(reason, attempt) {
      const current = listener;
      if (!current) {
        return Promise.resolve(undefined);
      }
      return new Promise((resolve) => current({ reason, attempt, answer: resolve }));
    },
    subscribe(next) {
      listener = next;
      return () => {
        if (listener === next) {
          listener = null;
        }
      };
    },
  };
}
