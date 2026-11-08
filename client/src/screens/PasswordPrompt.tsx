/**
 * Shows the sudo password request from the relay (see auth/password-prompt.ts) on top of the
 * current screen. The screen stays mounted (hidden) so its pending action carries on once the
 * password is in, with its keys paused (`InputPaused`) so nothing typed here reaches it.
 */
import { Box, useInput } from 'ink';
import { type ReactNode, useEffect, useRef, useState } from 'react';
import type { PasswordPrompter, PasswordRequest } from '../auth/password-prompt.js';
import { copy } from '../copy/index.js';
import { TextField } from '../ui/controls.js';
import { InputPaused } from '../ui/input.js';
import { Screen } from '../ui/layout.js';
import { glyph, T } from '../ui/theme.js';

function PasswordForm({ request }: { request: PasswordRequest }) {
  const p = copy.screens.password;
  const k = copy.common.keys;
  const [password, setPassword] = useState('');
  useInput((_input, key) => {
    if (key.escape) {
      request.answer(null);
    }
  });
  return (
    <Screen title={p.title} hints={[k.type, k.confirm, k.cancel]}>
      <Box flexDirection="column" gap={1}>
        <T>{p.body(request.reason)}</T>
        {request.attempt > 1 ? <T tone="danger">{`${glyph.cross} ${p.wrong}`}</T> : null}
        <TextField
          label={p.label}
          value={password}
          mask
          onChange={setPassword}
          onSubmit={() => {
            if (password) {
              request.answer(password);
              setPassword('');
            }
          }}
        />
      </Box>
    </Screen>
  );
}

export function PasswordPromptHost({
  prompter,
  children,
}: {
  prompter: PasswordPrompter;
  children?: ReactNode;
}) {
  const [request, setRequest] = useState<PasswordRequest | null>(null);
  // Subscribe while rendering, not in an effect: children's effects run before a parent's, and
  // a screen that makes an admin call as it mounts must already find someone to ask.
  const unsubscribe = useRef<(() => void) | null>(null);
  if (!unsubscribe.current) {
    unsubscribe.current = prompter.subscribe((next) =>
      setRequest({
        ...next,
        answer: (password) => {
          setRequest(null);
          next.answer(password);
        },
      }),
    );
  }
  useEffect(() => () => unsubscribe.current?.(), []);
  return (
    <>
      <Box display={request ? 'none' : 'flex'} flexDirection="column">
        <InputPaused.Provider value={request !== null}>{children}</InputPaused.Provider>
      </Box>
      {request ? (
        <PasswordForm key={`${request.reason}-${request.attempt}`} request={request} />
      ) : null}
    </>
  );
}
