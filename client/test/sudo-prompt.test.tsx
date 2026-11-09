import { Text } from 'ink';
import { useEffect, useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { createPasswordPrompter, type PasswordPrompter } from '../src/auth/password-prompt.js';
import { createSudoRelay } from '../src/auth/privileged.js';
import type { CommandRunner, RunOptions } from '../src/auth/process.js';
import { AuthError } from '../src/errors.js';
import { PasswordPromptHost } from '../src/screens/PasswordPrompt.js';
import { useInput } from '../src/ui/input.js';
import { KEY, press, render, waitFor } from './helpers/ink.js';

const OK = JSON.stringify({ ok: true, response: { type: 'Wallets', data: [] } });
const REQUEST = { method: 'ListWallets' as const, params: {} };

/** A fake sudo: no timestamp until `-v` gets `password` on stdin. */
function fakeSudo(password: string) {
  let stamped = false;
  const calls: { args: string[]; input: string | undefined }[] = [];
  const run = vi.fn(async (_cmd: string, args: readonly string[], options?: RunOptions) => {
    calls.push({ args: [...args], input: options?.input });
    if (args.includes('-v')) {
      stamped = options?.input === `${password}\n`;
      return { status: stamped ? 0 : 1, stdout: '', stderr: stamped ? '' : 'Sorry, try again.' };
    }
    if (args[0] === '-n' && !stamped) {
      return { status: 1, stdout: '', stderr: 'sudo: a password is required' };
    }
    return { status: 0, stdout: OK, stderr: '' };
  });
  return { run: run as unknown as CommandRunner, calls };
}

describe('sudo relay with the password asked in the UI', () => {
  it('asks, gets a timestamp with sudo -S on stdin, then retries with sudo -n', async () => {
    const prompter = createPasswordPrompter();
    const reasons: string[] = [];
    prompter.subscribe((request) => {
      reasons.push(request.reason);
      request.answer('hunter2');
    });
    const sudo = fakeSudo('hunter2');
    const relay = createSudoRelay(sudo.run, ['node', 'cli.js'], prompter);
    await expect(relay.run(REQUEST, 'see your wallets')).resolves.toEqual({
      type: 'Wallets',
      data: [],
    });
    expect(reasons).toEqual(['see your wallets']);
    expect(sudo.calls.map((c) => c.args.slice(0, 4).join(' '))).toEqual([
      '-n -- node cli.js',
      '-S -p  -v',
      '-n -- node cli.js',
    ]);
    // The password only ever travels on stdin.
    for (const call of sudo.calls) {
      expect(call.args.join(' ')).not.toContain('hunter2');
    }
    expect(sudo.calls[1]?.input).toBe('hunter2\n');
  });

  it('asks again after a wrong password, and gives up after three', async () => {
    const prompter = createPasswordPrompter();
    const attempts: number[] = [];
    prompter.subscribe((request) => {
      attempts.push(request.attempt);
      request.answer(request.attempt === 2 ? 'hunter2' : 'wrong');
    });
    const ok = createSudoRelay(fakeSudo('hunter2').run, ['cli'], prompter);
    await expect(ok.run(REQUEST)).resolves.toBeTruthy();
    expect(attempts).toEqual([1, 2]);

    const never = createPasswordPrompter();
    never.subscribe((request) => request.answer('wrong'));
    const failing = createSudoRelay(fakeSudo('hunter2').run, ['cli'], never);
    await expect(failing.run(REQUEST)).rejects.toMatchObject({ code: 'sudo_failed' });
  });

  it('cancelling fails the action without running it', async () => {
    const prompter = createPasswordPrompter();
    prompter.subscribe((request) => request.answer(null));
    const sudo = fakeSudo('hunter2');
    const relay = createSudoRelay(sudo.run, ['cli'], prompter);
    const error = await relay.run(REQUEST).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AuthError);
    expect((error as AuthError).code).toBe('sudo_cancelled');
    expect(sudo.calls).toHaveLength(1);
  });

  it('without a UI, sudo prompts on the terminal itself', async () => {
    const sudo = fakeSudo('x');
    const relay = createSudoRelay(sudo.run, ['cli'], createPasswordPrompter());
    await relay.run(REQUEST).catch(() => null);
    expect(sudo.calls[1]?.args[0]).toBe('--');
  });
});

/** A screen whose action needs the password as soon as it mounts. */
function Busy({ prompter }: { prompter: PasswordPrompter }) {
  const [result, setResult] = useState('working');
  useEffect(() => {
    void prompter.ask('approve sending 50 USD1', 1).then((p) => setResult(`got ${p?.length}`));
  }, [prompter]);
  return <Text>{`screen: ${result}`}</Text>;
}

/** A screen that records every key it receives. */
function KeyLog({ seen }: { seen: string[] }) {
  useInput((input, key) => {
    seen.push(key.escape ? 'esc' : input);
  });
  return <Text>screen</Text>;
}

describe('password prompt on screen', () => {
  it('shows a masked field over the screen, then the screen carries on', async () => {
    const prompter = createPasswordPrompter();
    const { lastFrame, stdin } = render(
      <PasswordPromptHost prompter={prompter}>
        <Busy prompter={prompter} />
      </PasswordPromptHost>,
    );
    const prompt = await waitFor(
      lastFrame,
      'Enter your password for sudo to approve sending 50 USD1.',
    );
    expect(prompt).not.toContain('screen:');
    await press(stdin, ...'hunter2'.split(''));
    expect(lastFrame()).not.toContain('hunter2');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'screen: got 7');
  });

  it('esc cancels', async () => {
    const prompter = createPasswordPrompter();
    const answer = vi.fn();
    const { lastFrame, stdin } = render(
      <PasswordPromptHost prompter={prompter}>
        <Text>screen</Text>
      </PasswordPromptHost>,
    );
    await waitFor(lastFrame, 'screen');
    void prompter.ask('do it', 1).then(answer);
    await waitFor(lastFrame, 'Enter your password');
    await press(stdin, KEY.escape);
    await vi.waitFor(() => expect(answer).toHaveBeenCalledWith(null));
    await waitFor(lastFrame, 'screen');
  });

  it('keys typed into the prompt never reach the screen underneath', async () => {
    const prompter = createPasswordPrompter();
    const seen: string[] = [];
    const answer = vi.fn();
    const { lastFrame, stdin } = render(
      <PasswordPromptHost prompter={prompter}>
        <KeyLog seen={seen} />
      </PasswordPromptHost>,
    );
    await waitFor(lastFrame, 'screen');
    void prompter.ask('do it', 1).then(answer);
    await waitFor(lastFrame, 'Enter your password');
    await press(stdin, 'q', 'n', KEY.escape);
    await vi.waitFor(() => expect(answer).toHaveBeenCalledWith(null));
    expect(seen).toEqual([]);
    await waitFor(lastFrame, 'screen');
    await press(stdin, 'r');
    await vi.waitFor(() => expect(seen).toEqual(['r']));
  });
});
