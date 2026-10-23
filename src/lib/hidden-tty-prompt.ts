interface HiddenPromptInput {
  isRaw?: boolean;
  isTTY?: boolean;
  on(event: 'data', listener: (chunk: Buffer | string) => void): this;
  on(event: 'error', listener: (error: Error) => void): this;
  removeListener(event: 'data', listener: (chunk: Buffer | string) => void): this;
  removeListener(event: 'error', listener: (error: Error) => void): this;
  pause?(): void;
  resume?(): void;
  setRawMode?(mode: boolean): void;
}

interface HiddenPromptOutput {
  isTTY?: boolean;
  write(chunk: string): boolean;
}

interface HiddenPromptDeps {
  input?: HiddenPromptInput;
  output?: HiddenPromptOutput;
}

export async function promptHiddenTty(
  query: string,
  nonInteractiveError: string,
  deps: HiddenPromptDeps = {},
): Promise<string> {
  const input = deps.input ?? (process.stdin as unknown as HiddenPromptInput);
  const output = deps.output ?? (process.stderr as unknown as HiddenPromptOutput);

  if (!input.isTTY || !output.isTTY || typeof input.setRawMode !== 'function') {
    throw new Error(nonInteractiveError);
  }

  output.write('\r\u001b[2K');
  output.write(query);
  const wasRaw = Boolean(input.isRaw);
  if (!wasRaw) {
    input.setRawMode(true);
  }
  input.resume?.();

  return await new Promise<string>((resolve, reject) => {
    let answer = '';
    let settled = false;

    const cleanup = () => {
      input.removeListener('data', onData);
      input.removeListener('error', onError);
      if (!wasRaw) {
        input.setRawMode?.(false);
      }
      input.pause?.();
      output.write('\n');
    };

    const finish = (callback: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback();
    };

    const onError = (error: Error) => {
      finish(() => reject(error));
    };

    const onData = (chunk: Buffer | string) => {
      const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      if (text.includes('\u001b')) {
        return;
      }

      for (const char of text) {
        if (char === '\r' || char === '\n') {
          finish(() => resolve(answer));
          return;
        }
        if (char === '\u0003' || char === '\u0004') {
          finish(() => reject(new Error('prompt canceled')));
          return;
        }
        if (char === '\u007f' || char === '\b') {
          const chars = Array.from(answer);
          chars.pop();
          answer = chars.join('');
          continue;
        }
        if (char === '\u0015') {
          answer = '';
          continue;
        }
        // biome-ignore lint/suspicious/noControlCharactersInRegex: drops control characters from hidden TTY input
        if (/[\u0000-\u001f\u007f]/u.test(char)) {
          continue;
        }
        answer += char;
      }
    };

    input.on('data', onData);
    input.on('error', onError);
  });
}
