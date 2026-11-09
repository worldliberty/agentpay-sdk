import type { Io } from '../../src/app/context.js';

export interface FakeIo extends Io {
  out(): string;
  err(): string;
  json<T = Record<string, unknown>>(): T;
  questions: string[];
}

export function fakeIo(
  options: { stdin?: string; isTTY?: boolean; answers?: string[] } = {},
): FakeIo {
  let out = '';
  let err = '';
  const answers = [...(options.answers ?? [])];
  const questions: string[] = [];
  return {
    stdout: (text) => {
      out += typeof text === 'string' ? text : Buffer.from(text).toString('utf8');
    },
    stderr: (text) => {
      err += text;
    },
    readStdin: async () => options.stdin ?? '',
    question: async (prompt) => {
      questions.push(prompt);
      return answers.shift() ?? '';
    },
    isTTY: options.isTTY ?? false,
    out: () => out,
    err: () => err,
    json: <T>() => JSON.parse(out) as T,
    questions,
  };
}
