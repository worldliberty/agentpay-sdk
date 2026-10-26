import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';

const modulePath = new URL('../src/lib/hidden-tty-prompt.ts', import.meta.url);

function loadModule(caseId) {
  return import(`${modulePath.href}?case=${caseId}`);
}

function createTty({ isRaw = false } = {}) {
  const input = new EventEmitter();
  input.isTTY = true;
  input.isRaw = isRaw;
  input.rawModes = [];
  input.paused = false;
  input.setRawMode = (mode) => {
    input.rawModes.push(mode);
    input.isRaw = mode;
  };
  input.resume = () => {
    input.paused = false;
  };
  input.pause = () => {
    input.paused = true;
  };
  const writes = [];
  const output = {
    isTTY: true,
    write: (chunk) => {
      writes.push(chunk);
      return true;
    },
  };
  return { input, output, writes };
}

test('promptHiddenTty collects input, applies editing keys, and restores the terminal', async () => {
  const { promptHiddenTty } = await loadModule(`${Date.now()}-collect`);
  const { input, output, writes } = createTty();

  const pending = promptHiddenTty('Password: ', 'not a tty', { input, output });
  input.emit('data', Buffer.from('abX\u007fc'));
  input.emit('data', '\u0001d');
  input.emit('data', '\r');

  assert.equal(await pending, 'abcd');
  assert.deepEqual(input.rawModes, [true, false]);
  assert.equal(input.paused, true);
  assert.equal(input.listenerCount('data'), 0);
  assert.equal(input.listenerCount('error'), 0);
  assert.ok(writes.includes('Password: '));
  assert.equal(writes.join('').includes('abcd'), false);
});

test('promptHiddenTty clears the line on Ctrl+U and ignores escape sequences', async () => {
  const { promptHiddenTty } = await loadModule(`${Date.now()}-ctrl-u`);
  const { input, output } = createTty();

  const pending = promptHiddenTty('Password: ', 'not a tty', { input, output });
  input.emit('data', 'wrong\u0015');
  input.emit('data', '\u001b[A');
  input.emit('data', 'right\n');

  assert.equal(await pending, 'right');
});

for (const [label, char] of [
  ['Ctrl+C', '\u0003'],
  ['Ctrl+D', '\u0004'],
]) {
  test(`promptHiddenTty treats ${label} as cancel`, async () => {
    const { promptHiddenTty } = await loadModule(`${Date.now()}-${label}`);
    const { input, output } = createTty();

    const pending = promptHiddenTty('Password: ', 'not a tty', { input, output });
    input.emit('data', `partial${char}ignored\r`);

    await assert.rejects(pending, /prompt canceled/u);
    assert.deepEqual(input.rawModes, [true, false]);
    assert.equal(input.listenerCount('data'), 0);
  });
}

test('promptHiddenTty leaves an already-raw terminal in raw mode and rejects on input errors', async () => {
  const { promptHiddenTty } = await loadModule(`${Date.now()}-raw-error`);
  const { input, output } = createTty({ isRaw: true });

  const pending = promptHiddenTty('Password: ', 'not a tty', { input, output });
  input.emit('error', new Error('tty read failed'));

  await assert.rejects(pending, /tty read failed/u);
  assert.deepEqual(input.rawModes, []);
});

test('promptHiddenTty refuses non-interactive input or output', async () => {
  const { promptHiddenTty } = await loadModule(`${Date.now()}-non-tty`);

  const noInputTty = createTty();
  noInputTty.input.isTTY = false;
  await assert.rejects(
    promptHiddenTty('Password: ', 'rerun on a local TTY', noInputTty),
    /rerun on a local TTY/u,
  );

  const noOutputTty = createTty();
  noOutputTty.output.isTTY = false;
  await assert.rejects(
    promptHiddenTty('Password: ', 'rerun on a local TTY', noOutputTty),
    /rerun on a local TTY/u,
  );

  const noRawMode = createTty();
  delete noRawMode.input.setRawMode;
  await assert.rejects(
    promptHiddenTty('Password: ', 'rerun on a local TTY', noRawMode),
    /rerun on a local TTY/u,
  );
});
