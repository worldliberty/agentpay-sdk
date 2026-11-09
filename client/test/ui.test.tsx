import { describe, expect, it, vi } from 'vitest';
import { Menu, Stepper, TaskList, UsageBar, usageRatio } from '../src/ui/controls.js';
import { Callout, ErrorPanel, KeyHints, Rows, Screen, StepIndicator } from '../src/ui/layout.js';
import { themeFromEnv } from '../src/ui/theme.js';
import { KEY, press, render, waitFor } from './helpers/ink.js';

describe('design system', () => {
  it('step indicator shows position and label', () => {
    expect(
      render(<StepIndicator index={1} total={6} label="Protect your wallet" />).lastFrame(),
    ).toBe('Step 2 of 6  ● ● ○ ○ ○ ○  Protect your wallet');
  });

  it('key hints join with a separator', () => {
    expect(
      render(<KeyHints hints={['↑↓ select', 'enter continue', 'esc back']} />).lastFrame(),
    ).toBe('↑↓ select · enter continue · esc back');
  });

  it('labeled rows align their values', () => {
    const frame = render(
      <Rows
        rows={[
          { label: 'To', value: '0x5aed…67de' },
          { label: 'Amount', value: '1 USD1' },
        ]}
      />,
    ).lastFrame();
    expect(frame).toBe('To      0x5aed…67de\nAmount  1 USD1');
  });

  it('usage bar fills by ratio', () => {
    expect(usageRatio(40n, 100n)).toBe(0.4);
    expect(usageRatio(150n, 100n)).toBe(1);
    expect(
      render(<UsageBar ratio={0.4} width={10} caption="40 of 100 USD1 used" />).lastFrame(),
    ).toBe('████░░░░░░ 40 of 100 USD1 used');
  });

  it('stepper and task list', () => {
    expect(render(<Stepper value="10" focused={false} width={4} />).lastFrame()).toBe('−   10 +');
    expect(
      render(
        <TaskList
          tasks={[
            { label: 'Generating wallet keys', state: 'done' },
            { label: 'Saving', state: 'pending' },
          ]}
        />,
      ).lastFrame(),
    ).toBe('✓ Generating wallet keys\n○ Saving');
  });

  it('screen frame with callout and error snapshot', () => {
    const frame = render(
      <Screen
        title="Receive USD1"
        step={{ index: 0, total: 3, label: 'Welcome' }}
        hints={['esc back']}
        error={{ message: 'It broke.', next: 'Try again.' }}
      >
        <Callout title="Important things to know" items={['Only send USD1 on BSC.']} />
      </Screen>,
    ).lastFrame();
    expect(frame).toMatchSnapshot();
    expect(
      render(<ErrorPanel guidance={{ message: 'No socket.', next: 'Run setup.' }} />).lastFrame(),
    ).toBe('✗ No socket.\n  Next: Run setup.');
  });

  it('turns colors off for NO_COLOR and dumb terminals', () => {
    expect(themeFromEnv({}).color).toBe(true);
    expect(themeFromEnv({ NO_COLOR: '1' }).color).toBe(false);
    expect(themeFromEnv({ NO_COLOR: '' }).color).toBe(true);
    expect(themeFromEnv({ TERM: 'dumb' }).color).toBe(false);
  });
});

describe('menu', () => {
  it('opens on the first row that can be chosen', async () => {
    const onSelect = vi.fn();
    const { lastFrame, stdin } = render(
      <Menu
        items={[
          { value: 'touch', label: 'Turn on Touch ID', disabled: true },
          { value: 'alerts', label: 'Turn on approval alerts' },
        ]}
        onSelect={onSelect}
      />,
    );
    await waitFor(lastFrame, '› Turn on approval alerts');
    await press(stdin, KEY.enter);
    expect(onSelect).toHaveBeenCalledWith('alerts');
  });
});
