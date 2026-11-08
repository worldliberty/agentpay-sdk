/**
 * `agentpay setup` on a machine that is already set up: instead of reinstalling the services and
 * walking the whole wizard again (which would replace the spending limits), it asks what to
 * change and opens just that.
 */
import { Box, useApp } from 'ink';
import { copy } from '../copy/index.js';
import { Menu } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { Screen } from '../ui/layout.js';
import { T } from '../ui/theme.js';

export type SetupChoice = 'limits' | 'wallet' | 'security' | 'repair' | 'full' | 'quit';

export function SetupMenu({
  wallet,
  onChoose,
}: {
  /** The wallet the agents use, as a label ("Trading bot · 0x8170…0bde"). */
  wallet: string | null;
  onChoose: (choice: SetupChoice) => void;
}) {
  const m = copy.screens.setupMenu;
  const k = copy.common.keys;
  const { exit } = useApp();
  const choose = (choice: SetupChoice) => {
    onChoose(choice);
    exit();
  };
  useInput((input, key) => {
    if (input === 'q' || key.escape) {
      choose('quit');
    }
  });
  return (
    <Screen title={m.title} hints={[k.select, k.open, k.quit]}>
      <Box flexDirection="column" gap={1}>
        <T>{wallet ? m.bodyWithWallet(wallet) : m.body}</T>
        <Menu<SetupChoice>
          items={[
            { value: 'limits', label: m.limits, hint: m.limitsHint },
            { value: 'wallet', label: m.wallet, hint: m.walletHint },
            { value: 'security', label: m.security, hint: m.securityHint },
            { value: 'repair', label: m.repair, hint: m.repairHint },
            { value: 'full', label: m.full, hint: m.fullHint },
          ]}
          onSelect={choose}
        />
      </Box>
    </Screen>
  );
}
