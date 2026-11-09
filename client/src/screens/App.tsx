/** The interactive home app: Home and the screens it opens. */
import { useApp } from 'ink';
import { useState } from 'react';
import { ActivityScreen } from './Activity.js';
import { ApprovalsScreen } from './Approvals.js';
import { type HomeAction, HomeScreen } from './Home.js';
import { LimitsScreen } from './Limits.js';
import { ReceiveScreen } from './Receive.js';
import { SecurityScreen } from './Security.js';
import { SendScreen } from './Send.js';
import type { AppServices } from './types.js';
import { WalletsScreen } from './Wallets.js';

export type Route = 'home' | Exclude<HomeAction, 'quit'>;

export function App({ services, initial = 'home' }: { services: AppServices; initial?: Route }) {
  const [route, setRoute] = useState<Route>(initial);
  const { exit } = useApp();
  // Opened directly (`agentpay admin approvals`): leaving the screen leaves the app.
  const home = initial === 'home' ? () => setRoute('home') : () => exit();
  switch (route) {
    case 'receive':
      return (
        <ReceiveScreen
          options={() => services.receiveOptions()}
          load={(choice) => services.funding(choice?.network, choice?.asset)}
          watch={(choice) => services.balance(choice?.network, choice?.asset)}
          onBack={home}
        />
      );
    case 'approvals':
      return <ApprovalsScreen services={services} onBack={home} />;
    case 'limits':
      return <LimitsScreen services={services} onBack={home} />;
    case 'send':
      return <SendScreen services={services} onBack={home} />;
    case 'activity':
      return (
        <ActivityScreen
          services={services}
          onBack={home}
          onOpenApprovals={() => setRoute('approvals')}
        />
      );
    case 'wallet':
      return <WalletsScreen services={services} onBack={home} />;
    case 'security':
      return <SecurityScreen services={services} onBack={home} />;
    case 'home':
      return (
        <HomeScreen
          load={() => services.loadHome()}
          onAction={(action) => {
            if (action !== 'quit') {
              setRoute(action);
            }
          }}
        />
      );
  }
}
