import uiPreset from '@worldlibertyfinancial/agent-ui/tailwind';
import type { Config } from 'tailwindcss';

const config: Config = {
  presets: [uiPreset as Config],
  content: ['./src/**/*.{ts,tsx}', '../../packages/ui/src/**/*.{ts,tsx}'],
};

export default config;
