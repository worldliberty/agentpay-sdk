/**
 * Design tokens: tones (semantic colors), spacing, and glyphs. Colors are dropped entirely when
 * `NO_COLOR` is set (https://no-color.org) or the terminal is `dumb`; emphasis then comes from
 * bold and dim text only.
 */
import { Text } from 'ink';
import { createContext, type ReactNode, useContext } from 'react';

export type Tone = 'default' | 'muted' | 'accent' | 'success' | 'warning' | 'danger';

const PALETTE: Readonly<Record<Tone, string | undefined>> = {
  default: undefined,
  muted: 'gray',
  accent: 'cyan',
  success: 'green',
  warning: 'yellow',
  danger: 'red',
};

export interface Theme {
  color: boolean;
}

/** Spacing scale, in terminal cells. */
export const space = {
  /** Between a screen's sections. */
  section: 1,
  /** Left padding of a screen. */
  gutter: 2,
  /** Indent of nested content. */
  indent: 2,
} as const;

export const glyph = {
  check: '✓',
  cross: '✗',
  bullet: '•',
  stepDone: '●',
  stepTodo: '○',
  pointer: '›',
  warning: '!',
  barFull: '█',
  barEmpty: '░',
  separator: '·',
  minus: '−',
  plus: '+',
} as const;

export function themeFromEnv(env: NodeJS.ProcessEnv): Theme {
  const noColor = env.NO_COLOR !== undefined && env.NO_COLOR !== '';
  return { color: !noColor && env.TERM !== 'dumb' };
}

const ThemeContext = createContext<Theme>({ color: true });

export function ThemeProvider({ theme, children }: { theme: Theme; children?: ReactNode }) {
  return <ThemeContext.Provider value={theme}>{children}</ThemeContext.Provider>;
}

export function useTheme(): Theme {
  return useContext(ThemeContext);
}

export interface ToneTextProps {
  tone?: Tone;
  bold?: boolean;
  inverse?: boolean;
  wrap?: 'wrap' | 'truncate-end';
  children: ReactNode;
}

/** Text in a semantic tone. Muted text is dimmed when colors are off. */
export function T({ tone = 'default', bold, inverse, wrap, children }: ToneTextProps) {
  const theme = useTheme();
  const color = theme.color ? PALETTE[tone] : undefined;
  return (
    <Text
      {...(color ? { color } : {})}
      {...(!theme.color && tone === 'muted' ? { dimColor: true } : {})}
      {...(bold ? { bold } : {})}
      {...(inverse ? { inverse } : {})}
      {...(wrap ? { wrap } : {})}
    >
      {children}
    </Text>
  );
}
