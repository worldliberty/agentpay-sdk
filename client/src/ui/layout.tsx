/** Screen frame, step indicator, key hints, labeled rows, callouts, and error panels. */
import { Box, Text } from 'ink';
import type { ReactNode } from 'react';
import { copy, type Guidance } from '../copy/index.js';
import { glyph, space, T, type Tone } from './theme.js';

export interface StepInfo {
  index: number;
  total: number;
  label: string;
}

/** "Step 2 of 6  ● ● ○ ○ ○ ○  Protect your wallet" */
export function StepIndicator({ index, total, label }: StepInfo) {
  const dots = Array.from({ length: total }, (_, i) =>
    i <= index ? glyph.stepDone : glyph.stepTodo,
  ).join(' ');
  return (
    <Box gap={2}>
      <T tone="muted">{copy.common.stepOf(index + 1, total)}</T>
      <T tone="accent">{dots}</T>
      <T tone="muted">{label}</T>
    </Box>
  );
}

/** Footer of keyboard hints: "↑↓ select · enter continue · esc back". */
export function KeyHints({ hints }: { hints: readonly string[] }) {
  return <T tone="muted">{hints.join(` ${glyph.separator} `)}</T>;
}

export interface ScreenProps {
  title: string;
  step?: StepInfo;
  /** Short context shown right of the title, e.g. a shortened address. */
  aside?: string;
  hints: readonly string[];
  error?: Guidance | null;
  children: ReactNode;
}

/** Every screen: header, optional step indicator, body, error, and key hints. */
export function Screen({ title, step, aside, hints, error, children }: ScreenProps) {
  return (
    <Box flexDirection="column" paddingX={space.gutter} paddingY={1}>
      <Box gap={1}>
        <T tone="accent" bold>
          {copy.common.product}
        </T>
        <T tone="muted">{glyph.separator}</T>
        <T bold>{title}</T>
        {aside ? <T tone="muted">{`  ${aside}`}</T> : null}
      </Box>
      {step ? (
        <Box marginTop={space.section}>
          <StepIndicator {...step} />
        </Box>
      ) : null}
      <Box flexDirection="column" marginTop={space.section} gap={space.section}>
        {children}
      </Box>
      {error ? (
        <Box marginTop={space.section}>
          <ErrorPanel guidance={error} />
        </Box>
      ) : null}
      <Box marginTop={space.section}>
        <KeyHints hints={hints} />
      </Box>
    </Box>
  );
}

/** One error and its single next action. */
export function ErrorPanel({ guidance }: { guidance: Guidance }) {
  return (
    <Box flexDirection="column">
      <T tone="danger" bold>{`${glyph.cross} ${guidance.message}`}</T>
      <Box marginLeft={space.indent}>
        <T>{`${copy.common.next}: ${guidance.next}`}</T>
      </Box>
    </Box>
  );
}

export interface Row {
  label: string;
  value: string;
  tone?: Tone;
}

/** Label/value rows with an aligned label column (To, Amount, Network, …). */
export function Rows({ rows }: { rows: readonly Row[] }) {
  const width = Math.max(...rows.map((row) => row.label.length)) + 2;
  return (
    <Box flexDirection="column">
      {rows.map((row) => (
        <Box key={row.label}>
          <Box width={width} flexShrink={0}>
            <T tone="muted">{row.label}</T>
          </Box>
          <T {...(row.tone ? { tone: row.tone } : {})}>{row.value}</T>
        </Box>
      ))}
    </Box>
  );
}

/** A bordered note: "Important things to know", irreversible warnings. */
export function Callout({
  title,
  items,
  tone = 'warning',
  children,
}: {
  title: string;
  items: readonly string[];
  tone?: Tone;
  children?: ReactNode;
}) {
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      paddingX={1}
      borderDimColor
      alignSelf="flex-start"
    >
      <T tone={tone} bold>{`${glyph.warning} ${title}`}</T>
      {items.map((item) => (
        <Text key={item}>{`${glyph.bullet} ${item}`}</Text>
      ))}
      {children}
    </Box>
  );
}

/** Plain paragraph text with the muted tone by default. */
export function Paragraph({ children, tone = 'default' }: { children: string; tone?: Tone }) {
  return <T tone={tone}>{children}</T>;
}
