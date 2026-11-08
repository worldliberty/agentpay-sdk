import type { Timestamp } from '../generated/index.js';

/** Shortens a long address or id for display: `0x5aed…67de`. */
export function shortAddress(value: string, head = 6, tail = 4): string {
  return value.length <= head + tail + 1 ? value : `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/** Converts the daemon's 9-element UTC timestamp array to a `Date`. */
export function timestampToDate(timestamp: Timestamp): Date {
  const [year, dayOfYear, hour, minute, second, nanosecond, offsetH, offsetM, offsetS] = timestamp;
  const offsetMs = ((offsetH * 60 + offsetM) * 60 + offsetS) * 1000;
  const utc = Date.UTC(year, 0, dayOfYear, hour, minute, second, Math.floor(nanosecond / 1e6));
  return new Date(utc - offsetMs);
}

/** "just now", "5 min ago", "3 h ago", "2 days ago". */
export function relativeTime(date: Date, now: Date = new Date()): string {
  const seconds = Math.max(0, Math.round((now.getTime() - date.getTime()) / 1000));
  if (seconds < 60) {
    return 'just now';
  }
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) {
    return `${minutes} min ago`;
  }
  const hours = Math.round(minutes / 60);
  if (hours < 48) {
    return `${hours} h ago`;
  }
  return `${Math.round(hours / 24)} days ago`;
}

/** Pads `text` to `width` columns (no truncation). */
export function padEnd(text: string, width: number): string {
  return text.length >= width ? text : text + ' '.repeat(width - text.length);
}

/** Renders rows as aligned plain-text columns separated by two spaces. */
export function columns(rows: readonly (readonly string[])[]): string[] {
  const widths: number[] = [];
  for (const row of rows) {
    row.forEach((cell, index) => {
      widths[index] = Math.max(widths[index] ?? 0, cell.length);
    });
  }
  return rows.map((row) =>
    row
      .map((cell, index) => (index === row.length - 1 ? cell : padEnd(cell, widths[index] ?? 0)))
      .join('  ')
      .trimEnd(),
  );
}
