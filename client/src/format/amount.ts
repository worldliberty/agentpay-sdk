/**
 * Decimal amount helpers. Amounts are never parsed as floating-point numbers: whole-unit
 * strings ("1.5") and base-unit strings ("1500000") are converted with BigInt only.
 */

const DECIMAL_PATTERN = /^(\d+)(?:\.(\d+))?$/u;
const INTEGER_PATTERN = /^\d+$/u;

/** Whether `value` is a non-negative decimal string such as `"10"` or `"0.25"`. */
export function isDecimalString(value: string): boolean {
  return DECIMAL_PATTERN.test(value.trim());
}

/** Whether `value` is a non-negative base-10 integer string (a `DecimalU128` on the wire). */
export function isIntegerString(value: string): boolean {
  return INTEGER_PATTERN.test(value.trim());
}

/**
 * Converts a whole-unit decimal string to base units. Throws when `value` is not a decimal or
 * has more fractional digits than `decimals`.
 */
export function parseUnits(value: string, decimals: number): bigint {
  const match = DECIMAL_PATTERN.exec(value.trim());
  if (!match) {
    throw new RangeError(`"${value}" is not a decimal amount`);
  }
  const whole = match[1] ?? '0';
  const fraction = match[2] ?? '';
  if (fraction.length > decimals) {
    throw new RangeError(`"${value}" has more than ${decimals} decimal places`);
  }
  return BigInt(whole + fraction.padEnd(decimals, '0'));
}

/** Formats base units as a whole-unit decimal string without trailing zeros. */
export function formatUnits(baseUnits: bigint, decimals: number): string {
  const negative = baseUnits < 0n;
  const digits = (negative ? -baseUnits : baseUnits).toString().padStart(decimals + 1, '0');
  const whole = digits.slice(0, digits.length - decimals);
  const fraction = digits.slice(digits.length - decimals).replace(/0+$/u, '');
  const text = fraction ? `${whole}.${fraction}` : whole;
  return negative ? `-${text}` : text;
}

/** Compares two whole-unit decimal strings exactly. */
export function compareDecimal(a: string, b: string): number {
  const scale = Math.max(fractionDigits(a), fractionDigits(b));
  const left = parseUnits(a, scale);
  const right = parseUnits(b, scale);
  return left === right ? 0 : left < right ? -1 : 1;
}

function fractionDigits(value: string): number {
  const dot = value.indexOf('.');
  return dot === -1 ? 0 : value.length - dot - 1;
}

/**
 * Shortens a decimal for display: at most `maxFraction` fractional digits, with thousands
 * separators in the whole part. Truncates (never rounds up) so a balance is never overstated.
 */
export function displayAmount(value: string, maxFraction = 6): string {
  const match = DECIMAL_PATTERN.exec(value.trim());
  if (!match) {
    return value;
  }
  const whole = (match[1] ?? '0').replace(/\B(?=(\d{3})+(?!\d))/gu, ',');
  const fraction = (match[2] ?? '').slice(0, maxFraction).replace(/0+$/u, '');
  return fraction ? `${whole}.${fraction}` : whole;
}

/**
 * The 1-2-5 ladder used by limit steppers ("+"/"-"): 0.001, 0.002, 0.005, 0.01, ... 1, 2, 5,
 * 10, 20, 50, 100, ... up to 10^12.
 */
const LADDER: readonly string[] = (() => {
  const values: string[] = [];
  for (let exponent = -3; exponent <= 12; exponent += 1) {
    for (const mantissa of [1, 2, 5]) {
      values.push(
        exponent < 0
          ? `0.${'0'.repeat(-exponent - 1)}${mantissa}`
          : `${mantissa}${'0'.repeat(exponent)}`,
      );
    }
  }
  return values;
})();

/** The next ladder value strictly above (`+1`) or below (`-1`) `value`, or `value` at an end. */
export function stepAmount(value: string, direction: 1 | -1): string {
  if (!isDecimalString(value) || compareDecimal(value, '0') === 0) {
    return direction === 1 ? (LADDER[0] ?? value) : '0';
  }
  if (direction === 1) {
    return LADDER.find((candidate) => compareDecimal(candidate, value) > 0) ?? value;
  }
  const below = LADDER.filter((candidate) => compareDecimal(candidate, value) < 0);
  return below[below.length - 1] ?? value;
}
