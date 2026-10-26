export type BalanceBucket = '0' | '<10' | '10-100' | '100-1k' | '1k-10k' | '10k+';

const BUCKET_UPPER_BOUNDS: ReadonlyArray<readonly [number, BalanceBucket]> = [
  [10, '<10'],
  [100, '10-100'],
  [1_000, '100-1k'],
  [10_000, '1k-10k'],
];

/**
 * Collapses a held balance into a coarse range so analytics never carries an exact position.
 * Amounts are expected in whole units (USD when a price is known, otherwise token units).
 */
export function bucketAmount(amount: number): BalanceBucket | undefined {
  if (!Number.isFinite(amount) || amount < 0) {
    return undefined;
  }
  if (amount === 0) {
    return '0';
  }

  for (const [upperBound, bucket] of BUCKET_UPPER_BOUNDS) {
    if (amount < upperBound) {
      return bucket;
    }
  }

  return '10k+';
}

export function bucketDecimalString(amount: string | undefined): BalanceBucket | undefined {
  if (!amount?.trim()) {
    return undefined;
  }

  return bucketAmount(Number(amount));
}
