/**
 * Derives the analytics `distinct_id`.
 *
 * The id is the random per-install UUID stored in `~/.agentpay/telemetry.json`, and nothing else.
 * An earlier design keyed analytics to a salted HMAC of the wallet address so a reinstall would
 * count as the same user. The salt had to ship inside a public bundle, though, which meant anyone
 * holding it could confirm whether a given on-chain address was behind an analytics identity — a
 * link to on-chain identity that telemetry must not carry. A reinstall that wipes `~/.agentpay` is
 * therefore counted as a new user, which is the acceptable side of that trade.
 */
export function resolveDistinctId(installId: string): string {
  return installId.trim();
}
