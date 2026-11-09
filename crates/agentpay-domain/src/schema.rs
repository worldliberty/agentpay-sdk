//! Schema-only types that describe how domain values look on the wire.
//!
//! Some domain fields are stored as Rust types whose JSON encoding is not obvious
//! from the type itself (`u128` amounts are decimal strings, `OffsetDateTime`
//! is a 9-element array). The types in this module are never constructed; they
//! exist so the generated JSON Schema (`schemars`) and TypeScript bindings
//! (`ts-rs`) name those encodings once instead of repeating them per field.

use schemars::JsonSchema;
use ts_rs::TS;

/// An unsigned 128-bit integer encoded as a base-10 string, for example `"1000000"`.
///
/// Used for every amount (wei, token base units, lamports) and every limit that
/// may exceed 2^53, so JavaScript clients never lose precision. No sign, no
/// leading `+`, no exponent, no `0x` prefix; leading zeros are accepted on input.
#[derive(JsonSchema, TS)]
pub struct DecimalU128(#[schemars(regex(pattern = r"^[0-9]{1,39}$"))] pub String);

/// A UTC-offset timestamp in the daemon's compact wire encoding.
///
/// It is the 9-element JSON array
/// `[year, ordinal, hour, minute, second, nanosecond, offset_hours, offset_minutes, offset_seconds]`
/// produced by the `time` crate's non-human-readable serde format, where
/// `ordinal` is the 1-based day of the year (1..=366). The daemon always emits
/// UTC (`offset_*` = 0). Example: `2026-11-05T12:30:00Z` is
/// `[2026, 309, 12, 30, 0, 0, 0, 0, 0]`.
#[derive(JsonSchema, TS)]
pub struct Timestamp(
    /// Calendar year, for example `2026`.
    pub i32,
    /// Day of the year, 1-based (1..=366).
    pub u16,
    /// Hour, 0..=23.
    pub u8,
    /// Minute, 0..=59.
    pub u8,
    /// Second, 0..=59.
    pub u8,
    /// Nanosecond, 0..=999_999_999.
    pub u32,
    /// Whole hours of the UTC offset (signed).
    pub i8,
    /// Minutes past the hour of the UTC offset (signed).
    pub i8,
    /// Seconds past the minute of the UTC offset (signed).
    pub i8,
);
