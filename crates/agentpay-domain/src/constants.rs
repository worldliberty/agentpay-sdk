/// EIP-7702 transaction type id.
pub const EIP7702_TX_TYPE: u8 = 0x04;
/// Default max gas spend per chain in wei (0.001 native token).
pub const DEFAULT_MAX_GAS_SPEND_PER_CHAIN_WEI: u128 = 1_000_000_000_000_000;
/// Canonical internal policy id for Solana mainnet/mainnet-beta.
pub const SOLANA_MAINNET_CHAIN_ID: u64 = 900_000_001;
/// Internal policy id historically used for Solana devnet.
pub const SOLANA_DEVNET_CHAIN_ID: u64 = 900_000_002;
/// Internal policy id historically used for Solana testnet.
pub const SOLANA_TESTNET_CHAIN_ID: u64 = 900_000_003;
/// Solana signatures do not bind a cluster id, so all Solana clusters share
/// one policy/accounting network family inside the daemon.
pub const SOLANA_POLICY_CHAIN_ID: u64 = SOLANA_MAINNET_CHAIN_ID;
/// Serialized size of a Solana durable nonce account (`NonceVersions`) in bytes.
pub const SOLANA_NONCE_ACCOUNT_DATA_LEN_BYTES: u128 = 80;
/// Rent-exempt minimum for an 80-byte Solana nonce account, from the runtime's
/// rent formula: `(ACCOUNT_STORAGE_OVERHEAD + data_len) * lamports_per_byte_year
/// * exemption_threshold_years` = `(128 + 80) * 3480 * 2` = 1_447_680 lamports.
pub const SOLANA_NONCE_ACCOUNT_RENT_EXEMPT_MINIMUM_LAMPORTS: u128 =
    (128 + SOLANA_NONCE_ACCOUNT_DATA_LEN_BYTES) * 3_480 * 2;
/// Upper bound accepted for `SolanaNonceAccountCreate::rent_lamports`.
///
/// Nonce account creation is wallet maintenance and bypasses spending
/// policies, so the rent it moves must be bounded. Twice the rent-exempt
/// minimum leaves headroom for cluster rent-parameter drift while preventing
/// the maintenance path from being used to drain SOL into a nonce account.
pub const SOLANA_NONCE_ACCOUNT_MAX_RENT_LAMPORTS: u128 =
    SOLANA_NONCE_ACCOUNT_RENT_EXEMPT_MINIMUM_LAMPORTS * 2;
/// Most transfer legs (the primary payment plus splits) in one
/// `SolanaPaymentTransaction`.
pub const SOLANA_PAYMENT_MAX_LEGS: usize = 9;
/// Longest memo, in UTF-8 bytes, that a `SolanaPaymentTransaction` carries
/// (per transaction and per leg).
pub const SOLANA_PAYMENT_MAX_MEMO_BYTES: usize = 566;
/// Highest compute unit limit a `SolanaPaymentTransaction` may request.
pub const SOLANA_PAYMENT_MAX_COMPUTE_UNIT_LIMIT: u32 = 200_000;

#[must_use]
pub fn is_solana_chain_id(chain_id: u64) -> bool {
    matches!(
        chain_id,
        SOLANA_MAINNET_CHAIN_ID | SOLANA_DEVNET_CHAIN_ID | SOLANA_TESTNET_CHAIN_ID
    )
}

#[must_use]
pub fn canonical_policy_chain_id(chain_id: u64) -> u64 {
    if is_solana_chain_id(chain_id) {
        SOLANA_POLICY_CHAIN_ID
    } else {
        chain_id
    }
}

/// Tempo mainnet chain id.
pub const TEMPO_MAINNET_CHAIN_ID: u64 = 4217;
/// Tempo testnet (Moderato) chain id.
pub const TEMPO_TESTNET_CHAIN_ID: u64 = 42431;
/// Tempo transaction envelope type byte.
pub const TEMPO_TX_TYPE: u8 = 0x76;
/// TIP-1034 TIP-20 channel reserve precompile (Tempo sessions v2), identical on every Tempo chain.
pub const TEMPO_CHANNEL_RESERVE_CONTRACT: &str = "0x4d50500000000000000000000000000000000000";
/// EIP-712 domain name of TIP-1034 channel reserve vouchers and close authorizations.
pub const TEMPO_CHANNEL_RESERVE_DOMAIN_NAME: &str = "TIP20 Channel Reserve";
/// EIP-712 domain version of TIP-1034 channel reserve vouchers and close authorizations.
pub const TEMPO_CHANNEL_RESERVE_DOMAIN_VERSION: &str = "1";

/// Returns whether `chain_id` is a supported Tempo network.
#[must_use]
pub fn is_tempo_chain_id(chain_id: u64) -> bool {
    matches!(chain_id, TEMPO_MAINNET_CHAIN_ID | TEMPO_TESTNET_CHAIN_ID)
}
