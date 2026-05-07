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
