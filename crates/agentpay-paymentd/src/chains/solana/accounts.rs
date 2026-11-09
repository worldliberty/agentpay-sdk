//! Reading Solana account state: durable nonce accounts, token mints
//! (SPL Token and Token-2022, with the transfer fee and transfer hook
//! extensions), and associated token account addresses.

use agentpay_domain::SolanaTokenProgram;
use solana_nonce::state::State as NonceState;
use solana_nonce::versions::Versions as NonceVersions;
use solana_sdk::account::Account;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use spl_token_2022_interface::extension::transfer_fee::TransferFeeConfig;
use spl_token_2022_interface::extension::transfer_hook::TransferHook;
use spl_token_2022_interface::extension::{BaseStateWithExtensions, StateWithExtensions};
use spl_token_2022_interface::state::Mint;

use crate::error::PaymentsError;

/// Size of a durable nonce account's data.
pub const NONCE_ACCOUNT_LEN: usize = 80;

/// The system program.
#[must_use]
pub fn system_program_id() -> Pubkey {
    solana_system_interface::program::ID
}

/// The program that owns mints of `program`.
#[must_use]
pub fn token_program_id(program: SolanaTokenProgram) -> Pubkey {
    match program {
        SolanaTokenProgram::Token => spl_token::ID,
        SolanaTokenProgram::Token2022 => spl_token_2022_interface::id(),
    }
}

/// The associated token account of `owner` for `mint` under `program`.
#[must_use]
pub fn associated_token_account(owner: &Pubkey, mint: &Pubkey, program: &Pubkey) -> Pubkey {
    spl_associated_token_account::get_associated_token_address_with_program_id(owner, mint, program)
}

/// The agent's managed nonce account on one network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedNonceAccount {
    /// `create_with_seed(wallet, seed, system program)`.
    pub address: Pubkey,
    /// `agentpay-<chain_id>-nonce`.
    pub seed: String,
}

/// Derives the managed nonce account of `wallet` for `chain_id`, exactly as
/// the TypeScript CLI did, so accounts created by earlier releases are reused.
pub fn managed_nonce_account(
    wallet: &Pubkey,
    chain_id: u64,
) -> Result<ManagedNonceAccount, PaymentsError> {
    let seed = format!("agentpay-{chain_id}-nonce");
    let address = Pubkey::create_with_seed(wallet, &seed, &system_program_id()).map_err(|err| {
        PaymentsError::Internal(format!("managed nonce account derivation failed: {err}"))
    })?;
    Ok(ManagedNonceAccount { address, seed })
}

/// Reads the current nonce value of a durable nonce account and checks that
/// `expected_authority` may advance it.
pub fn parse_nonce_account(
    account: &Account,
    expected_authority: &Pubkey,
) -> Result<Hash, PaymentsError> {
    let invalid = |reason: &str| PaymentsError::InvalidRequest(format!("nonce account {reason}"));
    if account.owner != system_program_id() {
        return Err(invalid("is not owned by the system program"));
    }
    let versions: NonceVersions = bincode::deserialize(&account.data)
        .map_err(|_| invalid("does not hold durable nonce state"))?;
    let NonceVersions::Current(state) = versions else {
        return Err(invalid(
            "uses the legacy nonce format; advance it once before using it",
        ));
    };
    match *state {
        NonceState::Initialized(data) => {
            if data.authority != *expected_authority {
                return Err(invalid("authority is not the agent's wallet"));
            }
            Ok(data.blockhash())
        }
        NonceState::Uninitialized => Err(invalid("is not initialized")),
    }
}

/// What a constrained token transfer needs to know about a mint.
#[derive(Debug, Clone, PartialEq)]
pub struct MintInfo {
    /// The program that owns the mint.
    pub token_program: SolanaTokenProgram,
    /// Mint decimals.
    pub decimals: u8,
    /// The Token-2022 transfer fee configuration, if the mint has one.
    pub transfer_fee: Option<TransferFeeConfig>,
}

impl MintInfo {
    /// The fee withheld when `amount` is transferred in `epoch`; `None` for a
    /// mint without a transfer fee configuration.
    pub fn transfer_fee(&self, epoch: u64, amount: u64) -> Result<Option<u64>, PaymentsError> {
        self.transfer_fee
            .as_ref()
            .map(|config| {
                config.calculate_epoch_fee(epoch, amount).ok_or_else(|| {
                    PaymentsError::InvalidRequest("token transfer fee overflows".into())
                })
            })
            .transpose()
    }
}

/// Parses a mint owned by the SPL Token or Token-2022 program. Token-2022
/// mints with a transfer hook are refused: a hook adds accounts and a CPI the
/// constrained transfer does not allow.
pub fn parse_mint(account: &Account) -> Result<MintInfo, PaymentsError> {
    let token_program = if account.owner == spl_token::ID {
        SolanaTokenProgram::Token
    } else if account.owner == spl_token_2022_interface::id() {
        SolanaTokenProgram::Token2022
    } else {
        return Err(PaymentsError::InvalidRequest(
            "mint is not owned by the SPL Token or Token-2022 program".into(),
        ));
    };
    let mint = StateWithExtensions::<Mint>::unpack(&account.data).map_err(|_| {
        PaymentsError::InvalidRequest("mint account is not a valid token mint".into())
    })?;
    if !mint.base.is_initialized {
        return Err(PaymentsError::InvalidRequest(
            "mint is not initialized".into(),
        ));
    }
    let mut transfer_fee = None;
    if token_program == SolanaTokenProgram::Token2022 {
        if let Ok(hook) = mint.get_extension::<TransferHook>() {
            if Option::<Pubkey>::from(hook.program_id).is_some() {
                return Err(PaymentsError::InvalidRequest(
                    "Token-2022 mints with a transfer hook are not supported".into(),
                ));
            }
        }
        transfer_fee = mint.get_extension::<TransferFeeConfig>().ok().copied();
    }
    Ok(MintInfo {
        token_program,
        decimals: mint.base.decimals,
        transfer_fee,
    })
}
