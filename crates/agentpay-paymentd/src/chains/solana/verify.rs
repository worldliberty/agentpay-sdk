//! Verifying a transaction the signer daemon signed before it is returned or
//! broadcast (ported from the TypeScript `verifySignedSolanaTransaction`).
//!
//! The signer daemon builds the transaction from a typed action, so a
//! mismatch means a bug or a compromised signer path. [`verify`] decodes the
//! bytes and accepts only the exact shape that was requested:
//!
//! - a legacy message with exactly one required signature, by the fee payer,
//!   and a valid Ed25519 signature over the message; no trailing bytes;
//! - the expected blockhash (or durable nonce value);
//! - for transfers: an optional `AdvanceNonceAccount` that must be first and
//!   is required when a nonce account was requested, at most one
//!   `SetComputeUnitLimit` and one `SetComputeUnitPrice` matching the
//!   request, and exactly one transfer (`Transfer` from the fee payer, or
//!   `TransferChecked` / `TransferCheckedWithFee` from the fee payer's
//!   associated token account with no extra signers) with the expected
//!   recipient, mint, amount, decimals, and fee;
//! - for nonce account creation: exactly `CreateAccountWithSeed` and
//!   `InitializeNonceAccount` for the expected account, seed, and rent;
//! - no other program, and priority fees within the caps.

use base64::Engine as _;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::{Transaction, VersionedTransaction};
use solana_system_interface::instruction::SystemInstruction;
use spl_token_2022_interface::extension::transfer_fee::instruction::TransferFeeInstruction;
use spl_token_2022_interface::instruction::TokenInstruction;

use super::accounts::{system_program_id, NONCE_ACCOUNT_LEN};
use super::budget::ComputeBudget;
use crate::error::PaymentsError;

/// The compute budget program.
const COMPUTE_BUDGET_PROGRAM: Pubkey =
    Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");
/// `ComputeBudgetInstruction::SetComputeUnitLimit(u32)` tag.
const SET_COMPUTE_UNIT_LIMIT: u8 = 2;
/// `ComputeBudgetInstruction::SetComputeUnitPrice(u64)` tag.
const SET_COMPUTE_UNIT_PRICE: u8 = 3;

/// What the signer daemon was asked to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// Fee payer and only signer.
    pub fee_payer: Pubkey,
    /// Recent blockhash or durable nonce value.
    pub recent_blockhash: Hash,
    /// Nonce account the transaction must advance first.
    pub durable_nonce_account: Option<Pubkey>,
    /// Compute budget the transaction must set (transfers only).
    pub compute_budget: ComputeBudget,
    /// The one operation.
    pub operation: ExpectedOperation,
}

/// The single operation an [`Expected`] transaction performs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedOperation {
    /// `SystemInstruction::Transfer` from the fee payer.
    SolTransfer {
        /// Recipient.
        to: Pubkey,
        /// Lamports.
        lamports: u64,
    },
    /// `TransferChecked` or `TransferCheckedWithFee`.
    SplTransfer {
        /// Token program that owns the mint.
        program: Pubkey,
        /// Mint.
        mint: Pubkey,
        /// The fee payer's associated token account.
        source: Pubkey,
        /// The recipient's associated token account.
        destination: Pubkey,
        /// Base units.
        amount: u64,
        /// Mint decimals.
        decimals: u8,
        /// Expected transfer fee; `Some` exactly for `TransferCheckedWithFee`.
        fee: Option<u64>,
    },
    /// `CreateAccountWithSeed` + `InitializeNonceAccount`.
    NonceAccountCreate {
        /// The derived nonce account.
        nonce_account: Pubkey,
        /// Its seed.
        seed: String,
        /// Rent lamports moved into it.
        rent_lamports: u64,
    },
}

/// A verified signed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The transaction, ready to send.
    pub transaction: Transaction,
    /// Its compute budget.
    pub compute_budget: ComputeBudget,
}

/// Decodes `raw_tx_base64` and checks it against `expected`.
pub fn verify(raw_tx_base64: &str, expected: &Expected) -> Result<Verified, PaymentsError> {
    check(raw_tx_base64, expected).map_err(|reason| {
        PaymentsError::SignedTransactionMismatch(format!("signed Solana transaction {reason}"))
    })
}

fn check(raw_tx_base64: &str, expected: &Expected) -> Result<Verified, String> {
    let transaction = decode(raw_tx_base64)?;
    let message = &transaction.message;
    if message.header.num_required_signatures != 1 || transaction.signatures.len() != 1 {
        return Err("must have exactly one signer".into());
    }
    let fee_payer = message.account_keys.first().ok_or("has no fee payer")?;
    same("fee payer", *fee_payer, expected.fee_payer)?;
    transaction
        .verify()
        .map_err(|_| "signature does not verify against the fee payer".to_string())?;
    if message.recent_blockhash != expected.recent_blockhash {
        return Err("recent blockhash does not match the request".into());
    }

    let instructions = message
        .instructions
        .iter()
        .map(|ix| {
            Instruction::resolve(
                &message.account_keys,
                ix.program_id_index,
                &ix.accounts,
                &ix.data,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let compute_budget = match &expected.operation {
        ExpectedOperation::NonceAccountCreate { .. } => {
            check_nonce_create(&instructions, expected)?;
            ComputeBudget {
                unit_limit: None,
                unit_price: None,
            }
        }
        _ => check_transfer(&instructions, expected)?,
    };
    compute_budget.check_caps()?;
    Ok(Verified {
        transaction,
        compute_budget,
    })
}

/// Base64, then bincode, into a legacy transaction whose encoding is
/// canonical (re-serializing it gives back the same bytes).
fn decode(raw_tx_base64: &str) -> Result<Transaction, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_tx_base64.trim())
        .map_err(|_| "is not valid base64".to_string())?;
    let versioned: VersionedTransaction =
        bincode::deserialize(&bytes).map_err(|_| "could not be decoded".to_string())?;
    let canonical = bincode::serialize(&versioned).map_err(|_| "could not be re-encoded")?;
    if canonical != bytes {
        return Err("has a non-canonical encoding".into());
    }
    versioned
        .into_legacy_transaction()
        .ok_or_else(|| "must be a legacy transaction without address lookup tables".into())
}

/// A compiled instruction with its program and accounts resolved.
struct Instruction<'a> {
    program: Pubkey,
    accounts: Vec<Pubkey>,
    data: &'a [u8],
}

impl<'a> Instruction<'a> {
    fn resolve(
        keys: &[Pubkey],
        program_id_index: u8,
        accounts: &[u8],
        data: &'a [u8],
    ) -> Result<Self, String> {
        let key = |index: u8| {
            keys.get(usize::from(index))
                .copied()
                .ok_or_else(|| "references a missing account".to_string())
        };
        Ok(Self {
            program: key(program_id_index)?,
            accounts: accounts.iter().map(|i| key(*i)).collect::<Result<_, _>>()?,
            data,
        })
    }

    fn account(&self, index: usize) -> Result<Pubkey, String> {
        self.accounts
            .get(index)
            .copied()
            .ok_or_else(|| "has an instruction with too few accounts".to_string())
    }

    fn system(&self) -> Result<SystemInstruction, String> {
        bincode::deserialize(self.data)
            .map_err(|_| "contains an undecodable system instruction".to_string())
    }
}

fn same(label: &str, actual: Pubkey, expected: Pubkey) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label} does not match the request"))
    }
}

fn check_transfer(
    instructions: &[Instruction<'_>],
    expected: &Expected,
) -> Result<ComputeBudget, String> {
    let mut budget = ComputeBudget {
        unit_limit: None,
        unit_price: None,
    };
    let mut transfers = 0usize;
    let mut nonce_advances = 0usize;
    for (index, ix) in instructions.iter().enumerate() {
        if ix.program == COMPUTE_BUDGET_PROGRAM {
            read_compute_budget(ix, &mut budget)?;
        } else if ix.program == system_program_id() {
            match ix.system()? {
                SystemInstruction::AdvanceNonceAccount => {
                    let account = expected
                        .durable_nonce_account
                        .ok_or("advances a durable nonce but no nonce account was requested")?;
                    if index != 0 {
                        return Err("durable nonce advance must be the first instruction".into());
                    }
                    same("durable nonce account", ix.account(0)?, account)?;
                    same(
                        "durable nonce authority",
                        ix.account(2)?,
                        expected.fee_payer,
                    )?;
                    nonce_advances += 1;
                }
                SystemInstruction::Transfer { lamports } => {
                    let ExpectedOperation::SolTransfer { to, lamports: want } = &expected.operation
                    else {
                        return Err(
                            "contains a SOL transfer but a token transfer was expected".into()
                        );
                    };
                    same("SOL transfer source", ix.account(0)?, expected.fee_payer)?;
                    same("SOL transfer recipient", ix.account(1)?, *to)?;
                    if lamports != *want {
                        return Err(format!(
                            "SOL amount {lamports} lamports does not match expected {want}"
                        ));
                    }
                    transfers += 1;
                }
                other => {
                    return Err(format!(
                        "contains an unsupported system instruction: {other:?}"
                    ))
                }
            }
        } else if let ExpectedOperation::SplTransfer { program, .. } = &expected.operation {
            same("program", ix.program, *program)?;
            check_token_transfer(ix, &expected.operation, expected.fee_payer)?;
            transfers += 1;
        } else {
            return Err(format!("invokes an unexpected program: {}", ix.program));
        }
    }
    if transfers != 1 {
        return Err(format!(
            "must contain exactly one transfer instruction; found {transfers}"
        ));
    }
    if expected.durable_nonce_account.is_some() && nonce_advances != 1 {
        return Err("is missing the expected durable nonce advance".into());
    }
    if budget != expected.compute_budget {
        return Err(format!(
            "compute budget {budget:?} does not match expected {:?}",
            expected.compute_budget
        ));
    }
    Ok(budget)
}

fn read_compute_budget(ix: &Instruction<'_>, budget: &mut ComputeBudget) -> Result<(), String> {
    match ix.data.split_first() {
        Some((&SET_COMPUTE_UNIT_LIMIT, rest)) if budget.unit_limit.is_none() => {
            let bytes: [u8; 4] = rest
                .try_into()
                .map_err(|_| "has a malformed compute unit limit")?;
            budget.unit_limit = Some(u32::from_le_bytes(bytes));
        }
        Some((&SET_COMPUTE_UNIT_PRICE, rest)) if budget.unit_price.is_none() => {
            let bytes: [u8; 8] = rest
                .try_into()
                .map_err(|_| "has a malformed compute unit price")?;
            budget.unit_price = Some(u64::from_le_bytes(bytes));
        }
        Some((&SET_COMPUTE_UNIT_LIMIT | &SET_COMPUTE_UNIT_PRICE, _)) => {
            return Err("sets a compute budget value more than once".into());
        }
        _ => return Err("contains an unsupported compute budget instruction".into()),
    }
    Ok(())
}

fn check_token_transfer(
    ix: &Instruction<'_>,
    operation: &ExpectedOperation,
    fee_payer: Pubkey,
) -> Result<(), String> {
    let ExpectedOperation::SplTransfer {
        mint,
        source,
        destination,
        amount,
        decimals,
        fee,
        ..
    } = operation
    else {
        return Err("contains a token transfer but a SOL transfer was expected".into());
    };
    let (got_amount, got_decimals, got_fee) = match TokenInstruction::unpack(ix.data) {
        Ok(TokenInstruction::TransferChecked { amount, decimals }) => (amount, decimals, None),
        Ok(TokenInstruction::TransferFeeExtension) => {
            match ix.data.get(1..).map(TransferFeeInstruction::unpack) {
                Some(Ok(TransferFeeInstruction::TransferCheckedWithFee {
                    amount,
                    decimals,
                    fee,
                })) => (amount, decimals, Some(fee)),
                _ => return Err(unsupported_token_instruction()),
            }
        }
        _ => return Err(unsupported_token_instruction()),
    };
    if ix.accounts.len() != 4 {
        return Err("token transfer must not include extra signers".into());
    }
    same("source token account", ix.account(0)?, *source)?;
    same("mint", ix.account(1)?, *mint)?;
    same("destination token account", ix.account(2)?, *destination)?;
    same("token transfer authority", ix.account(3)?, fee_payer)?;
    if got_amount != *amount {
        return Err(format!(
            "token amount {got_amount} does not match expected {amount}"
        ));
    }
    if got_decimals != *decimals {
        return Err(format!(
            "token decimals {got_decimals} do not match expected {decimals}"
        ));
    }
    match (got_fee, fee) {
        (None, None) => Ok(()),
        (Some(_), None) => Err("includes a transfer fee but none was expected".into()),
        (got, Some(want)) if got == Some(*want) => Ok(()),
        (got, Some(want)) => Err(format!(
            "transfer fee {} does not match expected {want}",
            got.map_or_else(|| "none".to_string(), |fee| fee.to_string())
        )),
    }
}

fn unsupported_token_instruction() -> String {
    "contains an unsupported token instruction; only transfer_checked and \
     transfer_checked_with_fee are allowed"
        .into()
}

fn check_nonce_create(instructions: &[Instruction<'_>], expected: &Expected) -> Result<(), String> {
    let ExpectedOperation::NonceAccountCreate {
        nonce_account,
        seed,
        rent_lamports,
    } = &expected.operation
    else {
        return Err("is not a nonce account creation".into());
    };
    let [create, initialize] = instructions else {
        return Err("must contain exactly the two nonce account creation instructions".into());
    };
    for ix in [create, initialize] {
        same("program", ix.program, system_program_id())?;
    }
    match create.system()? {
        SystemInstruction::CreateAccountWithSeed {
            base,
            seed: got_seed,
            lamports,
            space,
            owner,
        } => {
            same("nonce account base", base, expected.fee_payer)?;
            same(
                "nonce account funder",
                create.account(0)?,
                expected.fee_payer,
            )?;
            same("nonce account", create.account(1)?, *nonce_account)?;
            same("nonce account owner", owner, system_program_id())?;
            if got_seed != *seed || lamports != *rent_lamports || space != NONCE_ACCOUNT_LEN as u64
            {
                return Err("nonce account seed, rent, or size does not match".into());
            }
        }
        _ => return Err("must create the nonce account with a seed".into()),
    }
    match initialize.system()? {
        SystemInstruction::InitializeNonceAccount(authority) => {
            same("nonce authority", authority, expected.fee_payer)?;
            same(
                "initialized nonce account",
                initialize.account(0)?,
                *nonce_account,
            )
        }
        _ => Err("must initialize the nonce account".into()),
    }
}
