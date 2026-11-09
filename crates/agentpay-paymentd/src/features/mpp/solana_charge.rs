//! Paying a `solana` `charge` challenge (MPP `draft-solana-charge-00`): one
//! transaction of native SOL or an SPL token (Token or Token-2022) to the
//! merchant, plus up to eight split payments, signed by the signer daemon as
//! the agent (`SolanaPaymentTransaction`, policy-checked like any transfer)
//! and handed to the merchant as a pull-mode `transaction` credential.
//!
//! When the merchant sponsors fees (`feePayer` with `feePayerKey`), its key
//! is the transaction's fee payer and its signature slot is left empty for
//! it to fill; otherwise the agent pays the fee. The merchant broadcasts
//! either way. The challenge's `externalId` and split memos are written as
//! Memo Program instructions.

use std::str::FromStr;

use agentpay_api::payments::ChainFamily;
use agentpay_domain::{
    AgentAction, SolanaAddress, SolanaPaymentAsset, SolanaPaymentLeg, SolanaPaymentTransaction,
    SolanaTokenProgram, SOLANA_DEVNET_CHAIN_ID, SOLANA_MAINNET_CHAIN_ID,
};
use base64::Engine;
use mpp::protocol::core::{PaymentChallenge, PaymentCredential};
use serde_json::{json, Value};
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::{v0, VersionedMessage};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::VersionedTransaction;

use super::charge::Charged;
use crate::chains::solana::accounts::{associated_token_account, token_program_id};
use crate::chains::solana::SolanaChain;
use crate::error::PaymentsError;
use crate::features::payer::Payer;

/// Token Program and Token-2022 Program ids.
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// Memo Program limit for `externalId` and split memos, in bytes.
const MAX_MEMO_BYTES: usize = 566;

/// Most splits a charge may carry.
const MAX_SPLITS: usize = 8;

/// Compute budget the reference client sets (and merchants cap at).
const COMPUTE_UNIT_LIMIT: u32 = 200_000;
const COMPUTE_UNIT_PRICE_MICRO_LAMPORTS: u64 = 1;

const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

/// What is paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SolanaAsset {
    /// Native SOL (`currency: "sol"`), in lamports.
    Sol,
    /// An SPL token.
    Token {
        mint: String,
        decimals: u8,
        /// `TOKEN_PROGRAM` or `TOKEN_2022_PROGRAM`; `None` when the merchant
        /// did not say (read from the mint account before paying).
        program: Option<String>,
    },
}

/// One payment leg: the primary payment or a split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SolanaLeg {
    /// The recipient wallet (for tokens, the owner of the destination ATA).
    pub(super) recipient: String,
    /// Base units (lamports for SOL).
    pub(super) amount: u128,
    /// Create the recipient's ATA (idempotently) first; splits only.
    pub(super) create_ata: bool,
    pub(super) memo: Option<String>,
}

/// A payable `solana` charge, normalized.
#[derive(Debug, Clone)]
pub(super) struct SolanaCharge {
    /// AgentPay's id for the cluster (mainnet or devnet).
    pub(super) chain_id: u64,
    pub(super) asset: SolanaAsset,
    /// The primary leg first (`amount` minus the splits), then the splits.
    pub(super) legs: Vec<SolanaLeg>,
    /// The challenge `amount`: the total the agent pays.
    pub(super) total: u128,
    /// The merchant's fee payer key when it sponsors fees.
    pub(super) fee_payer: Option<String>,
    pub(super) recent_blockhash: Option<String>,
    /// The challenge `externalId`, written as a memo.
    pub(super) external_id: Option<String>,
}

impl SolanaCharge {
    /// `"sol"` or the mint.
    pub(super) fn currency(&self) -> String {
        match &self.asset {
            SolanaAsset::Sol => "sol".into(),
            SolanaAsset::Token { mint, .. } => mint.clone(),
        }
    }

    /// The primary recipient.
    pub(super) fn recipient(&self) -> String {
        self.legs
            .first()
            .map(|leg| leg.recipient.clone())
            .unwrap_or_default()
    }
}

fn pubkey(value: Option<&Value>, field: &str) -> Result<String, String> {
    let text = value
        .and_then(Value::as_str)
        .map(str::trim)
        .ok_or_else(|| format!("the charge names no {field}"))?;
    Pubkey::from_str(text)
        .map(|key| key.to_string())
        .map_err(|_| format!("{field} is not a Solana public key"))
}

/// A positive integer amount that fits a `u64` (Solana amounts are u64).
fn amount(value: Option<&Value>, field: &str) -> Result<u128, String> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("the charge names no {field}"))?;
    let valid =
        !text.is_empty() && !text.starts_with('0') && text.bytes().all(|b| b.is_ascii_digit());
    let amount = if valid {
        text.parse::<u64>().ok()
    } else {
        None
    };
    amount
        .map(u128::from)
        .ok_or_else(|| format!("{field} is not a positive integer amount that fits 64 bits"))
}

fn memo(value: Option<&Value>, field: &str) -> Result<Option<String>, String> {
    match value.and_then(Value::as_str) {
        None => Ok(None),
        Some(text) if text.len() > MAX_MEMO_BYTES => {
            Err(format!("{field} is longer than {MAX_MEMO_BYTES} bytes"))
        }
        Some(text) => Ok(Some(text.to_string())),
    }
}

/// Normalizes a `solana` charge challenge, or says why it cannot be paid.
/// Nothing is signed here.
pub(super) fn parse(challenge: &PaymentChallenge) -> Result<SolanaCharge, String> {
    let request: Value = challenge
        .request
        .decode()
        .map_err(|_| "the charge request is malformed".to_string())?;
    let details = request.get("methodDetails").cloned().unwrap_or(Value::Null);
    let chain_id = match details.get("network").and_then(Value::as_str) {
        None | Some("mainnet" | "mainnet-beta") => SOLANA_MAINNET_CHAIN_ID,
        Some("devnet") => SOLANA_DEVNET_CHAIN_ID,
        Some(other) => return Err(format!("Solana network '{other}' is not supported")),
    };
    if details.get("confidential").and_then(Value::as_bool) == Some(true) {
        return Err("confidential Solana charges are not supported".into());
    }
    let currency = request
        .get("currency")
        .and_then(Value::as_str)
        .map(str::trim)
        .ok_or("the charge names no currency")?;
    let decimals = details.get("decimals").and_then(Value::as_u64);
    let program = details.get("tokenProgram").and_then(Value::as_str);
    let asset = if currency == "sol" {
        if decimals.is_some() || program.is_some() {
            return Err("a SOL charge must not name decimals or a token program".into());
        }
        SolanaAsset::Sol
    } else {
        let mint = pubkey(request.get("currency"), "currency (mint)")?;
        let decimals = decimals
            .filter(|decimals| *decimals <= 9)
            .ok_or("a token charge must name its decimals (0 to 9)")?;
        let program = match program {
            None => None,
            Some(program @ (TOKEN_PROGRAM | TOKEN_2022_PROGRAM)) => Some(program.to_string()),
            Some(other) => return Err(format!("token program {other} is not supported")),
        };
        SolanaAsset::Token {
            mint,
            decimals: u8::try_from(decimals).unwrap_or(9),
            program,
        }
    };
    let total = amount(request.get("amount"), "amount")?;
    let mut splits = Vec::new();
    let raw_splits = details
        .get("splits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if raw_splits.len() > MAX_SPLITS {
        return Err(format!("more than {MAX_SPLITS} splits"));
    }
    for split in &raw_splits {
        let create_ata = split.get("ataCreationRequired").and_then(Value::as_bool) == Some(true);
        if create_ata && asset == SolanaAsset::Sol {
            return Err("ataCreationRequired is only valid for token charges".into());
        }
        splits.push(SolanaLeg {
            recipient: pubkey(split.get("recipient"), "split recipient")?,
            amount: amount(split.get("amount"), "split amount")?,
            create_ata,
            memo: memo(split.get("memo"), "split memo")?,
        });
    }
    let split_total = splits
        .iter()
        .try_fold(0u128, |sum, leg| sum.checked_add(leg.amount))
        .ok_or("the splits overflow")?;
    let primary = total
        .checked_sub(split_total)
        .filter(|primary| *primary > 0)
        .ok_or("the splits leave nothing for the primary recipient")?;
    let fee_payer = match details.get("feePayer").and_then(Value::as_bool) {
        Some(true) => Some(pubkey(
            details.get("feePayerKey"),
            "methodDetails.feePayerKey",
        )?),
        _ => None,
    };
    let recent_blockhash = match details.get("recentBlockhash").and_then(Value::as_str) {
        None => None,
        Some(hash) => Some(
            solana_sdk::hash::Hash::from_str(hash.trim())
                .map(|hash| hash.to_string())
                .map_err(|_| "methodDetails.recentBlockhash is not a blockhash")?,
        ),
    };
    let mut legs = vec![SolanaLeg {
        recipient: pubkey(request.get("recipient"), "recipient")?,
        amount: primary,
        create_ata: false,
        memo: None,
    }];
    legs.extend(splits);
    Ok(SolanaCharge {
        chain_id,
        asset,
        legs,
        total,
        fee_payer,
        recent_blockhash,
        external_id: memo(request.get("externalId"), "externalId")?,
    })
}

/// Whether the wallet can pay `charge`: it holds the amount, and SOL for
/// the fees when the merchant does not pay them. Reads only.
pub(super) async fn affordable(
    payer: &Payer,
    charge: &SolanaCharge,
) -> Result<bool, PaymentsError> {
    let (Some(agent), Some(provider)) = (payer.solana_wallet, payer.solana.clone()) else {
        return Ok(false);
    };
    let rpc = provider.rpc(&network(payer, charge.chain_id)?).await?;
    let lamports = rpc
        .account(&agent)
        .await?
        .map_or(0, |account| u128::from(account.lamports));
    if charge.fee_payer.is_none() && lamports == 0 {
        return Ok(false);
    }
    let held = match &charge.asset {
        SolanaAsset::Sol => lamports,
        SolanaAsset::Token { mint, .. } => {
            let mint = key(mint)?;
            let candidates = [
                token_program_id(SolanaTokenProgram::Token),
                token_program_id(SolanaTokenProgram::Token2022),
            ]
            .map(|program| associated_token_account(&agent, &mint, &program));
            rpc.accounts(&candidates)
                .await?
                .into_iter()
                .flatten()
                .filter_map(|account| {
                    // An SPL token account's amount: a little-endian u64 at 64.
                    let bytes: [u8; 8] = account.data.get(64..72)?.try_into().ok()?;
                    Some(u128::from(u64::from_le_bytes(bytes)))
                })
                .sum()
        }
    };
    Ok(held >= charge.total)
}

/// The configured Solana network for `chain_id`, with an RPC URL.
fn network(payer: &Payer, chain_id: u64) -> Result<SolanaChain, PaymentsError> {
    payer
        .config
        .chains
        .iter()
        .find(|(_, chain)| {
            chain.family == ChainFamily::Solana
                && chain.chain_id == chain_id
                && chain.rpc_url.is_some()
        })
        .map(|(key, chain)| SolanaChain {
            key: key.clone(),
            chain_id,
            rpc_url: chain.rpc_url.clone().unwrap_or_default(),
            fallback_rpc_urls: chain.fallback_rpc_urls.clone(),
        })
        .ok_or_else(|| {
            PaymentsError::InvalidRequest(format!(
                "no configured Solana network with an rpc_url has chain id {chain_id}; nothing \
                 was signed"
            ))
        })
}

fn key(text: &str) -> Result<Pubkey, PaymentsError> {
    Pubkey::from_str(text)
        .map_err(|_| PaymentsError::Internal(format!("{text} is not a Solana public key")))
}

fn address(key: &Pubkey) -> Result<SolanaAddress, PaymentsError> {
    key.to_string()
        .parse()
        .map_err(|_| PaymentsError::Internal("a Solana key is not representable".into()))
}

fn program_id(program: SolanaTokenProgram) -> Result<Pubkey, PaymentsError> {
    key(match program {
        SolanaTokenProgram::Token => TOKEN_PROGRAM,
        SolanaTokenProgram::Token2022 => TOKEN_2022_PROGRAM,
    })
}

/// The instructions the signer daemon is expected to sign, built here on
/// their own so its transaction is checked byte for byte before release.
fn expected_instructions(
    payment: &SolanaPaymentTransaction,
    agent: &Pubkey,
    fee_payer: &Pubkey,
) -> Result<Vec<Instruction>, PaymentsError> {
    let compute = |data: Vec<u8>| -> Result<Instruction, PaymentsError> {
        Ok(Instruction {
            program_id: key(COMPUTE_BUDGET_PROGRAM)?,
            accounts: Vec::new(),
            data,
        })
    };
    let memo = |text: &str| -> Result<Instruction, PaymentsError> {
        Ok(Instruction {
            program_id: key(MEMO_PROGRAM)?,
            accounts: Vec::new(),
            data: text.as_bytes().to_vec(),
        })
    };
    let mut instructions = Vec::new();
    if let Some(price) = payment.compute_unit_price_micro_lamports {
        instructions.push(compute([&[3u8][..], &price.to_le_bytes()].concat())?);
    }
    if let Some(limit) = payment.compute_unit_limit {
        instructions.push(compute([&[2u8][..], &limit.to_le_bytes()].concat())?);
    }
    for (index, leg) in payment.transfers.iter().enumerate() {
        let owner = key(&leg.recipient_owner.to_string())?;
        let amount = u64::try_from(leg.amount_wei)
            .map_err(|_| PaymentsError::Internal("a Solana amount exceeds 64 bits".into()))?;
        match &payment.asset {
            SolanaPaymentAsset::NativeSol => {
                instructions.push(solana_system_interface::instruction::transfer(
                    agent, &owner, amount,
                ));
            }
            SolanaPaymentAsset::SplToken {
                mint,
                decimals,
                token_program,
            } => {
                let mint = key(&mint.to_string())?;
                let program = program_id(*token_program)?;
                let ata = |wallet: &Pubkey| {
                    spl_associated_token_account::get_associated_token_address_with_program_id(
                        wallet, &mint, &program,
                    )
                };
                if leg.create_ata {
                    let ata_program = spl_associated_token_account::ID;
                    instructions.push(Instruction {
                        program_id: ata_program,
                        accounts: vec![
                            AccountMeta::new(*fee_payer, true),
                            AccountMeta::new(ata(&owner), false),
                            AccountMeta::new_readonly(owner, false),
                            AccountMeta::new_readonly(mint, false),
                            AccountMeta::new_readonly(
                                key("11111111111111111111111111111111")?,
                                false,
                            ),
                            AccountMeta::new_readonly(program, false),
                        ],
                        data: vec![1],
                    });
                }
                instructions.push(
                    spl_token_2022_interface::instruction::transfer_checked(
                        &program,
                        &ata(agent),
                        &mint,
                        &ata(&owner),
                        agent,
                        &[],
                        amount,
                        *decimals,
                    )
                    .map_err(|_| PaymentsError::Internal("transfer_checked failed".into()))?,
                );
            }
        }
        let text = if index == 0 {
            payment.memo.as_deref()
        } else {
            leg.memo.as_deref()
        };
        if let Some(text) = text {
            instructions.push(memo(text)?);
        }
    }
    Ok(instructions)
}

/// Checks the signer daemon's transaction: exactly the expected v0 message,
/// no lookup tables, the agent's signature valid over it, and the fee payer's
/// slot left empty when the merchant pays fees.
fn verify(
    raw_base64: &str,
    payment: &SolanaPaymentTransaction,
    agent: &Pubkey,
    fee_payer: &Pubkey,
) -> Result<VersionedTransaction, PaymentsError> {
    let mismatch = |why: &str| PaymentsError::SignedTransactionMismatch(why.to_string());
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_base64)
        .map_err(|_| mismatch("the signed Solana transaction is not base64"))?;
    let transaction: VersionedTransaction = bincode::deserialize(&bytes)
        .map_err(|_| mismatch("the signed transaction is malformed"))?;
    let blockhash = Hash::from_str(&payment.recent_blockhash)
        .map_err(|_| mismatch("the blockhash is malformed"))?;
    let instructions = expected_instructions(payment, agent, fee_payer)?;
    let expected = v0::Message::try_compile(fee_payer, &instructions, &[], blockhash)
        .map_err(|_| mismatch("the expected message does not compile"))?;
    let expected = VersionedMessage::V0(expected).serialize();
    let message = transaction.message.serialize();
    if message != expected {
        return Err(mismatch(
            "the signer daemon's Solana transaction differs from the requested payment",
        ));
    }
    let keys = transaction.message.static_account_keys();
    let signed_by = |who: &Pubkey| {
        keys.iter()
            .position(|k| k == who)
            .and_then(|index| transaction.signatures.get(index))
            .is_some_and(|signature| signature.verify(who.as_ref(), &message))
    };
    if !signed_by(agent) {
        return Err(mismatch("the agent's signature does not verify"));
    }
    if fee_payer != agent
        && transaction
            .signatures
            .first()
            .is_none_or(|slot| *slot != solana_sdk::signature::Signature::default())
    {
        return Err(mismatch("the merchant's fee payer slot is not empty"));
    }
    Ok(transaction)
}

/// Pays `charge` (from `challenge`) and returns the pull-mode credential.
pub(super) async fn pay(
    payer: &Payer,
    challenge: &PaymentChallenge,
    charge: &SolanaCharge,
) -> Result<Charged, PaymentsError> {
    let agent = payer.solana_wallet.ok_or_else(|| {
        PaymentsError::InvalidRequest("the agent's key cannot sign for Solana".into())
    })?;
    let provider = payer
        .solana
        .clone()
        .ok_or_else(|| PaymentsError::Internal("Solana is not available".into()))?;
    let chain = network(payer, charge.chain_id)?;
    let rpc = provider.rpc(&chain).await?;
    let asset = match &charge.asset {
        SolanaAsset::Sol => SolanaPaymentAsset::NativeSol,
        SolanaAsset::Token {
            mint,
            decimals,
            program,
        } => {
            let program = match program.as_deref() {
                Some(TOKEN_2022_PROGRAM) => SolanaTokenProgram::Token2022,
                Some(_) => SolanaTokenProgram::Token,
                // Not named: the mint account's owner decides, and an
                // unknown owner refuses the charge (never a fallback).
                None => {
                    let account = rpc.account(&key(mint)?).await?.ok_or_else(|| {
                        PaymentsError::InvalidRequest(format!(
                            "the mint {mint} does not exist on {}; nothing was signed",
                            chain.key
                        ))
                    })?;
                    match account.owner.to_string().as_str() {
                        TOKEN_PROGRAM => SolanaTokenProgram::Token,
                        TOKEN_2022_PROGRAM => SolanaTokenProgram::Token2022,
                        _ => {
                            return Err(PaymentsError::InvalidRequest(format!(
                                "{mint} is not a token mint; nothing was signed"
                            )))
                        }
                    }
                }
            };
            SolanaPaymentAsset::SplToken {
                mint: mint
                    .parse()
                    .map_err(|_| PaymentsError::Internal("the mint is malformed".into()))?,
                decimals: *decimals,
                token_program: program,
            }
        }
    };
    let fee_payer = match &charge.fee_payer {
        Some(merchant) => key(merchant)?,
        None => agent,
    };
    let recent_blockhash = match &charge.recent_blockhash {
        Some(hash) => hash.clone(),
        None => rpc.latest_blockhash().await?.to_string(),
    };
    let transfers = charge
        .legs
        .iter()
        .map(|leg| {
            Ok(SolanaPaymentLeg {
                recipient_owner: address(&key(&leg.recipient)?)?,
                amount_wei: leg.amount,
                create_ata: leg.create_ata,
                memo: leg.memo.clone(),
            })
        })
        .collect::<Result<Vec<_>, PaymentsError>>()?;
    let payment = SolanaPaymentTransaction {
        chain_id: charge.chain_id,
        recent_blockhash,
        fee_payer: address(&fee_payer)?,
        asset,
        transfers,
        memo: charge.external_id.clone(),
        compute_unit_limit: Some(COMPUTE_UNIT_LIMIT),
        compute_unit_price_micro_lamports: Some(COMPUTE_UNIT_PRICE_MICRO_LAMPORTS),
    };
    let answer = payer
        .signer()
        .sign(
            AgentAction::SolanaPaymentTransaction {
                payment: payment.clone(),
            },
            payer.wait,
        )
        .await?;
    let raw = answer.raw_tx_base64.as_deref().ok_or_else(|| {
        PaymentsError::SignerUnavailable("the signer daemon returned no signed transaction".into())
    })?;
    let transaction = verify(raw, &payment, &agent, &fee_payer)?;
    let payload = json!({ "type": "transaction", "transaction": raw });
    let credential =
        PaymentCredential::with_source(challenge.to_echo(), agent.to_string(), payload);
    // With the agent paying fees its signature is the transaction id; a
    // sponsored transaction's id is the merchant's, known once it signs.
    let tx_hash = (fee_payer == agent)
        .then(|| transaction.signatures.first().map(ToString::to_string))
        .flatten();
    Ok(Charged {
        network: chain.key,
        credential_type: "transaction",
        tx_hash,
        memo_hex: None,
        credential,
        unsent: None,
    })
}

#[cfg(test)]
mod tests {
    use mpp::protocol::core::Base64UrlJson;
    use serde_json::json;

    use super::*;

    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const MERCHANT: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    const PLATFORM: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

    fn challenge(request: Value) -> PaymentChallenge {
        PaymentChallenge::new(
            "id",
            "api.example.com",
            "solana",
            "charge",
            Base64UrlJson::from_value(&request).expect("request"),
        )
    }

    #[test]
    fn token_charges_with_splits_and_fee_sponsorship_are_normalized() {
        let charge = parse(&challenge(json!({
            "amount": "1050000", "currency": MINT, "recipient": MERCHANT,
            "externalId": "order-42",
            "methodDetails": {
                "network": "devnet", "decimals": 6, "tokenProgram": TOKEN_PROGRAM,
                "feePayer": true, "feePayerKey": PLATFORM,
                "splits": [{"recipient": PLATFORM, "amount": "50000", "memo": "platform fee",
                            "ataCreationRequired": true}]
            }
        })))
        .expect("charge");
        assert_eq!(charge.chain_id, SOLANA_DEVNET_CHAIN_ID);
        assert_eq!(charge.total, 1_050_000);
        assert_eq!(
            charge.legs.iter().map(|leg| leg.amount).collect::<Vec<_>>(),
            [1_000_000, 50_000],
            "the primary gets the remainder"
        );
        assert!(charge.legs[1].create_ata && !charge.legs[0].create_ata);
        assert_eq!(charge.fee_payer.as_deref(), Some(PLATFORM));
        assert_eq!(charge.external_id.as_deref(), Some("order-42"));
        assert_eq!(charge.currency(), MINT);
    }

    #[test]
    fn invalid_charges_are_refused() {
        let base = json!({"amount": "1000", "currency": "sol", "recipient": MERCHANT});
        assert_eq!(
            parse(&challenge(base.clone())).expect("sol").asset,
            SolanaAsset::Sol
        );
        let with = |patch: Value| {
            let mut request = base.clone();
            for (key, value) in patch.as_object().expect("object") {
                request[key] = value.clone();
            }
            parse(&challenge(request))
        };
        for bad in [
            json!({"methodDetails": {"network": "localnet"}}),
            json!({"methodDetails": {"decimals": 9}}),
            json!({"currency": MINT}),
            json!({"currency": MINT, "methodDetails": {"decimals": 6, "tokenProgram": "x"}}),
            json!({"amount": "0"}),
            json!({"amount": "18446744073709551616"}),
            json!({"recipient": "not-a-key"}),
            json!({"methodDetails": {"feePayer": true}}),
            json!({"methodDetails": {"splits": [{"recipient": PLATFORM, "amount": "1000"}]}}),
            json!({"methodDetails": {"splits": [{"recipient": PLATFORM, "amount": "1",
                                                 "ataCreationRequired": true}]}}),
            json!({"externalId": "x".repeat(567)}),
            json!({"methodDetails": {"confidential": true}}),
        ] {
            assert!(with(bad.clone()).is_err(), "{bad}");
        }
    }
}
