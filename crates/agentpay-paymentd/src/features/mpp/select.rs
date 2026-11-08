//! Normalizing and choosing MPP challenges.
//!
//! Payable: `tempo` `charge` and `session`, `evm` / `arbitrum` `charge`
//! ([`super::evm_charge`]), and `solana` `charge` ([`super::solana_charge`]). Selection follows the lessons of the TypeScript
//! client's review:
//!
//! 1. a caller `currency` and `network` filter first, and a challenge on a
//!    chain AgentPay has not configured is never paid;
//! 2. a persisted channel (read **before** selection) keeps only session
//!    challenges for that exact channel;
//! 3. sessions v1 (legacy escrow) are never paid;
//! 4. ranking: the preferred intent (session with a `session_key`, else
//!    charge), the chain the URL hints at (testnet names), a token the agent
//!    has limits for, a payment that needs no native coin for gas, mainnet
//!    over testnet, and only then an explicit `sessionProtocol: "v2"` marker
//!    as a tie-break between session challenges.

use std::str::FromStr;

use agentpay_domain::{is_tempo_chain_id, EvmAddress, TEMPO_CHANNEL_RESERVE_CONTRACT};
use agentpay_domain::{TEMPO_MAINNET_CHAIN_ID, TEMPO_TESTNET_CHAIN_ID};
use alloy_primitives::B256;
use mpp::protocol::core::PaymentChallenge;
use mpp::protocol::intents::{ChargeRequest, SessionRequest};
use serde_json::Value;
use tempo_alloy::primitives::is_tip20_prefix;

use super::evm_charge::{self, EvmCharge};
use super::solana_charge::{self, SolanaCharge};
use super::store::SessionRecord;
use crate::chains::evm::to_alloy_address;

/// Chain ids of test networks (testnet hints and ranking).
const TESTNET_CHAIN_IDS: [u64; 7] = [
    TEMPO_TESTNET_CHAIN_ID,
    11_155_111,
    84_532,
    421_614,
    97,
    900_000_002,
    900_000_003,
];

/// A payable challenge of any supported method, normalized.
#[derive(Debug, Clone)]
pub(super) enum Payable {
    /// `tempo` charge or session.
    Tempo(Offer),
    /// `evm` / `arbitrum` charge.
    Evm(EvmCharge),
    /// `solana` charge.
    Solana(SolanaCharge),
}

impl Payable {
    pub(super) fn intent(&self) -> Intent {
        match self {
            Self::Tempo(offer) => offer.intent,
            Self::Evm(_) | Self::Solana(_) => Intent::Charge,
        }
    }

    pub(super) fn chain_id(&self) -> u64 {
        match self {
            Self::Tempo(offer) => offer.chain_id,
            Self::Evm(charge) => charge.chain_id,
            Self::Solana(charge) => charge.chain_id,
        }
    }

    /// The token: an EVM address in lower case, or a Solana mint (or `sol`)
    /// as the challenge spells it (mints are case-sensitive).
    pub(super) fn currency(&self) -> String {
        match self {
            Self::Tempo(offer) => offer.currency.to_string().to_ascii_lowercase(),
            Self::Evm(charge) => charge.currency.to_string().to_ascii_lowercase(),
            Self::Solana(charge) => charge.currency(),
        }
    }

    /// [`Self::currency`] in lower case, for comparing with filters and
    /// configured tokens.
    fn currency_key(&self) -> String {
        self.currency().to_ascii_lowercase()
    }

    pub(super) fn recipient(&self) -> String {
        match self {
            Self::Tempo(offer) => offer.recipient.to_string(),
            Self::Evm(charge) => charge.recipient.to_string(),
            Self::Solana(charge) => charge.recipient(),
        }
    }

    /// Base units.
    pub(super) fn amount(&self) -> u128 {
        match self {
            Self::Tempo(offer) => offer.amount,
            Self::Evm(charge) => charge.amount,
            Self::Solana(charge) => charge.total,
        }
    }

    /// The Tempo offer, for session handling.
    pub(super) fn tempo(&self) -> Option<&Offer> {
        match self {
            Self::Tempo(offer) => Some(offer),
            Self::Evm(_) | Self::Solana(_) => None,
        }
    }
}

/// Normalizes `challenge` for its method, or says why it cannot be paid.
pub(super) fn payable(challenge: &PaymentChallenge) -> Result<Payable, String> {
    match (challenge.method.as_str(), challenge.intent.as_str()) {
        ("tempo", _) => offer(challenge).map(Payable::Tempo),
        ("evm" | "arbitrum", "charge") => evm_charge::parse(challenge).map(Payable::Evm),
        ("solana", "charge") => solana_charge::parse(challenge).map(Payable::Solana),
        (method @ ("evm" | "arbitrum" | "solana"), intent) => Err(format!(
            "{method} {intent} is not supported; only {method} charge is"
        )),
        (method, _) => Err(format!("method '{method}' is not supported")),
    }
}

/// Payment intent of a payable challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Intent {
    Charge,
    Session,
}

/// A payable `tempo` challenge, normalized.
#[derive(Debug, Clone)]
pub(super) struct Offer {
    pub(super) intent: Intent,
    pub(super) chain_id: u64,
    pub(super) currency: EvmAddress,
    pub(super) recipient: EvmAddress,
    /// Base units.
    pub(super) amount: u128,
    /// Session: `suggestedDeposit` (base units).
    pub(super) suggested_deposit: Option<u128>,
    /// Session: the merchant sponsors the open and top-up fees.
    pub(super) fee_payer: bool,
    /// Session: operator (zero address when absent).
    pub(super) operator: EvmAddress,
    /// Session: the channel the merchant expects, if it names one.
    pub(super) channel_id: Option<B256>,
    /// Session: the challenge explicitly says `sessionProtocol: "v2"`.
    pub(super) explicit_v2: bool,
    /// Charge: the challenge's own 32-byte memo.
    pub(super) memo: Option<[u8; 32]>,
}

/// Normalizes a `tempo` `challenge`, or says why it cannot be paid.
pub(super) fn offer(challenge: &PaymentChallenge) -> Result<Offer, String> {
    if challenge.method.as_str() != "tempo" {
        return Err(format!("method '{}' is not supported", challenge.method));
    }
    match challenge.intent.as_str() {
        "charge" => charge_offer(challenge),
        "session" => session_offer(challenge),
        other => Err(format!("intent '{other}' is not supported")),
    }
}

fn details(value: Option<&Value>) -> Value {
    value.cloned().unwrap_or(Value::Null)
}

fn address(value: &str, field: &str) -> Result<EvmAddress, String> {
    EvmAddress::from_str(value.trim()).map_err(|_| format!("{field} is not an EVM address"))
}

fn amount(value: &str, field: &str) -> Result<u128, String> {
    value
        .trim()
        .parse::<u128>()
        .map_err(|_| format!("{field} is not an integer amount in base units"))
}

fn chain_id(details: &Value) -> Result<u64, String> {
    // Never assume a default network: a stripped chainId would otherwise
    // redirect a payment to a chain the merchant did not name.
    let chain_id = details
        .get("chainId")
        .and_then(Value::as_u64)
        .ok_or("the challenge names no methodDetails.chainId")?;
    if !is_tempo_chain_id(chain_id) {
        return Err(format!("chain {chain_id} is not a Tempo chain"));
    }
    Ok(chain_id)
}

fn charge_offer(challenge: &PaymentChallenge) -> Result<Offer, String> {
    let request: ChargeRequest = challenge
        .request
        .decode()
        .map_err(|_| "the charge request is malformed".to_string())?;
    let details = details(request.method_details.as_ref());
    let amount = amount(&request.amount, "amount")?;
    if amount == 0 {
        return Err("zero-amount (proof) charges are not supported".into());
    }
    if details
        .get("splits")
        .and_then(Value::as_array)
        .is_some_and(|splits| !splits.is_empty())
    {
        return Err("split charges are not supported".into());
    }
    if let Some(modes) = details.get("supportedModes").and_then(Value::as_array) {
        if !modes.iter().any(|mode| mode.as_str() == Some("push")) {
            return Err("the charge does not accept a pushed (hash) payment".into());
        }
    }
    let memo = match details.get("memo").and_then(Value::as_str).map(str::trim) {
        None | Some("") => None,
        Some(memo) => Some(
            memo.strip_prefix("0x")
                .and_then(|digits| alloy_primitives::hex::decode(digits).ok())
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or("methodDetails.memo is not 32 bytes of hex")?,
        ),
    };
    let recipient = request
        .recipient
        .as_deref()
        .ok_or("the charge names no recipient")?;
    let currency = address(&request.currency, "currency")?;
    // The payment is a TIP-20 `transferWithMemo`; any other token on Tempo
    // (USD1 there is a plain ERC-20) would revert after the fee is spent.
    if !to_alloy_address(&currency).is_ok_and(is_tip20_prefix) {
        return Err(format!(
            "currency {currency} is not a TIP-20 token, which a tempo charge pays in"
        ));
    }
    Ok(Offer {
        intent: Intent::Charge,
        chain_id: chain_id(&details)?,
        currency,
        recipient: address(recipient, "recipient")?,
        amount,
        suggested_deposit: None,
        fee_payer: false,
        operator: zero_address()?,
        channel_id: None,
        explicit_v2: false,
        memo,
    })
}

fn session_offer(challenge: &PaymentChallenge) -> Result<Offer, String> {
    let request: SessionRequest = challenge
        .request
        .decode()
        .map_err(|_| "the session request is malformed".to_string())?;
    let details = details(request.method_details.as_ref());
    let protocol = details.get("sessionProtocol").and_then(Value::as_str);
    let escrow = details
        .get("escrowContract")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|escrow| !escrow.is_empty());
    let is_reserve = |escrow: &str| escrow.eq_ignore_ascii_case(TEMPO_CHANNEL_RESERVE_CONTRACT);
    match (protocol, escrow) {
        (Some("v1"), _) => return Err(legacy_session()),
        (Some(other), _) if other != "v2" => {
            return Err(format!("session protocol '{other}' is not supported"))
        }
        (_, Some(escrow)) if !is_reserve(escrow) => return Err(legacy_session()),
        _ => {}
    }
    let amount = amount(&request.amount, "amount")?;
    if amount == 0 {
        return Err("the session amount is zero".into());
    }
    let recipient = request
        .recipient
        .as_deref()
        .ok_or("the session names no recipient")?;
    let operator = match details.get("operator").and_then(Value::as_str) {
        Some(operator) => address(operator, "methodDetails.operator")?,
        None => zero_address()?,
    };
    let channel_id = match details
        .get("channelId")
        .and_then(Value::as_str)
        .map(str::trim)
    {
        None | Some("") => None,
        Some(id) => Some(B256::from_str(id).map_err(|_| "methodDetails.channelId is malformed")?),
    };
    let suggested_deposit = request
        .suggested_deposit
        .as_deref()
        .map(|deposit| amount_of(deposit, "suggestedDeposit"))
        .transpose()?;
    Ok(Offer {
        intent: Intent::Session,
        chain_id: chain_id(&details)?,
        currency: address(&request.currency, "currency")?,
        recipient: address(recipient, "recipient")?,
        amount,
        suggested_deposit,
        fee_payer: details.get("feePayer").and_then(Value::as_bool) == Some(true),
        operator,
        channel_id,
        explicit_v2: protocol == Some("v2"),
        memo: None,
    })
}

fn amount_of(value: &str, field: &str) -> Result<u128, String> {
    amount(value, field)
}

/// The reason a legacy (sessions v1) challenge is refused.
pub(super) fn legacy_session() -> String {
    "the merchant offers a Tempo sessions v1 (legacy escrow) channel, which is no longer \
     supported; only TIP-1034 (sessions v2) channels can be paid"
        .into()
}

/// The zero address (an unused channel operator).
pub(super) fn zero_address() -> Result<EvmAddress, String> {
    crate::chains::evm::evm_address(alloy_primitives::Address::ZERO)
        .map_err(|_| "the zero address is not representable".to_string())
}

/// What selection must respect.
pub(super) struct Preferences<'a> {
    /// Rank session challenges first.
    pub(super) prefer_session: bool,
    /// Only this token (lower case for EVM addresses).
    pub(super) currency: Option<&'a str>,
    /// Only this chain (the caller's `network`, resolved).
    pub(super) chain_id: Option<u64>,
    /// Chains AgentPay can pay on (configured, with an RPC).
    pub(super) configured_chains: &'a [u64],
    /// The persisted channel, if any.
    pub(super) persisted: Option<&'a SessionRecord>,
    /// The request URL (lower case), for testnet hints.
    pub(super) url: &'a str,
    /// Only this exact amount (base units).
    pub(super) amount: Option<u128>,
    /// Nothing above this amount (base units).
    pub(super) max_amount: Option<u128>,
    /// Tokens configured in AgentPay, as `(chain id, token)` (lower case): without a
    /// `currency`, a challenge in one of them ranks before one in a token the agent has no
    /// limits or balance for.
    pub(super) known_tokens: &'a [(u64, String)],
    /// Challenges (by id) the wallet cannot pay ([`super::funds`]): ranked
    /// after every other challenge.
    pub(super) unaffordable: &'a std::collections::HashSet<String>,
}

/// Picks the challenge to pay among `challenges`, or explains why none is
/// payable.
pub(super) fn select<'a>(
    challenges: &[&'a PaymentChallenge],
    preferences: &Preferences<'_>,
) -> Result<(&'a PaymentChallenge, Payable), String> {
    let mut reasons = Vec::new();
    let mut offers = Vec::new();
    for challenge in challenges {
        match payable(challenge) {
            Ok(offer) => offers.push((*challenge, offer)),
            Err(reason) => reasons.push(reason),
        }
    }
    let before = offers.len();
    let unconfigured: Vec<u64> = offers
        .iter()
        .map(|(_, offer)| offer.chain_id())
        .filter(|chain| !preferences.configured_chains.contains(chain))
        .collect();
    offers.retain(|(_, offer)| preferences.configured_chains.contains(&offer.chain_id()));
    if offers.is_empty() && before > 0 {
        reasons.push(format!(
            "no configured network has chain id {}; add the network to AgentPay's \
             configuration to pay on it",
            unconfigured
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" or ")
        ));
    }
    if let Some(chain_id) = preferences.chain_id {
        let before = offers.len();
        offers.retain(|(_, offer)| offer.chain_id() == chain_id);
        if offers.is_empty() && before > 0 {
            reasons.push(format!("no challenge pays on chain {chain_id}"));
        }
    }
    if let Some(currency) = preferences.currency {
        let before = offers.len();
        offers.retain(|(_, offer)| offer.currency_key() == currency);
        if offers.is_empty() && before > 0 {
            reasons.push(format!("no challenge pays in currency {currency}"));
        }
    }
    if let Some(expected) = preferences.amount {
        let before = offers.len();
        offers.retain(|(_, offer)| offer.amount() == expected);
        if offers.is_empty() && before > 0 {
            reasons.push(format!(
                "no challenge asks for exactly {expected} base units"
            ));
        }
    }
    if let Some(max) = preferences.max_amount {
        let before = offers.len();
        offers.retain(|(_, offer)| offer.amount() <= max);
        if offers.is_empty() && before > 0 {
            reasons.push(format!(
                "every challenge asks for more than {max} base units"
            ));
        }
    }
    if let Some(record) = preferences.persisted {
        let before = offers.len();
        offers.retain(|(_, offer)| {
            offer
                .tempo()
                .is_some_and(|offer| matches_channel(offer, record))
        });
        if offers.is_empty() && before > 0 {
            reasons.push(format!(
                "no session challenge matches the persisted channel {} (chain, token, \
                 recipient, or channel id differ); use another session_key",
                record.channel_id_hex
            ));
        }
    }
    let hint = testnet_hint(preferences.url);
    offers.sort_by_key(|(challenge, offer)| {
        let unaffordable = preferences.unaffordable.contains(&challenge.id);
        std::cmp::Reverse(score(offer, preferences, hint) - if unaffordable { 10_000 } else { 0 })
    });
    offers.into_iter().next().ok_or_else(|| {
        if reasons.is_empty() {
            "the merchant offered no MPP challenge AgentPay can pay".to_string()
        } else {
            reasons.join("; ")
        }
    })
}

fn matches_channel(offer: &Offer, record: &SessionRecord) -> bool {
    offer.intent == Intent::Session
        && offer.chain_id == record.chain_id
        && offer.currency == record.token
        && offer.recipient == record.recipient
        && offer.channel_id.is_none_or(|id| {
            B256::from_str(&record.channel_id_hex).is_ok_and(|persisted| persisted == id)
        })
}

/// Whether the URL names a testnet (`Some(true)`), mainnet (`Some(false)`), or neither.
fn testnet_hint(url: &str) -> Option<bool> {
    if ["tempo-testnet", "moderato", "testnet", "sepolia", "devnet"]
        .iter()
        .any(|word| url.contains(word))
    {
        Some(true)
    } else if url.contains("tempo-mainnet") {
        Some(false)
    } else {
        None
    }
}

fn score(offer: &Payable, preferences: &Preferences<'_>, testnet: Option<bool>) -> i64 {
    let mut score = 0;
    let preferred = if preferences.prefer_session {
        Intent::Session
    } else {
        Intent::Charge
    };
    if offer.intent() == preferred {
        score += 1_000;
    }
    let chain_id = offer.chain_id();
    let is_testnet = TESTNET_CHAIN_IDS.contains(&chain_id);
    match testnet {
        Some(hint) if hint == is_testnet => score += 100,
        Some(_) => score -= 100,
        None => {}
    }
    let currency = offer.currency_key();
    if preferences
        .known_tokens
        .iter()
        .any(|(chain, token)| *chain == chain_id && *token == currency)
    {
        score += 50;
    }
    // A payment that needs no native coin for gas: Tempo (fees in the
    // stablecoin), an EVM `authorization` or `permit2`, a Solana charge whose
    // fees the merchant pays.
    let gasless = match offer {
        Payable::Tempo(_) => true,
        Payable::Evm(charge) => charge.credential.is_gasless(),
        Payable::Solana(charge) => charge.fee_payer.is_some(),
    };
    if gasless {
        score += 30;
    }
    // Mainnet over testnet, Tempo mainnet first among mainnets.
    score += if is_testnet { 10 } else { 20 };
    if chain_id == TEMPO_MAINNET_CHAIN_ID {
        score += 1;
    }
    // The v2 marker only breaks ties between session challenges.
    if let Payable::Tempo(offer) = offer {
        if offer.intent == Intent::Session && offer.explicit_v2 {
            score += 1;
        }
    }
    score
}
