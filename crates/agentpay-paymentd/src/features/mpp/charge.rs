//! Paying a `tempo` `charge` challenge: a TIP-20 `transferWithMemo` sent as
//! an EIP-1559 transaction through the signer daemon's policy-checked
//! `BroadcastTx` (the same pipeline as `Transfer`), then a `hash`
//! credential.
//!
//! The memo binds the payment to the challenge: the challenge's own `memo`,
//! else `mpp`'s attribution memo for the challenge id and realm, which `mpp`
//! servers require (`assert_challenge_bound_memos`).

use agentpay_domain::BroadcastTx;
use alloy_primitives::{hex, U256};
use alloy_sol_types::{sol, SolCall};
use mpp::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};
use mpp::tempo::attribution;

use super::evm_tx::{self, Delivery};
use super::select::Offer;
use super::tempo::network_for_chain;
use crate::chains::evm::to_alloy_address;
use crate::error::PaymentsError;
use crate::features::payer::Payer;

sol! {
    function transferWithMemo(address to, uint256 amount, bytes32 memo);
}

/// A paid charge, for any method.
#[derive(Debug, Clone)]
pub(super) struct Charged {
    /// Configured network key.
    pub(super) network: String,
    /// `"hash"`, `"transaction"`, `"authorization"`, or `"signature"`.
    pub(super) credential_type: &'static str,
    /// The payment transaction (EVM hash or Solana signature), if any.
    pub(super) tx_hash: Option<String>,
    /// Tempo: the memo, `0x` + 64 hex.
    pub(super) memo_hex: Option<String>,
    /// The credential to send.
    pub(super) credential: PaymentCredential,
    /// A signed EVM transaction handed to the merchant unsent: its nonce is
    /// released if the merchant refuses the credential.
    pub(super) unsent: Option<(BroadcastTx, String)>,
}

/// Pays `offer` (from `challenge`) and returns the `hash` credential.
pub(super) async fn pay(
    payer: &Payer,
    challenge: &PaymentChallenge,
    offer: &Offer,
) -> Result<Charged, PaymentsError> {
    let (network, chain) = network_for_chain(&payer.config, offer.chain_id)?;
    let rpc = payer.evm.connect(&network, &chain).await?;
    let memo = offer
        .memo
        .unwrap_or_else(|| attribution::encode(&challenge.id, &challenge.realm, None));
    let data = transferWithMemoCall {
        to: to_alloy_address(&offer.recipient)?,
        amount: U256::from(offer.amount),
        memo: memo.into(),
    }
    .abi_encode();
    let sent = evm_tx::sign_call(
        payer,
        &rpc,
        &network,
        offer.chain_id,
        &offer.currency,
        data,
        Delivery::Send,
    )
    .await?;
    let source = PaymentCredential::evm_did(offer.chain_id, &payer.wallet.to_string());
    let credential = PaymentCredential::with_source(
        challenge.to_echo(),
        source,
        PaymentPayload::hash(&sent.hash),
    );
    Ok(Charged {
        network,
        credential_type: "hash",
        tx_hash: Some(sent.hash),
        memo_hex: Some(format!("0x{}", hex::encode(memo))),
        credential,
        unsent: None,
    })
}
