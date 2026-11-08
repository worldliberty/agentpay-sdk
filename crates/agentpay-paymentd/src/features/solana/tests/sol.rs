//! `TransferSol`: sign only, broadcast with the managed nonce account,
//! confirmation outcomes, policy denial, tampering, and request errors.

use std::sync::Arc;

use agentpay_api::payments::{
    SolanaAmount, SolanaNonceMode, SolanaTransferDetails, SolanaTransferOptions, SolanaTxStatus,
};
use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse, WireDaemonError};
use agentpay_domain::AgentAction;
use async_trait::async_trait;
use solana_sdk::pubkey::Pubkey;

use super::*;
use crate::chains::solana::testing::StatusMode;
use crate::signer::testing::per_tx_limit;
use crate::signer::SignerError;

#[tokio::test]
async fn sign_only_uses_a_recent_blockhash_and_returns_the_verified_transaction() {
    let h = Harness::new(allow_all()).await;
    let to = Pubkey::new_unique();
    let result = done(
        h.sol(
            to,
            SolanaAmount::Decimal("0.0015".into()),
            SolanaTransferOptions::default(),
        )
        .await,
    );
    assert_eq!(result.network, "solana-devnet");
    assert_eq!(result.chain_id, SOLANA_DEVNET_CHAIN_ID);
    assert_eq!(result.fee_payer, address(&h.wallet));
    assert_eq!(
        result.transfer,
        SolanaTransferDetails::Sol {
            to: address(&to),
            amount_wei: 1_500_000
        }
    );
    assert_eq!(
        result.recent_blockhash,
        h.cluster.with(|s| s.blockhash.to_string())
    );
    assert!(result.durable_nonce.is_none());
    assert!(result.broadcast.is_none());
    // Default limit and the median of the non-zero recent fees (1000, 2000, 3000).
    assert_eq!(result.compute_unit_limit, Some(5_000));
    assert_eq!(result.compute_unit_price_micro_lamports, Some(2_000));

    let tx = decode(
        result
            .raw_tx_base64
            .as_deref()
            .expect("sign-only returns the transaction"),
    );
    assert_eq!(tx.signatures[0].to_string(), result.signature);
    assert!(tx.verify().is_ok());
    assert!(h.cluster.sent().is_empty(), "sign-only never broadcasts");
}

#[tokio::test]
async fn broadcast_creates_the_managed_nonce_account_first() {
    let h = Harness::new(allow_all()).await;
    let to = Pubkey::new_unique();
    let result = done(h.sol(to, lamports(42), broadcast()).await);

    let sent = h.cluster.sent();
    assert_eq!(sent.len(), 2, "nonce account creation, then the transfer");
    let nonce = result.durable_nonce.expect("durable nonce");
    assert_eq!(nonce.account, address(&h.managed_nonce()));
    assert!(nonce.managed);
    assert_eq!(
        nonce.created_signature,
        Some(sent[0].signatures[0].to_string())
    );
    assert_eq!(result.signature, sent[1].signatures[0].to_string());
    assert_eq!(
        result.broadcast.map(|b| b.status),
        Some(SolanaTxStatus::Finalized)
    );
    assert!(result.raw_tx_base64.is_none(), "not revealed by default");
    // The transfer used the nonce stored by the creation, and advanced it.
    let created_nonce = h
        .cluster
        .with(|s| *solana_nonce::state::DurableNonce::from_blockhash(&s.blockhash).as_hash());
    assert_eq!(result.recent_blockhash, created_nonce.to_string());
    assert_ne!(
        h.cluster
            .nonce_of(&h.managed_nonce())
            .map(|n| n.to_string()),
        Some(result.recent_blockhash)
    );
}

#[tokio::test]
async fn an_existing_managed_nonce_account_is_reused() {
    let h = Harness::new(allow_all()).await;
    let nonce = h.cluster.add_nonce_account(h.managed_nonce(), h.wallet);
    let options = SolanaTransferOptions {
        reveal_raw_tx: true,
        ..broadcast()
    };
    let result = done(h.sol(Pubkey::new_unique(), lamports(42), options).await);
    assert_eq!(h.cluster.sent().len(), 1, "no second creation");
    assert_eq!(result.recent_blockhash, nonce.to_string());
    assert_eq!(result.durable_nonce.and_then(|n| n.created_signature), None);
    assert!(result.raw_tx_base64.is_some(), "revealed on request");
}

#[tokio::test]
async fn explicit_nonce_accounts_must_exist_and_belong_to_the_wallet() {
    let h = Harness::new(allow_all()).await;
    let account = Pubkey::new_unique();
    let explicit = |account| SolanaTransferOptions {
        nonce: SolanaNonceMode::Account(address(&account)),
        ..SolanaTransferOptions::default()
    };
    let reason = invalid(
        h.sol(Pubkey::new_unique(), lamports(1), explicit(account))
            .await,
    );
    assert!(reason.contains("does not exist"), "{reason}");

    h.cluster.add_nonce_account(account, Pubkey::new_unique());
    let reason = invalid(
        h.sol(Pubkey::new_unique(), lamports(1), explicit(account))
            .await,
    );
    assert!(reason.contains("authority"), "{reason}");

    let mine = Pubkey::new_unique();
    let value = h.cluster.add_nonce_account(mine, h.wallet);
    let result = done(
        h.sol(Pubkey::new_unique(), lamports(1), explicit(mine))
            .await,
    );
    assert_eq!(result.recent_blockhash, value.to_string());
    assert_eq!(result.durable_nonce.map(|n| n.managed), Some(false));
    assert!(h.cluster.sent().is_empty());
}

#[tokio::test]
async fn confirmation_outcomes_are_reported() {
    let h = Harness::new(allow_all()).await;
    h.cluster.add_nonce_account(h.managed_nonce(), h.wallet);

    let no_wait = SolanaTransferOptions {
        wait_for_confirmation: false,
        ..broadcast()
    };
    let result = done(h.sol(Pubkey::new_unique(), lamports(1), no_wait).await);
    assert_eq!(
        result.broadcast.map(|b| b.status),
        Some(SolanaTxStatus::Submitted)
    );

    h.cluster.with(|s| s.status = StatusMode::Failed);
    let failed = done(h.sol(Pubkey::new_unique(), lamports(2), broadcast()).await)
        .broadcast
        .expect("broadcast");
    assert_eq!(failed.status, SolanaTxStatus::Failed);
    assert_eq!(failed.slot, Some(89));
    assert!(failed.error.is_some());

    h.cluster.with(|s| s.status = StatusMode::Unknown);
    let unknown = done(h.sol(Pubkey::new_unique(), lamports(3), broadcast()).await);
    assert_eq!(
        unknown.broadcast.map(|b| b.status),
        Some(SolanaTxStatus::TimedOut)
    );
}

#[tokio::test]
async fn a_policy_denial_signs_and_sends_nothing() {
    let h = Harness::new(vec![per_tx_limit(1_000)]).await;
    h.cluster.add_nonce_account(h.managed_nonce(), h.wallet);
    let err = h
        .sol(Pubkey::new_unique(), lamports(5_000), broadcast())
        .await
        .expect_err("over the limit");
    assert!(
        matches!(err, PaymentsError::Signer(WireDaemonError::Policy(_))),
        "{err:?}"
    );
    assert!(h.cluster.sent().is_empty());
    done(
        h.sol(Pubkey::new_unique(), lamports(1_000), broadcast())
            .await,
    );
}

/// Forwards to signerd but asks for one more lamport than paymentd did, as
/// a compromised path between the two would.
struct Tampering(Arc<InProcessSigner>);

#[async_trait]
impl SignerClient for Tampering {
    async fn call(&self, mut request: DaemonRpcRequest) -> Result<DaemonRpcResponse, SignerError> {
        if let DaemonRpcRequest::SignForAgent(params) = &mut request {
            if let AgentAction::SolanaSolTransfer { transfer } = &mut params.request.action {
                transfer.amount_wei += 1;
                params.request.payload =
                    serde_json::to_vec(&params.request.action).expect("payload");
            }
        }
        self.0.call(request).await
    }
}

#[tokio::test]
async fn a_tampered_signature_is_never_returned_or_broadcast() {
    let h = Harness::with_signer(allow_all(), |signer| Arc::new(Tampering(signer))).await;
    h.cluster.add_nonce_account(h.managed_nonce(), h.wallet);
    for options in [SolanaTransferOptions::default(), broadcast()] {
        let err = h
            .sol(Pubkey::new_unique(), lamports(1_000), options)
            .await
            .expect_err("tampered");
        let PaymentsError::SignedTransactionMismatch(reason) = err else {
            panic!("expected SignedTransactionMismatch, got {err:?}");
        };
        assert!(reason.contains("SOL amount 1001 lamports"), "{reason}");
    }
    assert!(h.cluster.sent().is_empty());
}

#[tokio::test]
async fn bad_requests_fail_before_signing() {
    let h = Harness::new(allow_all()).await;
    let to = Pubkey::new_unique();
    let request = |network: &str| {
        PaymentsRpcRequest::TransferSol(agentpay_api::payments::TransferSolParams {
            auth: h.auth.clone(),
            network: network.into(),
            to: address(&to),
            amount: lamports(1),
            options: SolanaTransferOptions::default(),
        })
    };
    let reason = invalid(dispatch(&h.state, request("nowhere")).await);
    assert!(reason.contains("unknown network"), "{reason}");
    let reason = invalid(dispatch(&h.state, request("bsc")).await);
    assert!(reason.contains("not a Solana network"), "{reason}");

    let reason = invalid(
        h.sol(
            to,
            SolanaAmount::Decimal("0.0000000001".into()),
            SolanaTransferOptions::default(),
        )
        .await,
    );
    assert!(reason.contains("decimal places"), "{reason}");
    let reason = invalid(
        h.sol(to, lamports(0), SolanaTransferOptions::default())
            .await,
    );
    assert!(reason.contains("greater than zero"), "{reason}");
    let pricey = SolanaTransferOptions {
        compute_unit_price_micro_lamports: Some(20_000_000),
        ..SolanaTransferOptions::default()
    };
    let reason = invalid(h.sol(to, lamports(1), pricey).await);
    assert!(reason.contains("compute unit price"), "{reason}");
    assert!(h.cluster.sent().is_empty());
}

#[tokio::test]
async fn rpc_failures_are_chain_rpc_errors_without_the_url() {
    let h = Harness::new(allow_all()).await;
    h.cluster
        .with(|s| s.failing.push("getLatestBlockhash".into()));
    let err = h
        .sol(
            Pubkey::new_unique(),
            lamports(1),
            SolanaTransferOptions::default(),
        )
        .await
        .expect_err("rpc down");
    let PaymentsError::ChainRpc(reason) = err else {
        panic!("expected ChainRpc, got {err:?}");
    };
    assert!(reason.contains("getLatestBlockhash"), "{reason}");
    assert!(!reason.contains("solana.com"), "{reason}");

    // A wrong cluster behind the configured URL is refused up front.
    let h = Harness::new(allow_all()).await;
    h.cluster
        .with(|s| s.genesis = solana_sdk::hash::Hash::new_unique());
    let err = h
        .sol(
            Pubkey::new_unique(),
            lamports(1),
            SolanaTransferOptions::default(),
        )
        .await
        .expect_err("wrong cluster");
    assert!(matches!(err, PaymentsError::ChainRpc(ref r) if r.contains("another Solana cluster")));
}
