//! `solana` charges (`draft-solana-charge-00`) end to end: a fake devnet, the
//! in-process signer daemon, and a mock merchant that decodes the pull-mode
//! transaction itself and checks what it pays (fee payer and its empty slot,
//! the agent's signature, transfer amounts and destinations, split ATA
//! creation, memos).

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use agentpay_api::payments::{
    HttpRequest, MppFetchParams, MppFetchResult, PaymentsRpcRequest as Req,
    PaymentsRpcResponse as Res,
};
use agentpay_api::AgentAuth;
use agentpay_domain::SpendingPolicy;
use base64::Engine as _;
use mpp::protocol::core::{
    format_www_authenticate, parse_authorization, Base64UrlJson, PaymentChallenge, Receipt,
};
use serde_json::{json, Value};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::VersionedTransaction;

use crate::auth::authenticate;
use crate::chains::solana::testing::FakeCluster;
use crate::config::ConfigStore;
use crate::dispatch::dispatch;
use crate::error::PaymentsError;
use crate::features::http::merchant::{Merchant, Reply, Seen};
use crate::signer::testing::{per_tx_limit, InProcessSigner};
use crate::state::AppState;
use crate::test_support::TempDir;

const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const MERCHANT: &str = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const PLATFORM: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const SPONSOR: &str = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR";

struct Harness {
    state: AppState,
    cluster: FakeCluster,
    auth: AgentAuth,
    wallet: Pubkey,
    _dir: TempDir,
}

impl Harness {
    async fn new(policies: Vec<SpendingPolicy>) -> Self {
        let dir = TempDir::new("mpp-sol");
        let (signer, auth) = InProcessSigner::with_agent(policies).await;
        let signer = Arc::new(signer);
        let mut state = AppState::new(
            ConfigStore::open(dir.path()).expect("config"),
            signer.clone(),
        );
        let cluster = FakeCluster::devnet();
        state.chains.register(Arc::new(cluster.provider()));
        let wallet = authenticate(signer.as_ref(), &auth)
            .await
            .expect("authenticated")
            .identity
            .solana_address
            .expect("software keys sign for Solana")
            .to_string()
            .parse()
            .expect("pubkey");
        Self {
            state,
            cluster,
            auth,
            wallet,
            _dir: dir,
        }
    }

    async fn fetch(&self, url: String) -> Result<MppFetchResult, PaymentsError> {
        let params = MppFetchParams {
            auth: self.auth.clone(),
            request: HttpRequest {
                url,
                method: None,
                headers: Vec::new(),
                body: None,
            },
            amount: None,
            deposit: None,
            max_deposit: None,
            currency: None,
            network: None,
            session_key: None,
            close_session: false,
            approval_wait_secs: None,
        };
        match dispatch(&self.state, Req::MppFetch(params)).await? {
            Res::MppResponse(result) => Ok(result),
            other => panic!("unexpected response {other:?}"),
        }
    }
}

/// A merchant charging `request` (a `solana` charge request) and checking
/// the transaction it is handed with `check`.
struct SolMerchant {
    http: Merchant,
    log: Arc<Mutex<Vec<VersionedTransaction>>>,
}

impl SolMerchant {
    async fn start(request: Value) -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let issued = Arc::new(Mutex::new(HashMap::<String, PaymentChallenge>::new()));
        let shared = log.clone();
        let http =
            Merchant::start(move |seen: &Seen| serve(&request, &issued, &shared, seen)).await;
        Self { http, log }
    }

    fn url(&self) -> String {
        format!("{}/v1/data", self.http.url())
    }

    fn paid(&self) -> Vec<VersionedTransaction> {
        self.log.lock().expect("log").clone()
    }
}

fn serve(
    request: &Value,
    issued: &Mutex<HashMap<String, PaymentChallenge>>,
    log: &Mutex<Vec<VersionedTransaction>>,
    seen: &Seen,
) -> Reply {
    let mut issued = issued.lock().expect("issued");
    let Some(header) = seen.header("authorization") else {
        let challenge = PaymentChallenge::new(
            format!("sol-{}", issued.len()),
            "api.example.com",
            "solana",
            "charge",
            Base64UrlJson::from_value(request).expect("request"),
        );
        issued.insert(challenge.id.clone(), challenge.clone());
        return Reply::new(402, "payment required").header(
            "WWW-Authenticate",
            format_www_authenticate(&challenge).expect("challenge"),
        );
    };
    let credential = parse_authorization(header).expect("credential");
    assert!(issued.contains_key(&credential.challenge.id));
    assert_eq!(credential.payload["type"], "transaction");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(
            credential.payload["transaction"]
                .as_str()
                .expect("transaction"),
        )
        .expect("base64");
    assert!(bytes.len() <= 1232, "fits a Solana packet");
    let transaction: VersionedTransaction = bincode::deserialize(&bytes).expect("transaction");
    assert!(
        transaction
            .message
            .address_table_lookups()
            .is_none_or(<[_]>::is_empty),
        "no lookup tables"
    );
    log.lock().expect("log").push(transaction.clone());
    let receipt = Receipt::success("solana", transaction.signatures[0].to_string());
    Reply::new(200, "{\"ok\":true}")
        .header("content-type", "application/json")
        .header("Payment-Receipt", receipt.to_header().expect("receipt"))
}

/// The program id of instruction `index`.
fn program(transaction: &VersionedTransaction, index: usize) -> String {
    let instruction = &transaction.message.instructions()[index];
    transaction.message.static_account_keys()[usize::from(instruction.program_id_index)].to_string()
}

/// The account keys instruction `index` names.
fn accounts(transaction: &VersionedTransaction, index: usize) -> Vec<Pubkey> {
    let keys = transaction.message.static_account_keys();
    transaction.message.instructions()[index]
        .accounts
        .iter()
        .map(|account| keys[usize::from(*account)])
        .collect()
}

fn ata(owner: &str, mint: &Pubkey, program: &str) -> Pubkey {
    spl_associated_token_account::get_associated_token_address_with_program_id(
        &Pubkey::from_str(owner).expect("owner"),
        mint,
        &Pubkey::from_str(program).expect("program"),
    )
}

/// `transferChecked` amount and decimals.
fn transfer_checked(transaction: &VersionedTransaction, index: usize) -> (u64, u8) {
    let data = &transaction.message.instructions()[index].data;
    assert_eq!(data[0], 12, "TransferChecked");
    (
        u64::from_le_bytes(data[1..9].try_into().expect("amount")),
        data[9],
    )
}

fn agent_signed(transaction: &VersionedTransaction, wallet: &Pubkey) -> bool {
    let message = transaction.message.serialize();
    let keys = transaction.message.static_account_keys();
    let index = keys
        .iter()
        .position(|key| key == wallet)
        .expect("agent account");
    transaction.signatures[index].verify(wallet.as_ref(), &message)
}

#[tokio::test]
async fn a_sponsored_token_charge_with_a_split_and_memos_is_handed_over_partially_signed() {
    let harness = Harness::new(vec![per_tx_limit(u128::MAX)]).await;
    let mint = harness.cluster.add_mint(
        Pubkey::from_str(TOKEN_PROGRAM).expect("program"),
        6,
        None,
        false,
    );
    let merchant = SolMerchant::start(json!({
        "amount": "1050000", "currency": mint.to_string(), "recipient": MERCHANT,
        "externalId": "order-42",
        "methodDetails": {
            "network": "devnet", "decimals": 6, "tokenProgram": TOKEN_PROGRAM,
            "feePayer": true, "feePayerKey": SPONSOR,
            "splits": [{"recipient": PLATFORM, "amount": "50000", "memo": "platform fee",
                        "ataCreationRequired": true}]
        }
    }))
    .await;
    let result = harness.fetch(merchant.url()).await.expect("paid");
    let payment = result.payment.expect("payment");
    assert_eq!(
        (payment.method.as_str(), payment.network.as_str()),
        ("solana", "solana-devnet")
    );
    assert_eq!(payment.currency, mint.to_string(), "mints keep their case");
    let charge = payment.charge.expect("charge");
    assert_eq!(charge.credential_type, "transaction");
    assert_eq!(
        charge.tx_hash, None,
        "the merchant's signature makes the id"
    );

    let paid = merchant.paid();
    let [transaction] = paid.as_slice() else {
        panic!("one payment");
    };
    let keys = transaction.message.static_account_keys();
    assert_eq!(keys[0].to_string(), SPONSOR, "the merchant pays the fee");
    assert_eq!(
        transaction.signatures[0],
        Signature::default(),
        "its slot is empty"
    );
    assert!(agent_signed(transaction, &harness.wallet));
    // Compute price, compute limit, primary transfer, memo, ATA create, split, split memo.
    let programs: Vec<String> = (0..transaction.message.instructions().len())
        .map(|index| program(transaction, index))
        .collect();
    assert_eq!(
        programs,
        [
            "ComputeBudget111111111111111111111111111111",
            "ComputeBudget111111111111111111111111111111",
            TOKEN_PROGRAM,
            MEMO_PROGRAM,
            &spl_associated_token_account::ID.to_string(),
            TOKEN_PROGRAM,
            MEMO_PROGRAM,
        ]
    );
    assert_eq!(transfer_checked(transaction, 2), (1_000_000, 6));
    assert_eq!(
        accounts(transaction, 2)[2],
        ata(MERCHANT, &mint, TOKEN_PROGRAM)
    );
    assert_eq!(
        accounts(transaction, 2)[3],
        harness.wallet,
        "the agent authorizes"
    );
    assert_eq!(transaction.message.instructions()[3].data, b"order-42");
    assert_eq!(
        accounts(transaction, 4)[0].to_string(),
        SPONSOR,
        "the sponsor funds the ATA"
    );
    assert_eq!(transfer_checked(transaction, 5), (50_000, 6));
    assert_eq!(
        accounts(transaction, 5)[2],
        ata(PLATFORM, &mint, TOKEN_PROGRAM)
    );
    assert_eq!(transaction.message.instructions()[6].data, b"platform fee");
}

#[tokio::test]
async fn a_sol_charge_without_sponsorship_is_fully_signed_by_the_agent() {
    let harness = Harness::new(vec![per_tx_limit(u128::MAX)]).await;
    let merchant = SolMerchant::start(json!({
        "amount": "10000000", "currency": "sol", "recipient": MERCHANT,
        "methodDetails": {"network": "devnet"}
    }))
    .await;
    let charge = harness
        .fetch(merchant.url())
        .await
        .expect("paid")
        .payment
        .and_then(|payment| payment.charge)
        .expect("charge");
    let transaction = merchant.paid().remove(0);
    assert_eq!(transaction.message.static_account_keys()[0], harness.wallet);
    assert!(agent_signed(&transaction, &harness.wallet));
    assert_eq!(
        charge.tx_hash,
        Some(transaction.signatures[0].to_string()),
        "the agent's signature is the transaction id"
    );
    let system = (0..transaction.message.instructions().len())
        .find(|index| program(&transaction, *index) == "11111111111111111111111111111111")
        .expect("system transfer");
    assert_eq!(accounts(&transaction, system)[1].to_string(), MERCHANT);
    let data = &transaction.message.instructions()[system].data;
    assert_eq!(
        u64::from_le_bytes(data[4..12].try_into().expect("lamports")),
        10_000_000
    );
}

#[tokio::test]
async fn the_token_program_comes_from_the_mint_when_the_merchant_omits_it() {
    let harness = Harness::new(vec![per_tx_limit(u128::MAX)]).await;
    let mint = harness.cluster.add_mint(
        Pubkey::from_str(TOKEN_2022_PROGRAM).expect("program"),
        6,
        None,
        false,
    );
    let merchant = SolMerchant::start(json!({
        "amount": "1000", "currency": mint.to_string(), "recipient": MERCHANT,
        "methodDetails": {"network": "devnet", "decimals": 6}
    }))
    .await;
    harness.fetch(merchant.url()).await.expect("paid");
    let transaction = merchant.paid().remove(0);
    let transfer = (0..transaction.message.instructions().len())
        .find(|index| program(&transaction, *index) == TOKEN_2022_PROGRAM)
        .expect("a Token-2022 transfer");
    assert_eq!(
        accounts(&transaction, transfer)[2],
        ata(MERCHANT, &mint, TOKEN_2022_PROGRAM)
    );
}

#[tokio::test]
async fn solana_charges_are_policy_checked() {
    let harness = Harness::new(vec![per_tx_limit(999)]).await;
    let merchant = SolMerchant::start(json!({
        "amount": "1000", "currency": "sol", "recipient": MERCHANT,
        "methodDetails": {"network": "devnet"}
    }))
    .await;
    let error = harness
        .fetch(merchant.url())
        .await
        .expect_err("over the limit");
    assert!(
        matches!(
            &error,
            PaymentsError::Signer(_) | PaymentsError::ManualApprovalPending { .. }
        ),
        "{error:?}"
    );
    assert!(merchant.paid().is_empty());
}
